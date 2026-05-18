"""Async deep content inspection with adaptive HTTP negotiation."""

from __future__ import annotations

import asyncio
import re
from html.parser import HTMLParser
from typing import Iterable

import httpx

from urllib.parse import urlparse

from .adaptive import RequestProfile, build_request_profile
from .auth_policy import AuthConsent, AuthPolicy
from .auth_probe import AuthProbeResult, run_auth_probes
from .patterns import (
    API_PATH_RE,
    FRAMEWORK_SIGNATURES,
    INTERNAL_IP_RE,
    SENSITIVE_KEY_RE,
    TRIGGER_MAP,
    InspectionFinding,
)

from .ffuf_runner import INSPECTABLE_FFUF_STATUSES

MAX_BODY_BYTES = 512_000


class _HtmlStructureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms = 0
        self.inputs = 0
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = tag.lower()
        if t == "form":
            self.forms += 1
        elif t == "input":
            self.inputs += 1
        elif t == "script":
            src = dict(attrs).get("src") or ""
            if src:
                self.scripts.append(src)


def _extract_title(html: str) -> str:
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", html)
    return m.group(1).strip() if m else ""


def _html_structure_signals(html: str, baseline: _HtmlStructureParser | None) -> list[str]:
    parser = _HtmlStructureParser()
    try:
        parser.feed(html[:MAX_BODY_BYTES])
    except Exception:
        return ["html_parse_error"]
    signals: list[str] = []
    title = _extract_title(html)
    if title:
        signals.append(f"title:{title[:80]}")
    if parser.forms:
        signals.append(f"forms:{parser.forms}")
    if parser.inputs:
        signals.append(f"inputs:{parser.inputs}")
    if parser.scripts:
        signals.append(f"external_scripts:{len(parser.scripts)}")
    if baseline:
        if parser.forms > baseline.forms:
            signals.append("structural:more_forms_than_baseline")
        if len(parser.scripts) > len(baseline.scripts):
            signals.append("structural:more_scripts_than_baseline")
    return signals


def _detect_triggers(text: str, url: str) -> set[str]:
    haystack = f"{url}\n{text}".lower()
    return {cat for cat, needles in TRIGGER_MAP.items() if any(n in haystack for n in needles)}


def inspect_body(
    url: str,
    status: int,
    body: str,
    headers: httpx.Headers,
    baseline_html: str | None = None,
    *,
    ffuf_status: int | None = None,
    profile: RequestProfile | None = None,
) -> InspectionFinding:
    text = body[:MAX_BODY_BYTES]
    combined = text + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
    finding = InspectionFinding(url=url, status=status, ffuf_status=ffuf_status)
    if profile:
        finding.accepted_methods = list(profile.accepted_methods)
        finding.used_method = profile.method
        finding.content_type = profile.content_type
        finding.request_body = profile.body
        finding.adaptive_notes = list(profile.notes)
    finding.internal_ips = list(dict.fromkeys(INTERNAL_IP_RE.findall(combined)))[:20]
    finding.sensitive_keys = list(dict.fromkeys(m.group(1) for m in SENSITIVE_KEY_RE.finditer(combined)))[:20]
    finding.api_indicators = list(dict.fromkeys(API_PATH_RE.findall(combined)))[:20]
    for name, pattern in FRAMEWORK_SIGNATURES.items():
        if pattern.search(combined):
            finding.frameworks.append(name)
    baseline_parser: _HtmlStructureParser | None = None
    if baseline_html and "html" in headers.get("content-type", "").lower():
        baseline_parser = _HtmlStructureParser()
        try:
            baseline_parser.feed(baseline_html[:MAX_BODY_BYTES])
        except Exception:
            baseline_parser = None
    if "html" in headers.get("content-type", "").lower() or text.lstrip().startswith("<"):
        finding.html_signals = _html_structure_signals(text, baseline_parser)
    finding.triggers = _detect_triggers(combined, url)
    return finding


def _merge_auth(finding: InspectionFinding, auth: AuthProbeResult) -> None:
    finding.auth_type = auth.auth_type
    finding.login_form_count = len(auth.login_forms)
    finding.basic_realm = auth.basic_realm
    finding.auth_success = auth.success
    finding.auth_username = auth.working_username
    finding.auth_notes = list(auth.notes)
    if auth.login_forms:
        finding.triggers.add("admin")
    if auth.success:
        finding.triggers.add("admin")


def _apply_auth_to_profile(profile: RequestProfile, auth: AuthProbeResult) -> None:
    if auth.basic_auth_header:
        profile.authorization = auth.basic_auth_header
    if auth.session_cookie:
        profile.cookie = auth.session_cookie.split(";")[0]


async def _send_with_profile(
    client: httpx.AsyncClient,
    url: str,
    profile: RequestProfile,
) -> httpx.Response:
    headers: dict[str, str] = {}
    if profile.content_type:
        headers["Content-Type"] = profile.content_type
    content = profile.body.encode("utf-8") if profile.body else None
    return await client.request(profile.method, url, headers=headers or None, content=content)


class DeepInspector:
    def __init__(
        self,
        *,
        concurrency: int = 20,
        timeout: float = 15.0,
        verify_tls: bool = True,
        follow_redirects: bool = True,
        user_agent: str = "ffuf-intel/1.0",
        adaptive: bool = True,
        auth_consent: AuthConsent | None = None,
        max_inspect: int = 150,
    ) -> None:
        self.concurrency = concurrency
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.follow_redirects = follow_redirects
        self.user_agent = user_agent
        self.adaptive = adaptive
        self.auth_consent = auth_consent or AuthConsent(AuthPolicy.ASK)
        self.max_inspect = max(1, max_inspect)
        self._baseline_html: str | None = None
        self.profiles: dict[str, RequestProfile] = {}
        self.site_auth: dict[str, RequestProfile] = {}  # netloc -> profile with creds

    def _site_key(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed.netloc or url

    def _profile_for_site(self, url: str) -> RequestProfile | None:
        return self.site_auth.get(self._site_key(url))

    async def fetch_baseline(self, base_url: str) -> None:
        async with httpx.AsyncClient(
            verify=self.verify_tls,
            follow_redirects=self.follow_redirects,
            timeout=self.timeout,
            headers={"User-Agent": self.user_agent},
        ) as client:
            try:
                resp = await client.get(base_url)
                self._baseline_html = resp.text[:MAX_BODY_BYTES]
            except httpx.HTTPError:
                self._baseline_html = None

    async def inspect_many(
        self, targets: Iterable[tuple[str, int]], *, console: Console | None = None
    ) -> list[InspectionFinding]:
        from rich.console import Console as RichConsole

        target_list = list(targets)
        if len(target_list) > self.max_inspect:
            if console:
                console.print(
                    f"  [yellow]Inspecting first {self.max_inspect} of {len(target_list)} endpoints "
                    f"(raise with --max-inspect)[/]"
                )
            target_list = target_list[: self.max_inspect]

        sem = asyncio.Semaphore(self.concurrency)
        findings: list[InspectionFinding] = []
        _console = console or RichConsole()

        async with httpx.AsyncClient(
            verify=self.verify_tls,
            follow_redirects=self.follow_redirects,
            timeout=self.timeout,
            headers={"User-Agent": self.user_agent},
        ) as client:

            async def _one(url: str, ffuf_status: int) -> InspectionFinding | None:
                if ffuf_status not in INSPECTABLE_FFUF_STATUSES:
                    return None
                async with sem:
                    profile = self._profile_for_site(url) or RequestProfile()
                    try:
                        if self.adaptive:
                            profile = await build_request_profile(
                                client, url, initial_status=ffuf_status, initial_method="GET"
                            )
                            site = self._profile_for_site(url)
                            if site:
                                profile.authorization = profile.authorization or site.authorization
                                profile.cookie = profile.cookie or site.cookie
                            self.profiles[url] = profile
                            resp = await _send_with_profile(client, url, profile)
                        else:
                            headers = {}
                            site = self._profile_for_site(url)
                            if site and site.authorization:
                                headers["Authorization"] = site.authorization
                            if site and site.cookie:
                                headers["Cookie"] = site.cookie
                            resp = await client.get(url, headers=headers or None)
                    except httpx.HTTPError:
                        return InspectionFinding(
                            url=url,
                            status=ffuf_status,
                            ffuf_status=ffuf_status,
                            html_signals=["fetch_failed"],
                        )
                    except Exception as exc:
                        return InspectionFinding(
                            url=url,
                            status=ffuf_status,
                            ffuf_status=ffuf_status,
                            html_signals=[f"inspect_error:{type(exc).__name__}"],
                        )
                    finding = inspect_body(
                        url,
                        resp.status_code,
                        resp.text,
                        resp.headers,
                        self._baseline_html,
                        ffuf_status=ffuf_status,
                        profile=profile if self.adaptive else None,
                    )
                    try:
                        auth = await run_auth_probes(
                            client,
                            url,
                            status=resp.status_code,
                            headers=resp.headers,
                            body=resp.text,
                            consent=self.auth_consent,
                        )
                        _merge_auth(finding, auth)
                        if auth.success:
                            _apply_auth_to_profile(profile, auth)
                            self.profiles[url] = profile
                            self.site_auth[self._site_key(url)] = profile
                    except Exception as exc:
                        finding.auth_notes.append(f"auth_probe_error:{type(exc).__name__}")
                    return finding

            results = await asyncio.gather(
                *[_one(u, s) for u, s in target_list], return_exceptions=True
            )
            for item in results:
                if isinstance(item, InspectionFinding):
                    findings.append(item)
                elif isinstance(item, Exception):
                    _console.print(f"[red]inspect task error:[/] {item}")
        return findings
