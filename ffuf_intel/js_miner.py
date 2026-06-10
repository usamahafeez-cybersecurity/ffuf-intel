"""Hidden endpoint, parameter, and secret-pattern discovery from JavaScript."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import httpx

from .crawler import same_origin


@dataclass(slots=True)
class EndpointProbe:
    endpoint: str
    full_url: str
    status: int | str
    length: int = 0
    content_type: str = ""
    interesting: bool = False


@dataclass(slots=True)
class JsIntelResult:
    endpoints: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    interesting_parameters: list[str] = field(default_factory=list)
    secrets: dict[str, list[str]] = field(default_factory=dict)
    endpoint_sources: dict[str, list[str]] = field(default_factory=dict)
    probes: list[EndpointProbe] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


ENDPOINT_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.I)
    for pattern in (
        r'["\'`]((?:https?://[^"\'`<>\s]+)?/api/v?\d*/[A-Za-z0-9_./?=&%{}-]+)["\'`]',
        r'["\'`]((?:https?://[^"\'`<>\s]+)?/graphql[^"\'`\s]*)["\'`]',
        r'["\'`]((?:https?://[^"\'`<>\s]+)?/(?:auth|oauth|token|login|logout)[A-Za-z0-9_./?=&%{}-]*)["\'`]',
        r'["\'`]((?:https?://[^"\'`<>\s]+)?/(?:admin|internal|debug|v\d+)[A-Za-z0-9_./?=&%{}-]*)["\'`]',
        r'fetch\(\s*["\'`]([^"\'`]+)["\'`]',
        r'axios\.(?:get|post|put|delete|patch)\(\s*["\'`]([^"\'`]+)["\'`]',
        r'\.open\(\s*["\'`][A-Z]+["\'`]\s*,\s*["\'`]([^"\'`]+)["\'`]',
        r'url\s*:\s*["\'`]([^"\'`]+)["\'`]',
        r'(?:baseURL|API_URL|API_BASE|apiUrl|endpoint)\s*[:=]\s*["\'`]([^"\'`]+)["\'`]',
        r'new WebSocket\(\s*["\'`]([^"\'`]+)["\'`]',
    )
)

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "AWS Access Key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "Firebase URL": re.compile(r"https://[a-zA-Z0-9-]+\.firebaseio\.com"),
    "Stripe Key": re.compile(r"\b[sp]k_(?:live|test)_[0-9a-zA-Z]{16,}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_=.-]+\.[A-Za-z0-9_=.-]+\.?[A-Za-z0-9_.+/=-]*\b"),
    "Bearer Token": re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b"),
    "Private Key Marker": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
}

PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_-]{1,40})=")
INTERESTING_PARAMS = {
    "next",
    "redirect",
    "return",
    "return_url",
    "url",
    "file",
    "path",
    "id",
    "user",
    "token",
    "debug",
    "callback",
    "continue",
}


def mine_js(
    base_url: str,
    *,
    js_urls: list[str],
    inline_scripts: dict[str, str] | None = None,
    timeout: float = 10.0,
    verify_tls: bool = True,
    follow_redirects: bool = True,
    user_agent: str = "ffuf-intel/1.0",
    probe_endpoints: bool = False,
    max_probe: int = 50,
) -> JsIntelResult:
    """Extract endpoints and high-signal token patterns from same-origin JavaScript."""
    inline_scripts = inline_scripts or {}
    result = JsIntelResult()
    endpoints: set[str] = set()
    parameters: set[str] = set()
    interesting: set[str] = set()

    def add_endpoint(endpoint: str, source: str) -> None:
        endpoint = endpoint.strip()
        if not endpoint or endpoint.startswith(("data:", "mailto:", "tel:", "#")):
            return
        if endpoint.startswith(("http://", "https://")) and not same_origin(endpoint, base_url):
            return
        if endpoint.startswith("//"):
            return
        endpoints.add(endpoint)
        result.endpoint_sources.setdefault(endpoint, [])
        if source not in result.endpoint_sources[endpoint]:
            result.endpoint_sources[endpoint].append(source)
        for param in PARAM_RE.findall(endpoint):
            parameters.add(param)
            if param.lower() in INTERESTING_PARAMS:
                interesting.add(param)

    with httpx.Client(
        timeout=timeout,
        verify=verify_tls,
        follow_redirects=follow_redirects,
        headers={"User-Agent": user_agent},
    ) as client:
        for js_url in js_urls:
            try:
                resp = client.get(js_url)
            except httpx.HTTPError as exc:
                result.errors.append(f"{js_url}: {type(exc).__name__}")
                continue
            _mine_text(resp.text[:500_000], js_url, add_endpoint, result, parameters, interesting)

        for source, script in inline_scripts.items():
            _mine_text(script[:500_000], source, add_endpoint, result, parameters, interesting)

        result.endpoints = sorted(endpoints)
        result.parameters = sorted(parameters)
        result.interesting_parameters = sorted(interesting)

        if probe_endpoints:
            for endpoint in result.endpoints[: max(0, max_probe)]:
                full_url = urljoin(base_url.rstrip("/") + "/", endpoint.lstrip("/"))
                parsed = urlparse(full_url)
                if parsed.scheme not in ("http", "https") or not same_origin(full_url, base_url):
                    continue
                try:
                    probe = client.get(full_url, follow_redirects=False)
                    result.probes.append(
                        EndpointProbe(
                            endpoint=endpoint,
                            full_url=full_url,
                            status=probe.status_code,
                            length=len(probe.content),
                            content_type=probe.headers.get("content-type", ""),
                            interesting=probe.status_code not in (404, 410),
                        )
                    )
                except httpx.HTTPError:
                    result.probes.append(EndpointProbe(endpoint, full_url, "error"))

    result.probes.sort(key=lambda p: (not p.interesting, str(p.status), p.endpoint))
    return result


def _mine_text(
    text: str,
    source: str,
    add_endpoint,
    result: JsIntelResult,
    parameters: set[str],
    interesting: set[str],
) -> None:
    expanded = _basic_deobfuscate(text)
    for pattern in ENDPOINT_PATTERNS:
        for match in pattern.finditer(expanded):
            add_endpoint(match.group(1), source)
    for param in PARAM_RE.findall(expanded):
        parameters.add(param)
        if param.lower() in INTERESTING_PARAMS:
            interesting.add(param)
    for name, pattern in SECRET_PATTERNS.items():
        hits = sorted(set(pattern.findall(expanded)))
        if hits:
            existing = result.secrets.setdefault(name, [])
            for hit in hits[:20]:
                if isinstance(hit, tuple):
                    hit = "".join(part for part in hit if part)
                masked = _mask_secret(str(hit))
                if masked not in existing:
                    existing.append(masked)


def _basic_deobfuscate(text: str) -> str:
    text = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text)
    text = re.sub(
        r'["\']([^"\']*)["\']\s*\+\s*["\']([^"\']*)["\']',
        lambda m: f'"{m.group(1)}{m.group(2)}"',
        text,
    )
    for encoded in re.findall(r'atob\(["\']([A-Za-z0-9+/=]{8,})["\']\)', text):
        try:
            decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if "/" in decoded or "http" in decoded:
            text = text.replace(encoded, decoded)
    return text


def _mask_secret(value: str) -> str:
    if len(value) <= 12:
        return "***"
    return f"{value[:6]}...{value[-4:]}"
