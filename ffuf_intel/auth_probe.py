"""Login form and HTTP Basic authentication probing."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx

from .auth_policy import AuthConsent, AuthPolicy

WORDLIST_DIR = Path(__file__).resolve().parent / "wordlists"

# Built-in defaults tried first (user, password)
DEFAULT_CREDS: list[tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("root", "toor"),
    ("user", "user"),
    ("guest", "guest"),
    ("test", "test"),
    ("admin", "admin123"),
]

LOGIN_FAIL_HINTS = re.compile(
    r"(?i)(invalid|incorrect|failed|denied|wrong|error|bad credentials|login required)"
)
LOGIN_OK_HINTS = re.compile(r"(?i)(logout|sign out|dashboard|welcome back|/my account)")


@dataclass(slots=True)
class LoginForm:
    page_url: str
    action_url: str
    method: str
    username_field: str
    password_field: str
    hidden_fields: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class AuthProbeResult:
    auth_type: str  # none | basic | form
    login_forms: list[LoginForm] = field(default_factory=list)
    basic_realm: str | None = None
    credential_attempts: int = 0
    success: bool = False
    working_username: str | None = None
    working_password: str | None = None
    session_cookie: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def basic_auth_header(self) -> str | None:
        if not self.success or not self.working_username:
            return None
        token = base64.b64encode(
            f"{self.working_username}:{self.working_password or ''}".encode()
        ).decode()
        return f"Basic {token}"


class _LoginFormParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.forms: list[LoginForm] = []
        self._current: dict[str, Any] | None = None
        self._has_password = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k: (v or "") for k, v in attrs}
        t = tag.lower()
        if t == "form":
            self._flush()
            action = ad.get("action") or self.base_url
            self._current = {
                "action": urljoin(self.base_url, action),
                "method": (ad.get("method") or "GET").upper(),
                "hidden": {},
                "user_field": None,
                "pass_field": None,
            }
            self._has_password = False
        elif t == "input" and self._current is not None:
            name = ad.get("name") or ad.get("id") or ""
            itype = (ad.get("type") or "text").lower()
            if itype == "password":
                self._has_password = True
                self._current["pass_field"] = name or "password"
            elif itype in ("text", "email") and not self._current["user_field"]:
                if re.search(r"(?i)user|email|login|name", name):
                    self._current["user_field"] = name or "username"
            elif itype == "hidden" and name:
                self._current["hidden"][name] = ad.get("value", "")
        elif t == "button" and self._current is not None:
            if (ad.get("type") or "").lower() == "submit" and ad.get("name"):
                self._current["hidden"][ad["name"]] = ad.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._flush()

    def _flush(self) -> None:
        if self._current and self._has_password and self._current.get("pass_field"):
            self.forms.append(
                LoginForm(
                    page_url=self.base_url,
                    action_url=self._current["action"],
                    method=self._current["method"],
                    username_field=self._current["user_field"] or "username",
                    password_field=self._current["pass_field"],
                    hidden_fields=dict(self._current["hidden"]),
                )
            )
        self._current = None
        self._has_password = False

    def close(self) -> None:
        self._flush()
        super().close()


def detect_login_forms(url: str, html: str) -> list[LoginForm]:
    parser = _LoginFormParser(url)
    try:
        parser.feed(html[:500_000])
        parser.close()
    except Exception:
        return []
    return parser.forms


def _basic_from_headers(headers: httpx.Headers) -> tuple[bool, str | None]:
    www = headers.get("WWW-Authenticate") or headers.get("www-authenticate") or ""
    if www.lower().startswith("basic"):
        realm_m = re.search(r'realm="([^"]*)"', www, re.I)
        return True, realm_m.group(1) if realm_m else ""
    return False, None


def _is_basic_challenge(resp: httpx.Response) -> tuple[bool, str | None]:
    if resp.status_code != 401:
        return False, None
    return _basic_from_headers(resp.headers)


def _login_success(before_len: int, resp: httpx.Response, body: str) -> bool:
    if resp.status_code in (301, 302, 303, 307, 308):
        loc = resp.headers.get("location", "")
        if loc and "login" not in loc.lower():
            return True
    if resp.status_code in (200, 204) and LOGIN_OK_HINTS.search(body):
        return True
    if resp.status_code in (200, 204) and not LOGIN_FAIL_HINTS.search(body):
        if abs(len(body) - before_len) > 80 and "password" not in body.lower()[:2000]:
            return True
    if resp.status_code == 403:
        return False
    cookies = resp.headers.get("set-cookie", "")
    if cookies and re.search(r"(?i)(session|sid|token|auth)", cookies):
        if not LOGIN_FAIL_HINTS.search(body):
            return True
    return False


def _load_lines(name: str) -> list[str]:
    path = WORDLIST_DIR / name
    if not path.is_file():
        return []
    return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


def build_credential_list(policy: AuthPolicy, cap: int) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = list(DEFAULT_CREDS)
    if policy in (AuthPolicy.COMMON, AuthPolicy.UNRESTRICTED):
        users = _load_lines("default_users.txt") or ["admin"]
        passwords = _load_lines("common_passwords.txt")
        for user in users[:5]:
            for pwd in passwords:
                pairs.append((user, pwd))
    # dedupe preserve order
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for p in pairs:
        if p not in seen:
            seen.add(p)
            out.append(p)
        if len(out) >= cap:
            break
    return out[:cap]


async def probe_basic_auth(
    client: httpx.AsyncClient,
    url: str,
    consent: AuthConsent,
    *,
    response_headers: httpx.Headers | None = None,
    response_status: int | None = None,
) -> AuthProbeResult:
    result = AuthProbeResult(auth_type="none")
    initial: httpx.Response | None = None
    if response_headers is not None and response_status == 401:
        is_basic, realm = _basic_from_headers(response_headers)
    else:
        try:
            initial = await client.get(url)
        except httpx.HTTPError as exc:
            result.notes.append(f"basic probe fetch failed: {exc}")
            return result
        is_basic, realm = _is_basic_challenge(initial)

    if not is_basic:
        return result

    result.auth_type = "basic"
    result.basic_realm = realm
    result.notes.append(f"HTTP Basic Auth realm={realm!r}")

    if not consent.ensure_approved(f"Basic Auth at {url}"):
        result.notes.append("credential testing skipped (policy)")
        return result

    creds = build_credential_list(consent.policy, consent.basic_cap())
    before_len = len(initial.text) if initial else 0

    for user, pwd in creds:
        result.credential_attempts += 1
        try:
            resp = await client.get(url, auth=(user, pwd))
        except httpx.HTTPError:
            continue
        if resp.status_code not in (401, 403) and _login_success(before_len, resp, resp.text):
            result.success = True
            result.working_username = user
            result.working_password = pwd
            result.notes.append(f"basic auth success: {user}:{pwd} (HTTP {resp.status_code})")
            return result

    result.notes.append(f"tried {result.credential_attempts} basic credential pair(s)")
    return result


async def probe_login_forms(
    client: httpx.AsyncClient,
    url: str,
    html: str,
    consent: AuthConsent,
) -> AuthProbeResult:
    forms = detect_login_forms(url, html)
    result = AuthProbeResult(auth_type="none", login_forms=forms)
    if not forms:
        return result

    result.auth_type = "form"
    result.notes.append(f"found {len(forms)} login form(s)")

    if not consent.ensure_approved(f"login form at {url}"):
        result.notes.append("form credential testing skipped (policy)")
        return result

    creds = build_credential_list(consent.policy, consent.form_cap())
    before_len = len(html)

    for form in forms[:2]:
        for user, pwd in creds:
            result.credential_attempts += 1
            data = dict(form.hidden_fields)
            data[form.username_field] = user
            data[form.password_field] = pwd
            try:
                if form.method == "GET":
                    resp = await client.get(form.action_url, params=data)
                else:
                    resp = await client.post(form.action_url, data=data)
            except httpx.HTTPError:
                continue
            if _login_success(before_len, resp, resp.text):
                result.success = True
                result.working_username = user
                result.working_password = pwd
                result.session_cookie = resp.headers.get("set-cookie")
                result.notes.append(
                    f"form login success @ {form.action_url}: {user}:{pwd} (HTTP {resp.status_code})"
                )
                return result

    result.notes.append(f"tried {result.credential_attempts} form attempt(s)")
    return result


async def run_auth_probes(
    client: httpx.AsyncClient,
    url: str,
    *,
    status: int,
    headers: httpx.Headers,
    body: str,
    consent: AuthConsent,
) -> AuthProbeResult:
    """Run detection + optional credential tests."""
    if not consent.enabled:
        forms = detect_login_forms(url, body)
        if forms:
            return AuthProbeResult(auth_type="form", login_forms=forms, notes=["detection only (auth policy=off)"])
        is_basic, realm = _basic_from_headers(headers)
        if status == 401 and is_basic:
            return AuthProbeResult(auth_type="basic", basic_realm=realm, notes=["detection only"])
        return AuthProbeResult()

    is_basic, _ = _basic_from_headers(headers)
    if status == 401 and is_basic:
        basic = await probe_basic_auth(
            client, url, consent, response_headers=headers, response_status=status
        )
        if basic.success or basic.auth_type == "basic":
            return basic

    if "html" in (headers.get("content-type") or "").lower() or body.lstrip().startswith("<"):
        form_result = await probe_login_forms(client, url, body, consent)
        if form_result.auth_type == "form":
            return form_result

    if status == 401:
        return await probe_basic_auth(client, url, consent)

    return AuthProbeResult()
