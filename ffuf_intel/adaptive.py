"""Adaptive HTTP method and content-type/body discovery."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

# Methods probed when GET returns 405 or Allow header is missing
METHOD_PROBE_ORDER = ("OPTIONS", "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")

# Status codes that mean "wrong method" vs "wrong body/type"
METHOD_REJECT = frozenset({405, 501})
CONTENT_REJECT = frozenset({415, 406})  # Unsupported Media Type / Not Acceptable
BODY_UNCERTAIN = frozenset({400, 422})  # might be correct type, wrong schema

# Prefer responses that look "real" (not method/type rejection)
SUCCESSISH = frozenset({200, 201, 202, 204, 206, 301, 302, 303, 307, 308, 401, 403})

CONTENT_PROBES: list[tuple[str, str]] = [
    ("application/json", "{}"),
    ("application/json", '{"query":"{__typename}"}'),
    ("application/json", '{"FUZZ":"probe"}'),
    ("application/x-www-form-urlencoded", "FUZZ=probe"),
    ("text/plain", "FUZZ"),
    ("application/xml", "<root>FUZZ</root>"),
]


@dataclass(slots=True)
class RequestProfile:
    """Best-known way to talk to an endpoint."""

    method: str = "GET"
    content_type: str | None = None
    body: str | None = None
    accepted_methods: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    authorization: str | None = None  # value for Authorization header (e.g. "Basic ...")
    cookie: str | None = None

    def ffuf_headers(self) -> list[str]:
        headers: list[str] = []
        if self.content_type:
            headers.append(f"Content-Type: {self.content_type}")
        if self.authorization:
            headers.append(f"Authorization: {self.authorization}")
        if self.cookie:
            headers.append(f"Cookie: {self.cookie}")
        return headers

    def ffuf_body_template(self) -> str | None:
        """Body template for ffuf with FUZZ placeholder."""
        if self.method in ("GET", "HEAD", "DELETE", "OPTIONS"):
            return None
        if self.body and "FUZZ" in self.body:
            return self.body
        if self.content_type and "json" in self.content_type:
            return '{"path":"FUZZ"}'
        if self.content_type and "urlencoded" in self.content_type:
            return "FUZZ=1"
        return "FUZZ"


def _parse_allow_header(value: str) -> list[str]:
    return [m.strip().upper() for m in value.split(",") if m.strip()]


def _score_response(status: int) -> int:
    if status in SUCCESSISH:
        return 100
    if status in BODY_UNCERTAIN:
        return 50
    if status in CONTENT_REJECT:
        return 10
    if status in METHOD_REJECT:
        return 0
    return 30


def _pick_best_method(results: dict[str, int]) -> str:
    """Choose method with highest response score."""
    if not results:
        return "GET"
    ranked = sorted(results.items(), key=lambda kv: (-_score_response(kv[1]), kv[0]))
    return ranked[0][0]


def _graphql_hint(url: str, path: str) -> bool:
    return bool(re.search(r"(?i)graphql", url + path))


async def discover_methods(client: httpx.AsyncClient, url: str) -> tuple[list[str], str, list[str]]:
    """
    Find allowed HTTP methods. Returns (accepted_methods, best_method, notes).
    """
    notes: list[str] = []
    accepted: list[str] = []
    scores: dict[str, int] = {}

    try:
        opt = await client.request("OPTIONS", url)
        allow = opt.headers.get("Allow") or opt.headers.get("allow")
        if allow:
            accepted = _parse_allow_header(allow)
            notes.append(f"Allow: {', '.join(accepted)}")
            for m in accepted:
                scores[m] = max(scores.get(m, 0), _score_response(opt.status_code))
    except httpx.HTTPError:
        notes.append("OPTIONS failed")

    probe_list = list(METHOD_PROBE_ORDER)
    if accepted:
        probe_list = [m for m in probe_list if m in accepted] or probe_list

    for method in probe_list:
        if method == "OPTIONS":
            continue
        try:
            resp = await client.request(method, url)
        except httpx.HTTPError:
            continue
        if resp.status_code not in METHOD_REJECT:
            if method not in accepted:
                accepted.append(method)
            scores[method] = max(scores.get(method, 0), _score_response(resp.status_code))

    if not accepted:
        accepted = ["GET"]

    best = _pick_best_method(scores)
    if "POST" in accepted and _graphql_hint(url, ""):
        best = "POST"
        notes.append("graphql path bias → POST")

    return accepted, best, notes


async def discover_content(
    client: httpx.AsyncClient,
    url: str,
    method: str,
) -> tuple[str | None, str | None, list[str]]:
    """
    Try Content-Type + body combinations for POST/PUT/PATCH.
    Returns (content_type, body, notes).
    """
    if method not in ("POST", "PUT", "PATCH"):
        return None, None, []

    notes: list[str] = []
    best_ct: str | None = None
    best_body: str | None = None
    best_score = -1

    probes = list(CONTENT_PROBES)
    if _graphql_hint(url, ""):
        probes.insert(0, ("application/json", '{"query":"{__typename}"}'))

    for content_type, body in probes:
        try:
            resp = await client.request(
                method,
                url,
                headers={"Content-Type": content_type},
                content=body.encode("utf-8"),
            )
        except httpx.HTTPError:
            continue

        score = _score_response(resp.status_code)
        notes.append(f"{method} {content_type} → {resp.status_code}")

        if resp.status_code in CONTENT_REJECT:
            continue
        if score > best_score:
            best_score = score
            best_ct = content_type
            best_body = body

    return best_ct, best_body, notes


async def build_request_profile(
    client: httpx.AsyncClient,
    url: str,
    *,
    initial_status: int | None = None,
    initial_method: str = "GET",
) -> RequestProfile:
    """
    Build the best request profile for a URL after optional 405/415/400 signals.
    """
    profile = RequestProfile(method=initial_method)
    need_method_probe = initial_status in METHOD_REJECT or initial_status is None

    try:
        probe = await client.request(initial_method, url)
        initial_status = probe.status_code
        if probe.status_code in METHOD_REJECT:
            need_method_probe = True
    except httpx.HTTPError:
        profile.notes.append(f"{initial_method} failed")
        need_method_probe = True

    if need_method_probe:
        accepted, best, notes = await discover_methods(client, url)
        profile.accepted_methods = accepted
        profile.method = best
        profile.notes.extend(notes)
    else:
        profile.accepted_methods = [initial_method]
        profile.method = initial_method

    if profile.method in ("POST", "PUT", "PATCH") or initial_status in CONTENT_REJECT | BODY_UNCERTAIN:
        ct, body, cnotes = await discover_content(client, url, profile.method)
        profile.content_type = ct
        profile.body = body
        profile.notes.extend(cnotes)

    return profile
