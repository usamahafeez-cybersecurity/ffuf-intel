"""Technology and version fingerprinting from HTTP, HTML, and JavaScript."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

import httpx


@dataclass(slots=True)
class VersionFinding:
    technology: str
    version: str
    source: str
    evidence: str


HEADER_PATTERNS: dict[str, dict[str, re.Pattern[str]]] = {
    "Server": {
        "Apache": re.compile(r"Apache[/ ]([\d.]+)", re.I),
        "Nginx": re.compile(r"nginx[/ ]([\d.]+)", re.I),
        "Microsoft IIS": re.compile(r"Microsoft-IIS[/ ]([\d.]+)", re.I),
        "LiteSpeed": re.compile(r"LiteSpeed[/ ]([\d.]+)", re.I),
        "Cloudflare": re.compile(r"\bcloudflare\b", re.I),
    },
    "X-Powered-By": {
        "PHP": re.compile(r"PHP[/ ]([\d.]+)", re.I),
        "ASP.NET": re.compile(r"ASP\.NET(?:[/ ]([\d.]+))?", re.I),
        "Express": re.compile(r"Express(?:[/ ]([\d.]+))?", re.I),
        "Laravel": re.compile(r"Laravel(?:[/ ]([\d.]+))?", re.I),
        "Next.js": re.compile(r"Next\.js(?:[/ ]([\d.]+))?", re.I),
    },
    "X-Generator": {
        "Drupal": re.compile(r"Drupal(?:[/ ]([\d.]+))?", re.I),
        "WordPress": re.compile(r"WordPress(?:[/ ]([\d.]+))?", re.I),
    },
}

HTML_PATTERNS: dict[str, re.Pattern[str]] = {
    "WordPress": re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress ([\d.]+)', re.I),
    "Drupal": re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Drupal ([\d.]+)', re.I),
    "Joomla": re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']Joomla!? ?([\d.]*)', re.I),
    "TYPO3": re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']TYPO3 CMS ([\d.]+)', re.I),
    "Shopify": re.compile(r"Shopify\.theme\.version\s*=\s*['\"]?([\d.]+)", re.I),
    "React": re.compile(r"react(?:\.production)?(?:\.min)?\.js\?ver=([\d.]+)", re.I),
}

JS_PATTERNS: dict[str, re.Pattern[str]] = {
    "jQuery": re.compile(r"jquery[.-](?:min[.-])?v?([\d.]+)|jQuery JavaScript Library v([\d.]+)", re.I),
    "React": re.compile(r"react[.-](?:production[.-])?(?:min[.-])?v?([\d.]+)", re.I),
    "Angular": re.compile(r"angular[.-]v?([\d.]+)", re.I),
    "Vue": re.compile(r"vue[.-](?:runtime[.-])?v?([\d.]+)", re.I),
    "Bootstrap": re.compile(r"bootstrap[.-]v?([\d.]+)|Bootstrap v([\d.]+)", re.I),
    "Lodash": re.compile(r"lodash[.-]v?([\d.]+)|lodash v([\d.]+)", re.I),
    "Moment.js": re.compile(r"moment[.-]v?([\d.]+)|Moment\.js ([\d.]+)", re.I),
    "Axios": re.compile(r"axios[.-]v?([\d.]+)", re.I),
    "three.js": re.compile(r"three[.-](?:module[.-])?r?([\d.]+)", re.I),
}


def _version(match: re.Match[str]) -> str:
    for group in match.groups():
        if group:
            return group
    return "detected"


def _add_unique(findings: list[VersionFinding], finding: VersionFinding) -> None:
    key = (finding.technology.lower(), finding.version, finding.source)
    if any((f.technology.lower(), f.version, f.source) == key for f in findings):
        return
    findings.append(finding)


def detect_versions(
    target_url: str,
    *,
    js_urls: Iterable[str] = (),
    inline_scripts: dict[str, str] | None = None,
    timeout: float = 10.0,
    verify_tls: bool = True,
    follow_redirects: bool = True,
    user_agent: str = "ffuf-intel/1.0",
) -> list[VersionFinding]:
    """Collect best-effort technology versions without external CVE lookups."""
    findings: list[VersionFinding] = []
    inline_scripts = inline_scripts or {}
    page_url = target_url.replace("FUZZ", "").rstrip("/") or target_url

    with httpx.Client(
        timeout=timeout,
        verify=verify_tls,
        follow_redirects=follow_redirects,
        headers={"User-Agent": user_agent},
    ) as client:
        try:
            resp = client.get(page_url)
        except httpx.HTTPError:
            resp = None
        if resp is not None:
            for header, patterns in HEADER_PATTERNS.items():
                value = resp.headers.get(header, "")
                if not value:
                    continue
                for tech, pattern in patterns.items():
                    match = pattern.search(value)
                    if match:
                        _add_unique(
                            findings,
                            VersionFinding(tech, _version(match), f"header:{header}", value[:160]),
                        )
            html = resp.text[:512_000]
            for tech, pattern in HTML_PATTERNS.items():
                match = pattern.search(html)
                if match:
                    _add_unique(
                        findings,
                        VersionFinding(tech, _version(match), "html", match.group(0)[:160]),
                    )
            if "wp-content" in html or "wp-includes" in html:
                _add_unique(findings, VersionFinding("WordPress", "detected", "html", "wp-content/wp-includes"))
            if "drupalSettings" in html:
                _add_unique(findings, VersionFinding("Drupal", "detected", "html", "drupalSettings"))

        for js_url in js_urls:
            _scan_js_text(findings, js_url, js_url, source_prefix="js_filename")
            try:
                js_resp = client.get(js_url)
            except httpx.HTTPError:
                continue
            _scan_js_text(findings, js_url, js_resp.text[:200_000], source_prefix="js_content")

    for source, script in inline_scripts.items():
        _scan_js_text(findings, source, script[:200_000], source_prefix="inline_js")

    return sorted(findings, key=lambda f: (f.technology.lower(), f.source, f.version))


def _scan_js_text(
    findings: list[VersionFinding],
    source: str,
    text: str,
    *,
    source_prefix: str,
) -> None:
    for tech, pattern in JS_PATTERNS.items():
        match = pattern.search(text)
        if match:
            _add_unique(
                findings,
                VersionFinding(tech, _version(match), source_prefix, source[:180]),
            )
