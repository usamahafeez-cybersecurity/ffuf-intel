"""Same-origin crawling for version and JavaScript endpoint intelligence."""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlparse

import httpx


@dataclass(slots=True)
class FormInput:
    name: str
    input_type: str


@dataclass(slots=True)
class FormInfo:
    page: str
    action: str
    method: str
    inputs: list[FormInput] = field(default_factory=list)


@dataclass(slots=True)
class CrawlResult:
    urls: list[str]
    js_files: list[str]
    inline_scripts: dict[str, str]
    forms: list[FormInfo]
    errors: list[str] = field(default_factory=list)


class _PageParser(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__()
        self.page_url = page_url
        self.links: set[str] = set()
        self.js_files: set[str] = set()
        self.inline_scripts: list[str] = []
        self.forms: list[FormInfo] = []
        self._script_chunks: list[str] | None = None
        self._current_form: FormInfo | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k.lower(): v or "" for k, v in attrs}
        tag = tag.lower()
        if tag == "a" and values.get("href"):
            self.links.add(urljoin(self.page_url, values["href"]))
        elif tag == "script":
            if values.get("src"):
                self.js_files.add(urljoin(self.page_url, values["src"]))
            else:
                self._script_chunks = []
        elif tag == "form":
            self._current_form = FormInfo(
                page=self.page_url,
                action=urljoin(self.page_url, values.get("action", "")),
                method=(values.get("method") or "GET").upper(),
            )
        elif tag == "input" and self._current_form is not None:
            self._current_form.inputs.append(
                FormInput(
                    name=values.get("name", ""),
                    input_type=values.get("type", "text") or "text",
                )
            )

    def handle_data(self, data: str) -> None:
        if self._script_chunks is not None:
            self._script_chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "script" and self._script_chunks is not None:
            script = "".join(self._script_chunks).strip()
            if script:
                self.inline_scripts.append(script)
            self._script_chunks = None
        elif tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def same_origin(candidate: str, start_url: str) -> bool:
    parsed_candidate = urlparse(candidate)
    parsed_start = urlparse(start_url)
    return (
        parsed_candidate.scheme in ("http", "https")
        and parsed_candidate.scheme == parsed_start.scheme
        and parsed_candidate.netloc == parsed_start.netloc
    )


def normalize_page_url(url: str) -> str:
    clean, _fragment = urldefrag(url)
    return clean.rstrip("/") or clean


def crawl_site(
    start_url: str,
    *,
    max_depth: int = 2,
    max_pages: int = 100,
    timeout: float = 10.0,
    verify_tls: bool = True,
    follow_redirects: bool = True,
    user_agent: str = "ffuf-intel/1.0",
) -> CrawlResult:
    """Breadth-first same-origin crawl with JS and form extraction."""
    start = normalize_page_url(start_url.replace("FUZZ", "").rstrip("/") or start_url)
    queue: list[tuple[str, int]] = [(start, 0)]
    visited: set[str] = set()
    js_files: set[str] = set()
    inline_scripts: dict[str, str] = {}
    forms: list[FormInfo] = []
    errors: list[str] = []

    with httpx.Client(
        timeout=timeout,
        verify=verify_tls,
        follow_redirects=follow_redirects,
        headers={"User-Agent": user_agent},
    ) as client:
        while queue and len(visited) < max_pages:
            url, depth = queue.pop(0)
            url = normalize_page_url(url)
            if url in visited or depth > max_depth or not same_origin(url, start):
                continue
            visited.add(url)
            try:
                resp = client.get(url)
            except httpx.HTTPError as exc:
                errors.append(f"{url}: {type(exc).__name__}")
                continue
            content_type = resp.headers.get("content-type", "").lower()
            if "html" not in content_type and not resp.text.lstrip().startswith("<"):
                continue
            parser = _PageParser(str(resp.url))
            try:
                parser.feed(resp.text)
            except Exception as exc:
                errors.append(f"{url}: html_parse:{type(exc).__name__}")
                continue
            js_files.update(js for js in parser.js_files if same_origin(js, start))
            for idx, script in enumerate(parser.inline_scripts, start=1):
                inline_scripts[f"inline:{url}#{idx}"] = script
            forms.extend(parser.forms)
            if depth < max_depth:
                for link in sorted(parser.links):
                    clean_link = normalize_page_url(link)
                    if clean_link not in visited and same_origin(clean_link, start):
                        queue.append((clean_link, depth + 1))

    return CrawlResult(
        urls=sorted(visited),
        js_files=sorted(js_files),
        inline_scripts=inline_scripts,
        forms=forms,
        errors=errors,
    )
