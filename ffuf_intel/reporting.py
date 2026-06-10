"""Structured output reporting for ffuf-intel."""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .ffuf_runner import FfufResult
from .reasoning import ScanPass
from .patterns import InspectionFinding


def _slugify(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip().lower())
    value = re.sub(r"-+", "-", value).strip("-._")
    return value or "target"


def _target_label(target_url: str) -> str:
    parsed = urlparse(target_url)
    if parsed.netloc:
        return _slugify(parsed.netloc)
    return _slugify(target_url)


def create_session_dir(base_dir: Path, target_url: str) -> Path:
    base_dir = base_dir.expanduser().resolve()
    base_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    session_dir = base_dir / f"{_target_label(target_url)}-{stamp}"
    session_dir.mkdir(parents=True, exist_ok=False)
    return session_dir


def _ffuf_result_to_dict(result: FfufResult) -> dict[str, Any]:
    return {
        "url": result.url,
        "status": result.status,
        "length": result.length,
        "words": result.words,
        "lines": result.lines,
        "content_type": result.content_type,
        "redirect": result.redirect,
        "fuzz_word": result.fuzz_word,
    }


def _finding_to_dict(finding: InspectionFinding) -> dict[str, Any]:
    data = asdict(finding)
    data["triggers"] = sorted(finding.triggers)
    return data


def _pass_to_dict(pass_record: ScanPass) -> dict[str, Any]:
    return {
        "depth": pass_record.depth,
        "url": pass_record.url,
        "wordlist": str(pass_record.wordlist),
        "fuzz_mode": pass_record.fuzz_mode,
        "results": [_ffuf_result_to_dict(result) for result in pass_record.results],
        "findings": [_finding_to_dict(finding) for finding in pass_record.findings],
        "child_triggers": sorted(pass_record.child_triggers),
        "error": pass_record.error,
    }


def build_report_payload(
    *,
    target_url: str,
    wordlist: str,
    passes: list[ScanPass],
    errors: list[str],
    metadata: dict[str, Any] | None = None,
    intel: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "target_url": target_url,
        "wordlist": wordlist,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "metadata": metadata or {},
        "passes": [_pass_to_dict(pass_record) for pass_record in passes],
        "errors": list(errors),
        "summary": {
            "pass_count": len(passes),
            "result_count": sum(len(pass_record.results) for pass_record in passes),
            "finding_count": sum(1 for pass_record in passes for finding in pass_record.findings if finding.is_interesting),
        },
    }
    if intel:
        payload["intel"] = intel
    return payload


def render_markdown_report(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    lines = [
        "# ffuf-intel scan report",
        "",
        f"- Target: `{payload.get('target_url', '')}`",
        f"- Wordlist: `{payload.get('wordlist', '')}`",
        f"- Generated: `{payload.get('generated_at', '')}`",
        f"- Passes: `{summary.get('pass_count', 0)}`",
        f"- Hits inspected: `{summary.get('result_count', 0)}`",
        f"- Notable findings: `{summary.get('finding_count', 0)}`",
    ]
    metadata = payload.get("metadata") or {}
    if metadata:
        lines.append("")
        lines.append("## Runtime")
        for key, value in metadata.items():
            lines.append(f"- {key}: `{value}`")
    intel = payload.get("intel") or {}
    if intel:
        lines.append("")
        lines.append("## Intelligence")
        crawl = intel.get("crawl") or {}
        versions = intel.get("versions") or []
        js = intel.get("javascript") or {}
        lines.append(f"- Crawled URLs: `{len(crawl.get('urls', []))}`")
        lines.append(f"- JavaScript files: `{len(crawl.get('js_files', []))}`")
        lines.append(f"- Forms: `{len(crawl.get('forms', []))}`")
        lines.append(f"- Detected technologies: `{len(versions)}`")
        lines.append(f"- JS endpoints: `{len(js.get('endpoints', []))}`")
        if versions:
            lines.append("")
            lines.append("| Technology | Version | Source |")
            lines.append("|---|---|---|")
            for item in versions[:20]:
                lines.append(
                    f"| `{item.get('technology', '')}` | `{item.get('version', '')}` | `{item.get('source', '')}` |"
                )
        endpoints = js.get("endpoints") or []
        if endpoints:
            lines.append("")
            lines.append("Top JS endpoints:")
            for endpoint in endpoints[:20]:
                lines.append(f"- `{endpoint}`")
        secrets = js.get("secrets") or {}
        if secrets:
            lines.append("")
            lines.append("Potential JS secret patterns:")
            for name, hits in secrets.items():
                lines.append(f"- `{name}`: `{len(hits)}` match(es)")
    lines.append("")
    lines.append("## Passes")
    for idx, pass_record in enumerate(payload.get("passes", []), start=1):
        lines.append(f"### Pass {idx}")
        lines.append(f"- Depth: `{pass_record.get('depth', 0)}`")
        lines.append(f"- URL: `{pass_record.get('url', '')}`")
        lines.append(f"- Wordlist: `{Path(pass_record.get('wordlist', '')).name}`")
        lines.append(f"- Fuzz mode: `{pass_record.get('fuzz_mode', 'path')}`")
        lines.append(f"- Hits: `{len(pass_record.get('results', []))}`")
        lines.append(f"- Findings: `{len(pass_record.get('findings', []))}`")
        if pass_record.get("error"):
            lines.append(f"- Error: `{pass_record['error']}`")
        interesting = [
            f
            for f in pass_record.get("findings", [])
            if f.get("is_interesting") or f.get("score", 0) >= 3
        ]
        if interesting:
            lines.append("")
            lines.append("| URL | Score | Signals |")
            lines.append("|---|---:|---|")
            for finding in interesting[:10]:
                signals = ", ".join(finding.get("signals", [])[:8])
                lines.append(
                    f"| `{finding.get('url', '')}` | {finding.get('score', 0)} | {signals or '-'} |"
                )
        lines.append("")
    if payload.get("errors"):
        lines.append("## Errors")
        for err in payload["errors"][:20]:
            lines.append(f"- `{err}`")
    return "\n".join(lines).rstrip() + "\n"


def write_report_files(output_dir: Path, payload: dict[str, Any]) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "report.json"
    md_path = output_dir / "report.md"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(render_markdown_report(payload), encoding="utf-8")
    return {"json": json_path, "markdown": md_path}
