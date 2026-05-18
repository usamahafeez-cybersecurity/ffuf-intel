"""Native ffuf subprocess execution."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .adaptive import RequestProfile


class FfufNotFoundError(RuntimeError):
    pass


class FfufExecutionError(RuntimeError):
    pass


@dataclass(slots=True)
class FfufResult:
    url: str
    status: int
    length: int
    words: int
    lines: int
    content_type: str
    redirect: str
    fuzz_word: str


def _bundled_ffuf_candidates() -> list[Path]:
    """Search common local install locations (no PATH required)."""
    candidates: list[Path] = []
    env = os.environ.get("FFUF_PATH")
    if env:
        candidates.append(Path(env))
    package_root = Path(__file__).resolve().parents[1]
    candidates.extend(
        [
            package_root / "tools" / "ffuf.exe",
            package_root / "tools" / "ffuf",
            Path.cwd() / "tools" / "ffuf.exe",
            Path.cwd() / "tools" / "ffuf",
        ]
    )
    return candidates


def locate_ffuf(explicit: str | None = None) -> str:
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise FfufNotFoundError(f"ffuf binary not found at: {explicit}")
        return str(path.resolve())

    found = shutil.which("ffuf")
    if found:
        return found

    for candidate in _bundled_ffuf_candidates():
        if candidate.is_file():
            return str(candidate.resolve())

    tools_hint = Path(__file__).resolve().parents[1] / "tools" / "ffuf.exe"
    raise FfufNotFoundError(
        "ffuf binary not found.\n"
        f"  1) Run INSTALL_FFUF.ps1 in the project folder, or\n"
        f"  2) Pass --ffuf-path \"{tools_hint}\", or\n"
        f"  3) Install ffuf and add it to PATH: https://github.com/ffuf/ffuf"
    )


def normalize_fuzz_url(url: str) -> str:
    if "FUZZ" in url:
        return url
    return url.rstrip("/") + "/FUZZ"


# ffuf hits we always queue for deep inspection (incl. method/content negotiation)
INSPECTABLE_FFUF_STATUSES = frozenset({200, 302, 401, 403, 400, 405, 415, 406})


def run_ffuf(
    *,
    ffuf_bin: str,
    url: str,
    wordlist: Path,
    extra_args: list[str] | None = None,
    timeout: int | None = None,
    profile: RequestProfile | None = None,
) -> tuple[list[FfufResult], Path]:
    fuzz_url = normalize_fuzz_url(url)
    fd, out_name = tempfile.mkstemp(suffix=".ffuf.json")
    os.close(fd)
    out_file = Path(out_name)
    method = profile.method if profile else "GET"
    cmd: list[str] = [
        ffuf_bin,
        "-u",
        fuzz_url,
        "-w",
        str(wordlist),
        "-X",
        method,
        "-ac",
        "-o",
        str(out_file),
        "-of",
        "json",
        "-noninteractive",
    ]
    if profile:
        for header in profile.ffuf_headers():
            cmd.extend(["-H", header])
        body = profile.ffuf_body_template()
        if body:
            cmd.extend(["-d", body])
    if extra_args:
        cmd.extend(extra_args)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise FfufExecutionError(f"ffuf timed out after {timeout}s") from exc
    except FileNotFoundError as exc:
        raise FfufNotFoundError(f"Failed to execute ffuf at: {ffuf_bin}") from exc
    if proc.returncode != 0 and not out_file.exists():
        raise FfufExecutionError(f"ffuf failed (exit {proc.returncode}). stderr: {proc.stderr or '(empty)'}")
    return parse_ffuf_json(out_file), out_file


def parse_ffuf_json(path: Path) -> list[FfufResult]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open(encoding="utf-8") as fh:
        data: dict[str, Any] = json.load(fh)
    parsed: list[FfufResult] = []
    for item in data.get("results", []):
        status = int(item.get("status", 0))
        if status not in INSPECTABLE_FFUF_STATUSES:
            continue
        input_block = item.get("input") or {}
        parsed.append(
            FfufResult(
                url=str(item.get("url", "")),
                status=status,
                length=int(item.get("length", 0)),
                words=int(item.get("words", 0)),
                lines=int(item.get("lines", 0)),
                content_type=str(item.get("content-type", "")),
                redirect=str(item.get("redirectlocation", "")),
                fuzz_word=str(input_block.get("FUZZ", "")),
            )
        )
    return parsed


def cleanup_json(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
