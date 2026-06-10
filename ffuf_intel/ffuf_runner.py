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
from .validate import resolve_wordlist


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

    tools_hint = Path(__file__).resolve().parents[1] / "tools"
    raise FfufNotFoundError(
        "ffuf binary not found.\n"
        f"  Install ffuf: https://github.com/ffuf/ffuf\n"
        f"  Or place binary in: {tools_hint}/ffuf (Linux) or ffuf.exe (Windows)\n"
        "  Or set FFUF_PATH / --ffuf-path"
    )


def normalize_fuzz_url(url: str) -> str:
    if "FUZZ" in url:
        return url
    return url.rstrip("/") + "/FUZZ"


INSPECTABLE_FFUF_STATUSES = frozenset({200, 302, 401, 403, 400, 405, 415, 406})

_BLOCKED_FFUF_ARGS = frozenset({"-o", "-of", "-u", "-w", "-ac"})


def _check_extra_args(extra_args: list[str] | None) -> None:
    if not extra_args:
        return
    for i, arg in enumerate(extra_args):
        if arg in _BLOCKED_FFUF_ARGS:
            raise FfufExecutionError(
                f"Cannot pass {arg} in --ffuf-args (managed by ffuf-intel)."
            )
        if arg == "-w" and i + 1 < len(extra_args):
            raise FfufExecutionError("Use -w on ffuf-intel, not in --ffuf-args.")


def run_ffuf(
    *,
    ffuf_bin: str,
    url: str,
    wordlist: Path,
    extra_args: list[str] | None = None,
    timeout: int | None = None,
    profile: RequestProfile | None = None,
    fuzz_url: bool = True,
) -> tuple[list[FfufResult], Path]:
    wordlist = resolve_wordlist(wordlist)
    _check_extra_args(extra_args)

    target_url = normalize_fuzz_url(url) if fuzz_url else url
    fd, out_name = tempfile.mkstemp(suffix=".ffuf.json")
    os.close(fd)
    out_file = Path(out_name)
    method = profile.method if profile else "GET"

    cmd: list[str] = [
        ffuf_bin,
        "-u",
        target_url,
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
        cleanup_json(out_file)
        raise FfufExecutionError(f"ffuf timed out after {timeout}s") from exc
    except FileNotFoundError as exc:
        cleanup_json(out_file)
        raise FfufNotFoundError(f"Failed to execute ffuf at: {ffuf_bin}") from exc

    stderr = (proc.stderr or "").strip()
    stdout = (proc.stdout or "").strip()

    if proc.returncode != 0 and not out_file.exists():
        raise FfufExecutionError(_format_ffuf_failure(cmd, proc.returncode, stderr, stdout))

    if not out_file.exists() or out_file.stat().st_size == 0:
        raise FfufExecutionError(
            _format_ffuf_failure(cmd, proc.returncode, stderr, stdout)
            + "\nNo JSON output file was produced."
        )

    try:
        results = parse_ffuf_json(out_file)
    except (json.JSONDecodeError, ValueError) as exc:
        raise FfufExecutionError(
            f"ffuf produced invalid JSON: {exc}\nstderr: {stderr or '(empty)'}"
        ) from exc

    if proc.returncode != 0 and not results:
        raise FfufExecutionError(_format_ffuf_failure(cmd, proc.returncode, stderr, stdout))

    if proc.returncode != 0 and stderr:
        # ffuf sometimes exits non-zero with partial results
        pass

    return results, out_file


def _format_ffuf_failure(cmd: list[str], code: int, stderr: str, stdout: str) -> str:
    parts = [
        f"ffuf failed (exit {code}).",
        f"Command: {' '.join(cmd)}",
    ]
    if stderr:
        parts.append(f"stderr:\n{stderr}")
    if stdout and not stderr:
        parts.append(f"stdout:\n{stdout}")
    lowered = stderr.lower()
    if "no such file" in lowered or "cannot open" in lowered or "wordlist" in lowered:
        parts.append("Hint: check -w wordlist path exists and is readable.")
    return "\n".join(parts)


def parse_ffuf_json(path: Path) -> list[FfufResult]:
    with path.open(encoding="utf-8") as fh:
        data: dict[str, Any] = json.load(fh)

    raw = data.get("results")
    if raw is None:
        raise ValueError("ffuf JSON missing 'results' key")
    if not isinstance(raw, list):
        raise ValueError("ffuf JSON 'results' is not a list")

    parsed: list[FfufResult] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
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
