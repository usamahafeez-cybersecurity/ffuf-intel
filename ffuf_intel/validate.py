"""Preflight validation before scanning."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from urllib.parse import urlparse


class PreflightError(Exception):
    """User-facing configuration error."""


class WordlistError(PreflightError):
    pass


class TargetError(PreflightError):
    pass


def resolve_wordlist(path: Path) -> Path:
    """Resolve wordlist to an absolute path and validate it."""
    if not path or str(path).strip() == "":
        raise WordlistError("Wordlist path is empty.")

    candidate = path.expanduser()
    if not candidate.is_absolute():
        candidate = (Path.cwd() / candidate).resolve()
    else:
        candidate = candidate.resolve()

    if candidate.is_dir():
        raise WordlistError(
            f"Wordlist path is a directory, not a file:\n  {candidate}\n"
            f"Pass a file path, e.g. -w {candidate / 'common.txt'}"
        )

    if not candidate.exists():
        hints = _wordlist_hints(candidate)
        raise WordlistError(
            f"Wordlist not found:\n  {candidate}\n"
            f"  (from -w {path})\n"
            f"  cwd: {Path.cwd()}{hints}"
        )

    if not os.access(candidate, os.R_OK):
        raise WordlistError(f"Wordlist is not readable:\n  {candidate}")

    size = candidate.stat().st_size
    if size == 0:
        raise WordlistError(f"Wordlist is empty (0 bytes):\n  {candidate}")

    line_count = _count_lines(candidate)
    if line_count == 0:
        raise WordlistError(f"Wordlist has no non-empty lines:\n  {candidate}")

    return candidate


def _count_lines(path: Path) -> int:
    count = 0
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.strip() and not line.lstrip().startswith("#"):
                count += 1
    return count


def _wordlist_hints(missing: Path) -> str:
    """Suggest common wordlist locations (Kali / SecLists)."""
    common = [
        Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),
        Path("/usr/share/wordlists/dirb/common.txt"),
        Path("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
    ]
    found = [p for p in common if p.is_file()]
    if not found:
        return ""
    lines = ["", "Common wordlists on this system:"]
    lines.extend(f"  -w {p}" for p in found[:4])
    return "\n".join(lines)


def validate_target_url(url: str) -> str:
    if not url or not url.strip():
        raise TargetError("Target URL is empty.")
    normalized = url.strip()
    if "FUZZ" not in normalized:
        normalized = normalized.rstrip("/") + "/FUZZ"
    parsed = urlparse(normalized if "://" in normalized else f"http://{normalized}")
    if not parsed.scheme or not parsed.netloc:
        raise TargetError(
            f"Invalid target URL: {url!r}\n"
            "Use format: https://host.example/FUZZ"
        )
    if parsed.scheme not in ("http", "https"):
        raise TargetError(f"Unsupported URL scheme {parsed.scheme!r} (use http or https).")
    return normalized


def verify_ffuf_binary(ffuf_bin: str) -> None:
    try:
        proc = subprocess.run(
            [ffuf_bin, "-V"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except OSError as exc:
        raise PreflightError(f"Cannot execute ffuf at {ffuf_bin}: {exc}") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise PreflightError(
            f"ffuf binary failed health check (-V):\n  {ffuf_bin}\n  {detail or 'unknown error'}"
        )


def wordlist_info(path: Path) -> str:
  lines = _count_lines(path)
  size_kb = path.stat().st_size / 1024
  return f"{path.name} ({lines} entries, {size_kb:.1f} KB)"
