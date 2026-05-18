"""Command-line interface for ffuf-intel."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console

from .auth_policy import AuthConsent, AuthPolicy
from .ffuf_runner import FfufExecutionError, FfufNotFoundError, locate_ffuf
from .inspector import DeepInspector
from .reasoning import CampaignError, ReasoningEngine
from .validate import PreflightError, TargetError, validate_target_url, verify_ffuf_binary, wordlist_info, resolve_wordlist


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ffuf-intel",
        description=(
            "Intelligent ffuf wrapper: auto-calibration, deep content inspection, "
            "and behavioral next-hop fuzzing."
        ),
    )
    p.add_argument("-u", "--url", required=True, help="Target URL (FUZZ appended if missing).")
    p.add_argument("-w", "--wordlist", required=True, type=Path, help="Primary ffuf wordlist file.")
    p.add_argument("--ffuf-path", default=None, help="Explicit path to ffuf binary.")
    p.add_argument("--ffuf-args", nargs=argparse.REMAINDER, default=[], help="Extra ffuf args after --.")
    p.add_argument("--max-depth", type=int, default=1, help="Recursive reasoning depth (default: 1).")
    p.add_argument("--concurrency", type=int, default=20, help="Parallel inspection requests.")
    p.add_argument("--timeout", type=float, default=15.0, help="Inspection HTTP timeout.")
    p.add_argument("--ffuf-timeout", type=int, default=None, help="ffuf subprocess timeout in seconds.")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verify for inspection.")
    p.add_argument("--no-follow-redirects", action="store_true", help="Do not follow redirects.")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output.")
    p.add_argument("--no-adaptive", action="store_true", help="Disable method/Content-Type probing.")
    p.add_argument("--max-inspect", type=int, default=100, help="Max endpoints to inspect per pass (default: 100).")
    p.add_argument(
        "--auth-policy",
        choices=[p.value for p in AuthPolicy],
        default=AuthPolicy.OFF.value,
        help="Credential testing: off, ask, defaults, common, unrestricted (default: off).",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Exit with error if any ffuf pass fails.",
    )
    return p


async def _async_main(args: argparse.Namespace) -> int:
    console = Console()
    exit_code = 0

    try:
        target_url = validate_target_url(args.url)
        wordlist = resolve_wordlist(args.wordlist)
    except (PreflightError, TargetError) as exc:
        console.print(f"[bold red]Configuration error:[/]\n{exc}")
        return 2

    try:
        ffuf_bin = locate_ffuf(args.ffuf_path)
        verify_ffuf_binary(ffuf_bin)
    except (FfufNotFoundError, PreflightError) as exc:
        console.print(f"[bold red]ffuf error:[/]\n{exc}")
        return 2

    console.print(f"[dim]Target:[/] {target_url}")
    console.print(f"[dim]Wordlist:[/] {wordlist_info(wordlist)}")
    if args.verbose:
        console.print(f"[dim]ffuf:[/] {ffuf_bin}")

    auth_policy = AuthPolicy(args.auth_policy)
    if auth_policy is not AuthPolicy.OFF:
        console.print(
            f"[yellow]Auth probing:[/] policy={auth_policy.value} — authorized targets only."
        )

    inspector = DeepInspector(
        concurrency=max(1, args.concurrency),
        timeout=max(1.0, args.timeout),
        verify_tls=not args.insecure,
        follow_redirects=not args.no_follow_redirects,
        adaptive=not args.no_adaptive,
        auth_consent=AuthConsent(auth_policy, console),
        max_inspect=max(1, args.max_inspect),
    )
    engine = ReasoningEngine(
        ffuf_bin=ffuf_bin,
        max_depth=max(0, args.max_depth),
        ffuf_extra_args=args.ffuf_args,
        ffuf_timeout=args.ffuf_timeout,
        inspector=inspector,
        console=console,
        strict=args.strict,
    )

    try:
        passes, errors = await engine.run_recursive_campaign(
            start_url=target_url,
            primary_wordlist=wordlist,
            baseline_host=_baseline_host(target_url),
        )
    except CampaignError as exc:
        console.print(f"[bold red]Scan failed:[/]\n{exc}")
        return 1

    total_results = sum(len(p.results) for p in passes)
    total_findings = sum(1 for p in passes for f in p.findings if f.is_interesting)

    if errors:
        exit_code = 1
        console.print(f"\n[bold red]Errors ({len(errors)}):[/]")
        for err in errors[:10]:
            console.print(f"  • {err}")
        if len(errors) > 10:
            console.print(f"  … and {len(errors) - 10} more")

    color = "green" if exit_code == 0 else "yellow"
    console.print(
        f"\n[bold {color}]Done.[/] {len(passes)} ffuf pass(es), "
        f"{total_results} hits inspected, {total_findings} notable finding(s)."
    )
    return exit_code


def _baseline_host(url: str) -> str:
    if "FUZZ" in url:
        base = url.split("FUZZ", 1)[0].rstrip("/")
    else:
        base = url.rstrip("/")
    from urllib.parse import urlparse

    parsed = urlparse(base if "://" in base else f"http://{base}")
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}/"
    return base + "/"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return asyncio.run(_async_main(args))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except (PreflightError, TargetError, FfufNotFoundError, FfufExecutionError) as exc:
        Console().print(f"[bold red]Error:[/]\n{exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
