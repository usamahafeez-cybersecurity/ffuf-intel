"""Command-line interface for ffuf-intel."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from rich.console import Console

from .auth_policy import AuthConsent, AuthPolicy
from .ffuf_runner import FfufNotFoundError, locate_ffuf
from .inspector import DeepInspector
from .reasoning import ReasoningEngine


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ffuf-intel",
        description=(
            "Intelligent ffuf wrapper: auto-calibration, deep content inspection, "
            "and behavioral next-hop fuzzing."
        ),
    )
    p.add_argument("-u", "--url", required=True, help="Target URL (FUZZ appended if missing).")
    p.add_argument("-w", "--wordlist", required=True, type=Path, help="Primary ffuf wordlist.")
    p.add_argument("--ffuf-path", default=None, help="Explicit path to ffuf binary.")
    p.add_argument("--ffuf-args", nargs=argparse.REMAINDER, default=[], help="Extra ffuf args after --.")
    p.add_argument("--max-depth", type=int, default=2, help="Recursive reasoning depth.")
    p.add_argument("--concurrency", type=int, default=20, help="Parallel inspection requests.")
    p.add_argument("--timeout", type=float, default=15.0, help="Inspection HTTP timeout.")
    p.add_argument("--ffuf-timeout", type=int, default=None, help="ffuf subprocess timeout.")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verify for inspection.")
    p.add_argument("--no-follow-redirects", action="store_true", help="Do not follow redirects.")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output.")
    p.add_argument(
        "--no-adaptive",
        action="store_true",
        help="Disable method/content-type probing (405/415/JSON/form negotiation).",
    )
    p.add_argument(
        "--auth-policy",
        choices=[p.value for p in AuthPolicy],
        default=AuthPolicy.ASK.value,
        help=(
            "Credential testing policy: off=detect only; ask=prompt once; "
            "defaults=builtin pairs; common=defaults+small wordlist; "
            "unrestricted=higher attempt cap, no prompt."
        ),
    )
    return p


def _validate_wordlist(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Wordlist not found: {path}")


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


async def _async_main(args: argparse.Namespace) -> int:
    console = Console()
    _validate_wordlist(args.wordlist)
    try:
        ffuf_bin = locate_ffuf(args.ffuf_path)
    except FfufNotFoundError as exc:
        console.print(f"[bold red]Error:[/] {exc}")
        return 2
    if args.verbose:
        console.print(f"Using ffuf: {ffuf_bin}")
    auth_policy = AuthPolicy(args.auth_policy)
    if auth_policy is not AuthPolicy.OFF:
        console.print(
            "[yellow]Auth probing enabled[/] "
            f"(policy={auth_policy.value}). Authorized targets only."
        )
    inspector = DeepInspector(
        concurrency=args.concurrency,
        timeout=args.timeout,
        verify_tls=not args.insecure,
        follow_redirects=not args.no_follow_redirects,
        adaptive=not args.no_adaptive,
        auth_consent=AuthConsent(auth_policy, console),
    )
    engine = ReasoningEngine(
        ffuf_bin=ffuf_bin,
        max_depth=args.max_depth,
        ffuf_extra_args=args.ffuf_args,
        ffuf_timeout=args.ffuf_timeout,
        inspector=inspector,
        console=console,
    )
    passes = await engine.run_recursive_campaign(
        start_url=args.url,
        primary_wordlist=args.wordlist,
        baseline_host=_baseline_host(args.url),
    )
    total_results = sum(len(p.results) for p in passes)
    total_findings = sum(1 for p in passes for f in p.findings if f.is_interesting)
    console.print(
        f"\n[bold green]Done.[/] {len(passes)} ffuf pass(es), "
        f"{total_results} inspected endpoints, {total_findings} notable finding(s)."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return asyncio.run(_async_main(args))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except FileNotFoundError as exc:
        Console().print(f"[bold red]Error:[/] {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
