"""Command-line interface for ffuf-intel."""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import asdict
from pathlib import Path

from rich.console import Console

from .auth_policy import AuthConsent, AuthPolicy
from .crawler import crawl_site
from .ffuf_runner import FfufExecutionError, FfufNotFoundError, locate_ffuf
from .inspector import DeepInspector
from .js_miner import mine_js
from .reporting import build_report_payload, create_session_dir, write_report_files
from .reasoning import AGGRESSION_PRESETS, CampaignError, ReasoningEngine
from .validate import PreflightError, TargetError, validate_target_url, verify_ffuf_binary, wordlist_info, resolve_wordlist
from .version_detect import detect_versions


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
    p.add_argument("--aggression", choices=list(AGGRESSION_PRESETS), default="A2", help="Aggression preset from A1 to A4 (default: A2).")
    p.add_argument("--max-depth", type=int, default=None, help="Override recursive reasoning depth.")
    p.add_argument("--concurrency", type=int, default=20, help="Parallel inspection requests.")
    p.add_argument("--timeout", type=float, default=15.0, help="Inspection HTTP timeout.")
    p.add_argument("--ffuf-timeout", type=int, default=None, help="ffuf subprocess timeout in seconds.")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verify for inspection.")
    p.add_argument("--no-follow-redirects", action="store_true", help="Do not follow redirects.")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output.")
    p.add_argument("--no-adaptive", action="store_true", help="Disable method/Content-Type probing.")
    p.add_argument("--max-inspect", type=int, default=None, help="Override max endpoints inspected per pass.")
    p.add_argument(
        "--fuzz-modes",
        default=None,
        help="Comma-separated secondary fuzz modes: path, query, header, body.",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=Path("ffuf-intel-output"),
        help="Directory used to store JSON/Markdown reports.",
    )
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
    p.add_argument(
        "--all-wordlists",
        action="store_true",
        help="Use every bundled wordlist for secondary passes instead of trigger-specific lists.",
    )
    p.add_argument(
        "--continue-without-ask",
        action="store_true",
        help="Continue automatically when the zero-result threshold is reached.",
    )
    p.add_argument(
        "--no-result-threshold",
        type=int,
        default=None,
        help="Prompt after this many consecutive zero-result passes (default comes from aggression preset).",
    )
    p.add_argument(
        "--intel",
        action="store_true",
        help="Run same-origin crawl, version detection, and JavaScript endpoint mining.",
    )
    p.add_argument("--crawl-depth", type=int, default=2, help="Max depth for --intel crawler.")
    p.add_argument("--crawl-pages", type=int, default=100, help="Max pages for --intel crawler.")
    p.add_argument(
        "--probe-js-endpoints",
        action="store_true",
        help="Actively probe same-origin endpoints discovered in JavaScript (requires --intel).",
    )
    p.add_argument(
        "--max-js-probes",
        type=int,
        default=50,
        help="Maximum JavaScript endpoints to probe when --probe-js-endpoints is set.",
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

    aggression = AGGRESSION_PRESETS[args.aggression]
    max_depth = args.max_depth if args.max_depth is not None else aggression.max_depth
    max_inspect = args.max_inspect if args.max_inspect is not None else aggression.max_inspect
    zero_result_threshold = (
        args.no_result_threshold if args.no_result_threshold is not None else aggression.zero_result_threshold
    )
    all_wordlists = args.all_wordlists or aggression.all_wordlists

    try:
        fuzz_modes = _parse_fuzz_modes(args.fuzz_modes) if args.fuzz_modes else aggression.fuzz_modes
    except ValueError as exc:
        console.print(f"[bold red]Configuration error:[/]\n{exc}")
        return 2

    auth_policy = AuthPolicy(args.auth_policy)
    if auth_policy is not AuthPolicy.OFF:
        console.print(
            f"[yellow]Auth probing:[/] policy={auth_policy.value} - authorized targets only."
        )
    console.print(
        f"[dim]Aggression:[/] {aggression.name} | modes={','.join(fuzz_modes)} | "
        f"depth={max_depth} | inspect={max_inspect} | wordlists={'all' if all_wordlists else 'trigger-based'}"
    )

    intel_payload: dict | None = None
    if args.intel:
        intel_payload = _run_intel_pass(
            console=console,
            target_url=target_url,
            timeout=max(1.0, args.timeout),
            verify_tls=not args.insecure,
            follow_redirects=not args.no_follow_redirects,
            crawl_depth=max(0, args.crawl_depth),
            crawl_pages=max(1, args.crawl_pages),
            probe_js_endpoints=args.probe_js_endpoints,
            max_js_probes=max(0, args.max_js_probes),
        )

    inspector = DeepInspector(
        concurrency=max(1, args.concurrency),
        timeout=max(1.0, args.timeout),
        verify_tls=not args.insecure,
        follow_redirects=not args.no_follow_redirects,
        adaptive=not args.no_adaptive,
        auth_consent=AuthConsent(auth_policy, console),
        max_inspect=max(1, max_inspect),
    )
    engine = ReasoningEngine(
        ffuf_bin=ffuf_bin,
        max_depth=max(0, max_depth),
        ffuf_extra_args=args.ffuf_args,
        ffuf_timeout=args.ffuf_timeout,
        inspector=inspector,
        console=console,
        strict=args.strict,
        fuzz_modes=fuzz_modes,
        aggression=aggression,
        all_wordlists=all_wordlists,
        zero_result_threshold=max(0, zero_result_threshold),
        auto_continue=args.continue_without_ask,
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

    try:
        report_dir = create_session_dir(args.output_dir, target_url)
        report_payload = build_report_payload(
            target_url=target_url,
            wordlist=str(wordlist),
            passes=passes,
            errors=errors,
            metadata={
                "ffuf_bin": ffuf_bin,
                "aggression": aggression.name,
                "max_depth": max_depth,
                "concurrency": args.concurrency,
                "timeout": args.timeout,
                "ffuf_timeout": args.ffuf_timeout,
                "adaptive": not args.no_adaptive,
                "auth_policy": auth_policy.value,
                "strict": args.strict,
                "fuzz_modes": ",".join(fuzz_modes),
                "max_inspect": max_inspect,
                "all_wordlists": all_wordlists,
                "zero_result_threshold": zero_result_threshold,
                "continue_without_ask": args.continue_without_ask,
                "intel": args.intel,
                "probe_js_endpoints": args.probe_js_endpoints if args.intel else False,
            },
            intel=intel_payload,
        )
        report_paths = write_report_files(report_dir, report_payload)
        console.print(f"[dim]Reports:[/] {report_paths['json']} | {report_paths['markdown']}")
    except Exception as exc:
        console.print(f"[yellow]Report write warning:[/] {exc}")

    if errors:
        exit_code = 1
        console.print(f"\n[bold red]Errors ({len(errors)}):[/]")
        for err in errors[:10]:
            console.print(f"  - {err}")
        if len(errors) > 10:
            console.print(f"  ... and {len(errors) - 10} more")

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


def _run_intel_pass(
    *,
    console: Console,
    target_url: str,
    timeout: float,
    verify_tls: bool,
    follow_redirects: bool,
    crawl_depth: int,
    crawl_pages: int,
    probe_js_endpoints: bool,
    max_js_probes: int,
) -> dict:
    base_url = _baseline_host(target_url)
    console.print(
        f"[bold cyan]intel pass[/] crawl_depth={crawl_depth} pages={crawl_pages} base={base_url}"
    )
    crawl = crawl_site(
        base_url,
        max_depth=crawl_depth,
        max_pages=crawl_pages,
        timeout=timeout,
        verify_tls=verify_tls,
        follow_redirects=follow_redirects,
    )
    console.print(
        f"  [green]{len(crawl.urls)}[/] URLs, "
        f"[green]{len(crawl.js_files)}[/] JS file(s), "
        f"[green]{len(crawl.forms)}[/] form(s)"
    )
    versions = detect_versions(
        base_url,
        js_urls=crawl.js_files,
        inline_scripts=crawl.inline_scripts,
        timeout=timeout,
        verify_tls=verify_tls,
        follow_redirects=follow_redirects,
    )
    if versions:
        console.print(f"  [yellow]versions:[/] {', '.join(v.technology for v in versions[:10])}")
    js_intel = mine_js(
        base_url,
        js_urls=crawl.js_files,
        inline_scripts=crawl.inline_scripts,
        timeout=timeout,
        verify_tls=verify_tls,
        follow_redirects=follow_redirects,
        probe_endpoints=probe_js_endpoints,
        max_probe=max_js_probes,
    )
    console.print(
        f"  [yellow]JS endpoints:[/] {len(js_intel.endpoints)} "
        f"parameters={len(js_intel.parameters)} secret-patterns={len(js_intel.secrets)}"
    )
    return {
        "crawl": asdict(crawl),
        "versions": [asdict(item) for item in versions],
        "javascript": asdict(js_intel),
    }


def _parse_fuzz_modes(raw: str) -> tuple[str, ...]:
    allowed = {"path", "query", "header", "body"}
    modes: list[str] = []
    for part in (p.strip().lower() for p in raw.split(",")):
        if not part:
            continue
        if part not in allowed:
            raise ValueError(f"Unsupported fuzz mode: {part}")
        if part not in modes:
            modes.append(part)
    return tuple(modes) or ("path",)


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
