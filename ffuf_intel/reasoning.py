"""Intelligent next-hop reasoning and recursive fuzz orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console

from .adaptive import RequestProfile
from .ffuf_runner import FfufResult, cleanup_json, run_ffuf
from .inspector import DeepInspector
from .patterns import InspectionFinding

WORDLIST_DIR = Path(__file__).resolve().parent / "wordlists"
TRIGGER_TO_WORDLIST = {
    "admin": "admin.txt",
    "api": "api.txt",
    "graphql": "graphql.txt",
    "config": "config.txt",
}


@dataclass(slots=True)
class ScanPass:
    depth: int
    url: str
    wordlist: Path
    results: list[FfufResult] = field(default_factory=list)
    findings: list[InspectionFinding] = field(default_factory=list)
    child_triggers: set[str] = field(default_factory=set)


class ReasoningEngine:
    def __init__(
        self,
        *,
        ffuf_bin: str,
        max_depth: int = 2,
        ffuf_extra_args: list[str] | None = None,
        ffuf_timeout: int | None = None,
        inspector: DeepInspector,
        console: Console | None = None,
    ) -> None:
        self.ffuf_bin = ffuf_bin
        self.max_depth = max_depth
        self.ffuf_extra_args = ffuf_extra_args or []
        self.ffuf_timeout = ffuf_timeout
        self.inspector = inspector
        self.console = console or Console()
        self._fuzzed_jobs: set[tuple[str, str]] = set()

    def _wordlist_for_trigger(self, trigger: str) -> Path | None:
        filename = TRIGGER_TO_WORDLIST.get(trigger)
        if not filename:
            return None
        path = WORDLIST_DIR / filename
        return path if path.is_file() else None

    def _profile_for_fuzz_url(self, fuzz_url: str) -> RequestProfile:
        """Use discovered profile for parent URL when fuzzing children."""
        if "FUZZ" not in fuzz_url:
            site = self.inspector._profile_for_site(fuzz_url)
            return site or RequestProfile()
        parent = fuzz_url.split("FUZZ", 1)[0].rstrip("/")
        site = self.inspector._profile_for_site(parent)
        if parent in self.inspector.profiles:
            prof = self.inspector.profiles[parent]
            if site:
                prof.authorization = prof.authorization or site.authorization
                prof.cookie = prof.cookie or site.cookie
            return prof
        if site:
            return site
        for key, profile in self.inspector.profiles.items():
            if parent.startswith(key.rstrip("/")) or key.rstrip("/").startswith(parent):
                return profile
        return RequestProfile()

    def _secondary_fuzz_url(self, base: str, wordlist: Path) -> str:
        base = base.rstrip("/")
        job_key = (base.lower(), str(wordlist.resolve()))
        if job_key in self._fuzzed_jobs:
            return ""
        self._fuzzed_jobs.add(job_key)
        return f"{base}/FUZZ"

    async def run_pass(self, *, url: str, wordlist: Path, depth: int, baseline_host: str) -> ScanPass:
        pass_record = ScanPass(depth=depth, url=url, wordlist=wordlist)
        self.console.print(f"[bold cyan]ffuf pass[/] depth={depth} url={url} wordlist={wordlist.name}")
        profile = self._profile_for_fuzz_url(url)
        extras = []
        if profile.method != "GET":
            extras.append(profile.method)
        if profile.content_type:
            extras.append(f"Content-Type={profile.content_type}")
        if profile.authorization:
            extras.append("Authorization=***")
        if profile.cookie:
            extras.append("Cookie=***")
        if extras:
            self.console.print(f"  [dim]adaptive ffuf:[/] {' '.join(extras)}")
        try:
            results, json_path = run_ffuf(
                ffuf_bin=self.ffuf_bin,
                url=url,
                wordlist=wordlist,
                extra_args=self.ffuf_extra_args,
                timeout=self.ffuf_timeout,
                profile=profile,
            )
        except Exception as exc:
            self.console.print(f"[red]ffuf error:[/] {exc}")
            return pass_record
        pass_record.results = results
        self.console.print(f"  [green]{len(results)}[/] endpoints to inspect")
        if depth == 0 and baseline_host:
            await self.inspector.fetch_baseline(baseline_host)
        pass_record.findings = await self.inspector.inspect_many([(r.url, r.status) for r in results])
        for finding in pass_record.findings:
            if finding.is_interesting:
                self._log_finding(finding)
            pass_record.child_triggers.update(finding.triggers)
        cleanup_json(json_path)
        return pass_record

    def _log_finding(self, f: InspectionFinding) -> None:
        status_note = f"HTTP {f.status}"
        if f.ffuf_status and f.ffuf_status != f.status:
            status_note += f" (ffuf reported {f.ffuf_status})"
        self.console.print(f"[yellow]insight[/] {f.url} ({status_note})")
        if f.used_method and f.used_method != "GET":
            self.console.print(f"  method: {f.used_method}")
        if f.accepted_methods:
            self.console.print(f"  accepts: {', '.join(f.accepted_methods)}")
        if f.content_type:
            self.console.print(f"  content-type: {f.content_type}")
        if f.adaptive_notes:
            self.console.print(f"  adaptive: {'; '.join(f.adaptive_notes[:4])}")
        if f.login_form_count:
            self.console.print(f"  login forms: {f.login_form_count}")
        if f.basic_realm is not None:
            self.console.print(f"  basic realm: {f.basic_realm}")
        if f.auth_success:
            self.console.print(
                f"  [bold red]auth success:[/] {f.auth_username} "
                f"({f.auth_type}) — rotate credentials if lab"
            )
        elif f.auth_notes:
            self.console.print(f"  auth: {'; '.join(f.auth_notes[:3])}")
        if f.triggers:
            self.console.print(f"  triggers: {', '.join(sorted(f.triggers))}")

    async def run_recursive_campaign(
        self, *, start_url: str, primary_wordlist: Path, baseline_host: str
    ) -> list[ScanPass]:
        all_passes: list[ScanPass] = []
        queue: list[tuple[str, Path, int, set[str]]] = [(start_url, primary_wordlist, 0, set())]
        while queue:
            fuzz_url, wordlist, depth, inherited_triggers = queue.pop(0)
            pass_record = await self.run_pass(
                url=fuzz_url, wordlist=wordlist, depth=depth,
                baseline_host=baseline_host if depth == 0 else "",
            )
            all_passes.append(pass_record)
            if depth >= self.max_depth:
                continue
            triggers = inherited_triggers | pass_record.child_triggers
            for seed_url in self._select_secondary_seeds(pass_record):
                for trigger in sorted(triggers):
                    wl = self._wordlist_for_trigger(trigger)
                    if not wl:
                        continue
                    secondary = self._secondary_fuzz_url(seed_url, wl)
                    if secondary:
                        queue.append((secondary, wl, depth + 1, triggers))
        return all_passes

    def _select_secondary_seeds(self, pass_record: ScanPass) -> list[str]:
        seeds: list[str] = []
        for result in pass_record.results:
            if result.status in (200, 302, 405) or (
                result.status in (403, 400, 415)
                and any(f.url == result.url for f in pass_record.findings if f.triggers or f.accepted_methods)
            ):
                seeds.append(result.url.rstrip("/"))
        seen: set[str] = set()
        unique: list[str] = []
        for s in seeds:
            if s.lower() not in seen:
                seen.add(s.lower())
                unique.append(s)
        return unique[:10]
