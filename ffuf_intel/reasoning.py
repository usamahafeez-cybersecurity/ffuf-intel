"""Intelligent next-hop reasoning and recursive fuzz orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console

from .adaptive import RequestProfile
from .ffuf_runner import FfufExecutionError, FfufNotFoundError, FfufResult, cleanup_json, run_ffuf
from .inspector import DeepInspector
from .patterns import InspectionFinding
from .validate import WordlistError, resolve_wordlist

WORDLIST_DIR = Path(__file__).resolve().parent / "wordlists"
TRIGGER_TO_WORDLIST = {
    "admin": "admin.txt",
    "api": "api.txt",
    "graphql": "graphql.txt",
    "config": "config.txt",
}


class CampaignError(Exception):
    """Fatal error during the primary scan pass."""


@dataclass(slots=True)
class ScanPass:
    depth: int
    url: str
    wordlist: Path
    results: list[FfufResult] = field(default_factory=list)
    findings: list[InspectionFinding] = field(default_factory=list)
    child_triggers: set[str] = field(default_factory=set)
    error: str | None = None


class ReasoningEngine:
    def __init__(
        self,
        *,
        ffuf_bin: str,
        max_depth: int = 1,
        ffuf_extra_args: list[str] | None = None,
        ffuf_timeout: int | None = None,
        inspector: DeepInspector,
        console: Console | None = None,
        strict: bool = False,
    ) -> None:
        self.ffuf_bin = ffuf_bin
        self.max_depth = max_depth
        self.ffuf_extra_args = ffuf_extra_args or []
        self.ffuf_timeout = ffuf_timeout
        self.inspector = inspector
        self.console = console or Console()
        self.strict = strict
        self._fuzzed_jobs: set[tuple[str, str]] = set()
        self._errors: list[str] = []

    def _wordlist_for_trigger(self, trigger: str) -> Path | None:
        filename = TRIGGER_TO_WORDLIST.get(trigger)
        if not filename:
            return None
        path = WORDLIST_DIR / filename
        if not path.is_file():
            self._errors.append(f"Bundled wordlist missing for trigger '{trigger}': {path}")
            return None
        try:
            return resolve_wordlist(path)
        except WordlistError as exc:
            self._errors.append(str(exc))
            return None

    def _profile_for_fuzz_url(self, fuzz_url: str) -> RequestProfile:
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
        self.console.print(
            f"[bold cyan]ffuf pass[/] depth={depth} url={url} wordlist={wordlist.name}"
        )

        try:
            wordlist = resolve_wordlist(wordlist)
        except WordlistError as exc:
            msg = str(exc)
            pass_record.error = msg
            self._errors.append(msg)
            self.console.print(f"[bold red]wordlist error:[/]\n{msg}")
            if depth == 0:
                raise CampaignError(msg) from exc
            return pass_record

        profile = self._profile_for_fuzz_url(url)
        if profile.method != "GET" or profile.content_type or profile.authorization:
            bits = [profile.method]
            if profile.content_type:
                bits.append(f"Content-Type={profile.content_type}")
            if profile.authorization:
                bits.append("Authorization=***")
            self.console.print(f"  [dim]profile:[/] {' '.join(bits)}")

        try:
            results, json_path = run_ffuf(
                ffuf_bin=self.ffuf_bin,
                url=url,
                wordlist=wordlist,
                extra_args=self.ffuf_extra_args,
                timeout=self.ffuf_timeout,
                profile=profile,
            )
        except (FfufExecutionError, FfufNotFoundError) as exc:
            msg = str(exc)
            pass_record.error = msg
            self._errors.append(f"depth={depth} {url}: {msg}")
            self.console.print(f"[bold red]ffuf error:[/]\n{msg}")
            if depth == 0:
                raise CampaignError(msg) from exc
            return pass_record
        except Exception as exc:
            msg = f"{type(exc).__name__}: {exc}"
            pass_record.error = msg
            self._errors.append(f"depth={depth} {url}: {msg}")
            self.console.print(f"[bold red]unexpected error:[/] {msg}")
            if depth == 0:
                raise CampaignError(msg) from exc
            return pass_record

        pass_record.results = results
        self.console.print(f"  [green]{len(results)}[/] hits → inspect (cap {self.inspector.max_inspect})")

        if depth == 0 and baseline_host:
            await self.inspector.fetch_baseline(baseline_host)

        pass_record.findings = await self.inspector.inspect_many(
            [(r.url, r.status) for r in results],
            console=self.console,
        )
        for finding in pass_record.findings:
            if finding.is_interesting:
                self._log_finding(finding)
            pass_record.child_triggers.update(finding.triggers)

        cleanup_json(json_path)
        return pass_record

    def _log_finding(self, f: InspectionFinding) -> None:
        status_note = f"HTTP {f.status}"
        if f.ffuf_status and f.ffuf_status != f.status:
            status_note += f" (ffuf {f.ffuf_status})"
        self.console.print(f"[yellow]insight[/] {f.url} ({status_note})")
        if f.triggers:
            self.console.print(f"  triggers: {', '.join(sorted(f.triggers))}")
        if f.auth_success:
            self.console.print(f"  [red]auth ok:[/] {f.auth_username} ({f.auth_type})")
        elif f.login_form_count:
            self.console.print(f"  login forms: {f.login_form_count}")

    async def run_recursive_campaign(
        self,
        *,
        start_url: str,
        primary_wordlist: Path,
        baseline_host: str,
    ) -> tuple[list[ScanPass], list[str]]:
        all_passes: list[ScanPass] = []
        queue: list[tuple[str, Path, int, set[str]]] = [
            (start_url, primary_wordlist, 0, set()),
        ]

        while queue:
            fuzz_url, wordlist, depth, inherited_triggers = queue.pop(0)
            pass_record = await self.run_pass(
                url=fuzz_url,
                wordlist=wordlist,
                depth=depth,
                baseline_host=baseline_host if depth == 0 else "",
            )
            all_passes.append(pass_record)

            if pass_record.error and self.strict:
                break
            if depth >= self.max_depth:
                continue

            triggers = inherited_triggers | pass_record.child_triggers
            if not triggers:
                continue

            for seed_url in self._select_secondary_seeds(pass_record):
                for trigger in sorted(triggers):
                    wl = self._wordlist_for_trigger(trigger)
                    if not wl:
                        continue
                    secondary = self._secondary_fuzz_url(seed_url, wl)
                    if secondary:
                        queue.append((secondary, wl, depth + 1, triggers))

        return all_passes, list(self._errors)
