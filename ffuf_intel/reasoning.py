"""Intelligent next-hop reasoning and recursive fuzz orchestration."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from rich.console import Console
from rich.prompt import Confirm

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


@dataclass(frozen=True, slots=True)
class AggressionProfile:
    name: str
    fuzz_modes: tuple[str, ...]
    min_recurse_score: int
    max_secondary_seeds: int
    max_triggers_per_pass: int
    all_wordlists: bool
    max_depth: int
    max_inspect: int
    zero_result_threshold: int


AGGRESSION_PRESETS: dict[str, AggressionProfile] = {
    "A1": AggressionProfile(
        name="A1",
        fuzz_modes=("path",),
        min_recurse_score=8,
        max_secondary_seeds=1,
        max_triggers_per_pass=1,
        all_wordlists=False,
        max_depth=0,
        max_inspect=25,
        zero_result_threshold=3,
    ),
    "A2": AggressionProfile(
        name="A2",
        fuzz_modes=("path", "query"),
        min_recurse_score=6,
        max_secondary_seeds=1,
        max_triggers_per_pass=1,
        all_wordlists=False,
        max_depth=1,
        max_inspect=50,
        zero_result_threshold=4,
    ),
    "A3": AggressionProfile(
        name="A3",
        fuzz_modes=("path", "query", "header"),
        min_recurse_score=4,
        max_secondary_seeds=2,
        max_triggers_per_pass=2,
        all_wordlists=False,
        max_depth=2,
        max_inspect=100,
        zero_result_threshold=5,
    ),
    "A4": AggressionProfile(
        name="A4",
        fuzz_modes=("path", "query", "header", "body"),
        min_recurse_score=2,
        max_secondary_seeds=4,
        max_triggers_per_pass=4,
        all_wordlists=True,
        max_depth=3,
        max_inspect=200,
        zero_result_threshold=6,
    ),
}
TRIGGER_PRIORITY = ("admin", "api", "graphql", "config")


class CampaignError(Exception):
    """Fatal error during the primary scan pass."""


@dataclass(slots=True)
class ScanPass:
    depth: int
    url: str
    wordlist: Path
    fuzz_mode: str = "path"
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
        fuzz_modes: tuple[str, ...] | None = None,
        aggression: AggressionProfile | None = None,
        all_wordlists: bool = False,
        zero_result_threshold: int | None = None,
        auto_continue: bool = False,
    ) -> None:
        self.ffuf_bin = ffuf_bin
        self.max_depth = max_depth
        self.ffuf_extra_args = ffuf_extra_args or []
        self.ffuf_timeout = ffuf_timeout
        self.inspector = inspector
        self.console = console or Console()
        self.strict = strict
        self.aggression = aggression or AGGRESSION_PRESETS["A2"]
        self.fuzz_modes = tuple(fuzz_modes or self.aggression.fuzz_modes)
        self.min_recurse_score = self.aggression.min_recurse_score
        self.max_secondary_seeds = self.aggression.max_secondary_seeds
        self.max_triggers_per_pass = self.aggression.max_triggers_per_pass
        self.all_wordlists = all_wordlists or self.aggression.all_wordlists
        self.zero_result_threshold = (
            zero_result_threshold
            if zero_result_threshold is not None
            else self.aggression.zero_result_threshold
        )
        self.auto_continue = auto_continue
        self._fuzzed_jobs: set[tuple[str, str]] = set()
        self._errors: list[str] = []

    @lru_cache(maxsize=None)
    def _all_wordlists(self) -> tuple[Path, ...]:
        return tuple(sorted(p for p in WORDLIST_DIR.glob("*.txt") if p.is_file()))

    def _wordlists_for_trigger(self, trigger: str) -> list[Path]:
        if self.all_wordlists:
            return list(self._all_wordlists())
        filename = TRIGGER_TO_WORDLIST.get(trigger)
        if not filename:
            return []
        path = WORDLIST_DIR / filename
        if not path.is_file():
            self._errors.append(f"Bundled wordlist missing for trigger '{trigger}': {path}")
            return []
        try:
            return [resolve_wordlist(path)]
        except WordlistError as exc:
            self._errors.append(str(exc))
            return []

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

    def _reserve_secondary_job(self, base: str, wordlist: Path, mode: str) -> bool:
        job_key = (self._normalize_seed_url(base).lower() + f"::{mode}", str(wordlist.resolve()))
        if job_key in self._fuzzed_jobs:
            return False
        self._fuzzed_jobs.add(job_key)
        return True

    def _secondary_fuzz_url(self, base: str, wordlist: Path) -> str:
        base = self._normalize_seed_url(base)
        if not self._reserve_secondary_job(base, wordlist, "path"):
            return ""
        return f"{base}/FUZZ"

    def _query_fuzz_url(self, base: str, wordlist: Path) -> str:
        base = self._normalize_seed_url(base)
        if not self._reserve_secondary_job(base, wordlist, "query"):
            return ""
        joiner = "&" if "?" in base else "?"
        return f"{base}{joiner}FUZZ=probe"

    def _header_fuzz_profile(self, profile: RequestProfile) -> RequestProfile:
        header_templates = list(profile.header_templates)
        for header in ("X-FUZZ: FUZZ", "X-Forwarded-For: FUZZ", "X-Original-URL: FUZZ"):
            if header not in header_templates:
                header_templates.append(header)
        return profile.clone(header_templates=header_templates)

    def _body_fuzz_profile(self, profile: RequestProfile) -> RequestProfile:
        body_profile = profile.clone()
        if body_profile.method in ("GET", "HEAD", "DELETE", "OPTIONS"):
            body_profile = body_profile.clone(method="POST")
        if not body_profile.content_type:
            body_profile = body_profile.clone(content_type="application/x-www-form-urlencoded")
        if body_profile.body and "FUZZ" in body_profile.body:
            return body_profile
        if body_profile.content_type and "json" in body_profile.content_type:
            return body_profile.clone(body='{"FUZZ":"probe"}')
        return body_profile.clone(body="FUZZ=probe")

    def _modes_for_trigger(self, trigger: str) -> tuple[str, ...]:
        preferred = {
            "admin": ("path", "query", "header", "body"),
            "api": ("path", "query", "header", "body"),
            "graphql": ("path", "query", "body", "header"),
            "config": ("path", "query", "body"),
        }.get(trigger, self.fuzz_modes)
        return tuple(mode for mode in preferred if mode in self.fuzz_modes)

    def _is_strong_finding(self, finding: InspectionFinding) -> bool:
        return bool(
            finding.score >= self.min_recurse_score
            or finding.internal_ips
            or finding.sensitive_keys
            or finding.api_indicators
            or finding.frameworks
            or finding.auth_success
            or finding.login_form_count
            or finding.accepted_methods
        )

    def _sorted_triggers(self, triggers: set[str]) -> list[str]:
        priority = {name: idx for idx, name in enumerate(TRIGGER_PRIORITY)}
        return sorted(triggers, key=lambda item: (priority.get(item, len(priority)), item))

    def _normalize_seed_url(self, url: str) -> str:
        """Strip query/fragment noise before building a nested fuzz target."""
        parsed = urlsplit(url)
        if parsed.scheme and parsed.netloc:
            path = parsed.path.rstrip("/")
            return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))
        return url.split("?", 1)[0].split("#", 1)[0].rstrip("/")

    def _select_secondary_seeds(self, pass_record: ScanPass) -> list[str]:
        """
        Prefer URLs whose inspection findings suggest a useful next-hop target.

        When we do not have any strong signals, fall back to the inspected URLs
        themselves so recursion can still continue from the current pass.
        """
        seeds: list[str] = []
        seen: set[str] = set()

        def add(url: str) -> None:
            candidate = self._normalize_seed_url(url)
            if not candidate or candidate in seen:
                return
            seen.add(candidate)
            seeds.append(candidate)

        ranked = sorted(
            zip(pass_record.results, pass_record.findings),
            key=lambda pair: (-pair[1].score, pair[0].url),
        )
        for result, finding in ranked:
            if not self._is_strong_finding(finding):
                continue
            add(result.url)
            if len(seeds) >= self.max_secondary_seeds:
                break

        return seeds

    async def run_pass(
        self,
        *,
        url: str,
        wordlist: Path,
        depth: int,
        baseline_host: str,
        fuzz_mode: str = "path",
    ) -> ScanPass:
        pass_record = ScanPass(depth=depth, url=url, wordlist=wordlist, fuzz_mode=fuzz_mode)
        self.console.print(
            f"[bold cyan]ffuf pass[/] depth={depth} mode={fuzz_mode} url={url} wordlist={wordlist.name}"
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
        fuzz_url = url
        if fuzz_mode == "header":
            profile = self._header_fuzz_profile(profile)
        elif fuzz_mode == "body":
            profile = self._body_fuzz_profile(profile)
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
                url=fuzz_url,
                wordlist=wordlist,
                extra_args=self.ffuf_extra_args,
                timeout=self.ffuf_timeout,
                profile=profile,
                fuzz_url=fuzz_mode in ("path", "query"),
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
        self.console.print(f"  [green]{len(results)}[/] hits -> inspect (cap {self.inspector.max_inspect})")

        if depth == 0 and baseline_host:
            await self.inspector.fetch_baseline(baseline_host)

        try:
            pass_record.findings = await self.inspector.inspect_many(
                [(r.url, r.status) for r in results],
                console=self.console,
            )
            for finding in pass_record.findings:
                if finding.is_interesting:
                    self._log_finding(finding)
                pass_record.child_triggers.update(finding.triggers)
        finally:
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
        queue: list[tuple[str, Path, int, set[str], str]] = [
            (start_url, primary_wordlist, 0, set(), "path"),
        ]
        zero_result_streak = 0

        while queue:
            fuzz_url, wordlist, depth, inherited_triggers, fuzz_mode = queue.pop(0)
            pass_record = await self.run_pass(
                url=fuzz_url,
                wordlist=wordlist,
                depth=depth,
                baseline_host=baseline_host if depth == 0 else "",
                fuzz_mode=fuzz_mode,
            )
            all_passes.append(pass_record)

            if pass_record.error and self.strict:
                break
            if not pass_record.results and not pass_record.error:
                zero_result_streak += 1
            elif pass_record.results:
                zero_result_streak = 0

            if (
                self.zero_result_threshold > 0
                and zero_result_streak >= self.zero_result_threshold
                and queue
            ):
                msg = (
                    f"No results after {zero_result_streak} consecutive pass(es). "
                    f"{len(queue)} queued follow-up scan(s) remain."
                )
                if self.auto_continue:
                    self.console.print(f"[yellow]{msg} Continuing automatically.[/]")
                    zero_result_streak = 0
                else:
                    self.console.print(f"[yellow]{msg}[/]")
                    try:
                        should_continue = Confirm.ask("Continue scanning?", default=True)
                    except (EOFError, OSError):
                        self.console.print(
                            "[yellow]Interactive prompt unavailable; continuing automatically.[/]"
                        )
                        should_continue = True
                    if not should_continue:
                        self._errors.append("Stopped after repeated zero-result passes by operator choice.")
                        break
                    zero_result_streak = 0

            if depth >= self.max_depth:
                continue

            triggers = inherited_triggers | {
                trigger for finding in pass_record.findings if self._is_strong_finding(finding) for trigger in finding.triggers
            }
            if not triggers:
                continue

            selected_triggers = self._sorted_triggers(triggers)[: self.max_triggers_per_pass]

            for seed_url in self._select_secondary_seeds(pass_record):
                for trigger in selected_triggers:
                    for wl in self._wordlists_for_trigger(trigger):
                        for mode in self._modes_for_trigger(trigger):
                            if mode == "path":
                                secondary = self._secondary_fuzz_url(seed_url, wl)
                            elif mode == "query":
                                secondary = self._query_fuzz_url(seed_url, wl)
                            else:
                                secondary = self._normalize_seed_url(seed_url)
                                if not self._reserve_secondary_job(seed_url, wl, mode):
                                    secondary = ""
                            if secondary:
                                queue.append((secondary, wl, depth + 1, triggers, mode))

        return all_passes, list(self._errors)
