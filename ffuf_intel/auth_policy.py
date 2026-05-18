"""User consent and limits for credential probing."""

from __future__ import annotations

from enum import Enum

from rich.console import Console
from rich.prompt import Confirm


class AuthPolicy(str, Enum):
    """Credential testing policy."""

    OFF = "off"  # detect login/basic auth only
    ASK = "ask"  # prompt before any credential attempts
    DEFAULTS = "defaults"  # built-in default user:pass pairs only
    COMMON = "common"  # defaults + small common-password list (capped)
    UNRESTRICTED = "unrestricted"  # same lists, higher cap; no prompts


# Max attempts per URL per category
ATTEMPT_CAPS: dict[AuthPolicy, tuple[int, int]] = {
    # (basic_auth_pairs, form_password_attempts)
    AuthPolicy.OFF: (0, 0),
    AuthPolicy.ASK: (8, 12),
    AuthPolicy.DEFAULTS: (8, 8),
    AuthPolicy.COMMON: (12, 25),
    AuthPolicy.UNRESTRICTED: (20, 40),
}


class AuthConsent:
    """Tracks whether the operator approved credential testing."""

    def __init__(self, policy: AuthPolicy, console: Console | None = None) -> None:
        self.policy = policy
        self.console = console or Console()
        self._approved = policy in (AuthPolicy.DEFAULTS, AuthPolicy.COMMON, AuthPolicy.UNRESTRICTED)
        self._asked = False

    @property
    def enabled(self) -> bool:
        return self.policy is not AuthPolicy.OFF

    def basic_cap(self) -> int:
        return ATTEMPT_CAPS[self.policy][0]

    def form_cap(self) -> int:
        return ATTEMPT_CAPS[self.policy][1]

    def ensure_approved(self, context: str) -> bool:
        if self.policy is AuthPolicy.OFF:
            return False
        if self.policy is AuthPolicy.ASK:
            if self._approved:
                return True
            if self._asked:
                return False
            self._asked = True
            self.console.print(
                "\n[bold yellow]Credential testing requested[/] for: "
                f"{context}\n"
                "[dim]Only use on systems you own or have written permission to test.[/]"
            )
            self._approved = Confirm.ask(
                "Try default/common credentials (Basic Auth + login forms)?",
                default=False,
            )
            return self._approved
        return True
