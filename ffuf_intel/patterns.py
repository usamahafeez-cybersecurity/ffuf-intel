"""Detection patterns for deep content inspection."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

INTERNAL_IP_RE = re.compile(
    r"\b(?:"
    r"10(?:\.\d{1,3}){3}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|"
    r"192\.168(?:\.\d{1,3}){2}|"
    r"127(?:\.\d{1,3}){3}|"
    r"169\.254(?:\.\d{1,3}){2}"
    r")\b"
)

SENSITIVE_KEY_RE = re.compile(
    r"(?i)\b("
    r"password|passwd|secret|api[_-]?key|access[_-]?token|"
    r"auth[_-]?token|private[_-]?key|aws[_-]?secret|"
    r"client[_-]?secret|bearer|credential|jwt|session[_-]?id"
    r")\s*[:=]"
)

API_PATH_RE = re.compile(
    r"(?i)(?:/api(?:/v\d+)?/|/rest/|/graphql|swagger|openapi|\.json\b|/v\d+/[a-z])"
)

FRAMEWORK_SIGNATURES: dict[str, re.Pattern[str]] = {
    "django": re.compile(r"(?i)csrfmiddlewaretoken|django"),
    "laravel": re.compile(r"(?i)laravel_session|Illuminate\\"),
    "spring": re.compile(r"(?i)Whitelabel Error Page|springframework"),
    "express": re.compile(r"(?i)X-Powered-By:\s*Express"),
    "rails": re.compile(r"(?i)authenticity_token|rails"),
    "aspnet": re.compile(r"(?i)__VIEWSTATE|asp\.net"),
    "wordpress": re.compile(r"(?i)wp-content|wp-includes"),
    "graphql": re.compile(r"(?i)graphiql|__schema|introspection"),
}

TRIGGER_MAP: dict[str, tuple[str, ...]] = {
    "admin": ("admin", "dashboard", "manage", "panel", "wp-admin", "backend"),
    "api": ("api", "rest", "/v1", "/v2", "v1/", "v2/", "webhook"),
    "graphql": ("graphql", "graphiql", "playground", "__schema"),
    "config": ("config", ".env", "settings", "secret", "credential", "backup"),
}


@dataclass(slots=True)
class InspectionFinding:
    url: str
    status: int
    ffuf_status: int | None = None
    internal_ips: list[str] = field(default_factory=list)
    sensitive_keys: list[str] = field(default_factory=list)
    api_indicators: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    html_signals: list[str] = field(default_factory=list)
    triggers: set[str] = field(default_factory=set)
    # Adaptive HTTP discovery
    accepted_methods: list[str] = field(default_factory=list)
    used_method: str = "GET"
    content_type: str | None = None
    request_body: str | None = None
    adaptive_notes: list[str] = field(default_factory=list)
    # Authentication discovery
    auth_type: str = "none"  # none | basic | form
    login_form_count: int = 0
    basic_realm: str | None = None
    auth_success: bool = False
    auth_username: str | None = None
    auth_notes: list[str] = field(default_factory=list)

    @property
    def is_interesting(self) -> bool:
        return bool(
            self.internal_ips
            or self.sensitive_keys
            or self.api_indicators
            or self.frameworks
            or self.triggers
            or self.accepted_methods
            or self.adaptive_notes
            or self.login_form_count
            or self.auth_success
            or self.auth_notes
        )
