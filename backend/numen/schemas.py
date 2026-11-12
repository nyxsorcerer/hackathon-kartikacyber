import re
from typing import Annotated, Literal
from urllib.parse import urlparse
from pathlib import PurePosixPath
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


OPERATIONS = (
    "commit_triage",
    "commit_analysis",
    "version_recipe",
    "audit_context",
    "cve_analysis",
    "finding_artifacts",
)
CATEGORIES = (
    "Likely vulnerability fix",
    "Potentially introduced vulnerability",
    "Security hardening",
    "Unrelated change",
    "Insufficient context",
)
CHANGE_KINDS = ("vulnerability_fix", "security_hardening", "vulnerability_introduction", "unrelated", "insufficient_context")
# Monitoring intervals in seconds: at least 5 minutes, at most 10 years.
MIN_INTERVAL, MAX_INTERVAL = 300, 3650 * 86400


def http_url(value):
    if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("URL must not contain control characters")
    parsed = urlparse(value)
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("Invalid HTTP port") from exc
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ValueError("Expected an HTTP(S) URL without credentials or fragment")
    return value.rstrip("/")


def safe_path(value):
    p = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or p.is_absolute()
        or any(x in ("..", ".", "") for x in value.split("/"))
        or len(value) > 240
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise ValueError("Expected a safe workspace-relative path")
    return str(p)


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Profile(Strict):
    agent: Literal["pi", "claude", "codex"]
    connection_id: str
    model_id: str
    reasoning_effort: str | None = None


class ModelCapability(BaseModel):
    id: str = Field(min_length=1, max_length=200)
    name: str = Field(min_length=1, max_length=400)
    reasoning_efforts: list[str] = Field(default_factory=list)
    default_effort: str | None = None

    @model_validator(mode="after")
    def effort(self):
        if self.default_effort is not None and self.default_effort not in self.reasoning_efforts:
            raise ValueError("Default effort must be supported by this model")
        return self


class ApplicationConfig(Strict):
    monitor_interval_inherited: bool = False
    triage_mode: Literal["disabled", "jev", "pi", "claude", "codex"] = "disabled"
    profiles: dict[str, Profile] = Field(default_factory=dict)
    cve_selectors: list[dict] = Field(default_factory=list)
    cve_min_score: float | None = Field(default=None, ge=0, le=10)
    cve_versions: list[Literal["3.0", "3.1", "4.0"]] = Field(default_factory=list)
    cve_auto_analyze: bool = False
    # Refresh the audit context after each source check that moves the source head.
    audit_auto_refresh: bool = False
    active_recipe_id: str | None = None
    version_scheme: Literal["semver", "php", "unknown"] = "unknown"
    version_monitor_enabled: bool = True
    asset_origins: list[str] = Field(default_factory=list)
    jev_connection_id: str | None = None
    jev_model_id: str | None = None

    @field_validator("profiles")
    @classmethod
    def operations(cls, value):
        if set(value) - set(OPERATIONS):
            raise ValueError("Unknown agent operation")
        return value

    @field_validator("asset_origins")
    @classmethod
    def origins(cls, value):
        return [http_url(v) for v in value]

    @field_validator("cve_selectors")
    @classmethod
    def selectors(cls, value):
        for selector in value:
            if (
                selector.get("type") not in ("cpe", "keyword")
                or not isinstance(selector.get("value"), str)
                or not selector["value"].strip()
            ):
                raise ValueError("CVE selectors require type=cpe|keyword and a nonempty value")
            if selector["type"] == "cpe" and not selector["value"].startswith("cpe:2.3:"):
                raise ValueError("CPE selector must be a CPE 2.3 identity")
        return value


class ApplicationInput(Strict):
    asset_name: str = Field(min_length=1, max_length=200)
    asset_url: str
    product_kind: str = Field(min_length=1, max_length=100)
    product_name: str = Field(min_length=1, max_length=200)
    monitor_interval_seconds: int | None = Field(default=None, ge=MIN_INTERVAL, le=MAX_INTERVAL)
    monitor_enabled: bool = True
    archived: bool = False
    config: ApplicationConfig = Field(default_factory=ApplicationConfig)

    @field_validator("asset_url")
    @classmethod
    def url(cls, value):
        return http_url(value)


class RepositoryInput(Strict):
    role: Literal["own", "upstream"] = "upstream"
    source_kind: Literal["github", "wordpress"]
    source_url: str | None = None
    plugin_slug: str | None = None
    source_ref: str | None = None
    source_path: str | None = None
    locked_version: str | None = Field(default=None, max_length=100)

    @field_validator("source_path")
    @classmethod
    def path(cls, value):
        return safe_path(value) if value else None

    @model_validator(mode="after")
    def source(self):
        if self.source_kind == "github":
            if not self.source_url or not re.fullmatch(
                r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?", self.source_url
            ):
                raise ValueError("GitHub source requires https://github.com/owner/repository")
            # One row per repository: GitHub names are case-insensitive.
            self.source_url = self.source_url.rstrip("/").removesuffix(".git").lower()
        elif self.role == "own":
            raise ValueError("An Own repository must be a GitHub repository")
        else:
            if not self.plugin_slug or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", self.plugin_slug):
                raise ValueError("WordPress source requires a valid plugin slug")
            self.source_url = f"https://plugins.svn.wordpress.org/{self.plugin_slug}"
            self.source_ref = self.source_ref or "trunk"
            safe_path(self.source_ref)
        return self


class RepositoryPatch(Strict):
    # An explicit null clears the Locked version; an omitted field keeps it.
    enabled: bool | None = None
    locked_version: str | None = Field(default=None, max_length=100)


class BackfillInput(Strict):
    count: int = Field(ge=1, le=100)


class FindingInput(Strict):
    application_id: str
    kind: Literal["cve", "0day"]
    cve_id: str | None = None
    title: str = Field(min_length=1, max_length=300)
    status: Literal["open", "fixed"] = "open"
    affected_versions: list = Field(default_factory=list)
    fixed_versions: list = Field(default_factory=list)
    target_applicability: Literal["affected", "not affected", "unknown"] = "unknown"
    source_commit_id: str | None = None
    source_analysis_id: str | None = None
    evidence: list = Field(default_factory=list)

    @model_validator(mode="after")
    def cve(self):
        if self.kind == "cve" and not self.cve_id:
            raise ValueError("A CVE finding requires a CVE ID")
        if self.cve_id and not re.fullmatch(r"CVE-\d{4}-\d{4,}", self.cve_id):
            raise ValueError("Invalid CVE ID")
        return self


class AccountInput(Strict):
    label: str = Field(min_length=1, max_length=200)
    provider: Literal["deepseek", "commandcode", "openai", "claude", "jev", "github", "nvd"]
    auth_type: Literal["api_key", "native_oauth"]
    api_key: str | None = Field(default=None, max_length=20000)

    @model_validator(mode="after")
    def native(self):
        if self.auth_type == "native_oauth" and self.provider not in (
            "openai",
            "claude",
            "commandcode",
        ):
            raise ValueError(
                "Native login is supported only for OpenAI, Claude and Command Code connections"
            )
        if self.auth_type == "native_oauth" and self.api_key:
            raise ValueError("Native login does not accept an API key")
        return self


class LoginCodeInput(Strict):
    # Claude's manual OAuth flow shows "code#state"; Command Code Studio shows an API key.
    # The runner enforces the same shape.
    code: str = Field(min_length=8, max_length=2048, pattern=r"^[A-Za-z0-9._~+/=#-]+$", repr=False)

    @field_validator("code", mode="before")
    @classmethod
    def trim(cls, value):
        return value.strip() if isinstance(value, str) else value


class SessionInput(Strict):
    # The runner enforces the same shape before input reaches the agent's session.
    run_id: str = Field(min_length=1, max_length=64)
    action: Literal["prompt", "keys", "hold", "release"]
    text: str | None = Field(default=None, min_length=1, max_length=16000)
    keys: list[Annotated[str, Field(pattern=r"^[a-z0-9+]{1,20}$")]] | None = Field(
        default=None, min_length=1, max_length=16
    )

    @model_validator(mode="after")
    def complete(self):
        if (self.action == "prompt") != (self.text is not None) or (self.action == "keys") != (
            self.keys is not None
        ):
            raise ValueError("Session input does not match its action")
        return self


AUDIT_MAX_FUNCTIONS = 24


class OperationInput(Strict):
    profile: Profile | None = None
    focus: str | None = Field(default=None, max_length=4000)
    # Audit context only: significant functions orientation may select, one agent run each.
    max_functions: int = Field(default=AUDIT_MAX_FUNCTIONS, ge=1, le=100)
    # Audit context only: ignore an interrupted audit of the same request instead of continuing it.
    fresh: bool = False
    # Audit context only: refresh this context for the current source, reusing unchanged work.
    refresh_from: str | None = Field(default=None, max_length=64)
    # CVE analysis and finding artifacts only: analyze this revision instead of the resolved
    # affected release, for records whose vulnerable version cannot be ranked automatically.
    source_ref: str | None = Field(default=None, max_length=200)

    @field_validator("source_ref")
    @classmethod
    def revision(cls, value):
        value = (value or "").strip()
        return safe_path(value) if value else None


class ReviewInput(Strict):
    # candidate awaits review; confirmed is a real vulnerability, dismissed is not one.
    decision: Literal["pending", "dismissed", "candidate", "confirmed"]


class BatchReviewInput(ReviewInput):
    ids: list[str] = Field(min_length=1, max_length=1000)


# Each revision runs as its own agent job with a build sandbox, so one request queues few.
ANALYSIS_BATCH_MAX = 50


class BatchAnalysisInput(Strict):
    ids: list[str] = Field(min_length=1, max_length=ANALYSIS_BATCH_MAX)
    profile: Profile | None = None


class BatchDeleteInput(Strict):
    ids: list[str] = Field(min_length=1, max_length=1000)


class PromptInput(Strict):
    source: str = Field(max_length=100_000)


class PromptPreviewInput(Strict):
    operation: str = Field(min_length=1, max_length=100)
    # An unsaved draft of one template, rendered in place of its saved version.
    name: str | None = Field(default=None, max_length=100)
    source: str | None = Field(default=None, max_length=100_000)
    # Defaults to how the operation's jobs run.
    build: bool | None = None

    @model_validator(mode="after")
    def draft(self):
        if (self.name is None) != (self.source is None):
            raise ValueError("A draft needs both the template name and its source")
        return self


class MatchInput(Strict):
    confirmed: bool


class ManualObservation(Strict):
    version: str = Field(min_length=1, max_length=100)
    evidence: list | dict | str


class LoginInput(Strict):
    username: str
    password: str = Field(max_length=1024)
