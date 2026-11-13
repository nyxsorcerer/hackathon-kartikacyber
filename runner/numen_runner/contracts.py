import base64
import binascii
import hashlib
import io
import tarfile
import zlib
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal

from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .adapters import CODEX_REFUSED

MAXIMA = {"timeout_seconds": 1800, "memory_mb": 2048, "cpus": 2.0, "pids": 128,
          "output_bytes": 8 * 1024 * 1024, "input_bytes": 32 * 1024 * 1024}
# Expanded bounds for a compressed archive input. A real application's own tree is tens of
# thousands of files and hundreds of megabytes before its dependencies are vendored at all.
ARCHIVE_FILES, ARCHIVE_BYTES = 65536, 512 * 1024 * 1024
# A lab run carries a whole application and builds it, so it is bounded like a build, not like a
# read-only analysis. Its ceiling applies only to that kind. ADR-0005: a Lab image is at most 4 GB,
# its build gets 15 minutes and its run (timeout_seconds, which starts after the build) 10.
LAB_MAXIMA = {"timeout_seconds": 600, "build_seconds": 900, "image_bytes": 4 * 1024**3, "memory_mb": 8192,
              "cpus": 4.0, "pids": 4096, "output_bytes": 64 * 1024 * 1024, "input_bytes": 512 * 1024 * 1024}
# A Detection rule run (A07) only reads its trees with yara, so it is bounded like a scan; its trees
# arrive as archive inputs.
RULE_MAXIMA = {"timeout_seconds": 600, "memory_mb": 1024, "cpus": 2.0, "pids": 64,
               "output_bytes": 8 * 1024 * 1024, "input_bytes": 256 * 1024 * 1024}
CEILINGS = {"lab": LAB_MAXIMA, "detection_rule": RULE_MAXIMA}
PROVIDERS = {"openai": ["api.openai.com", "chatgpt.com", "auth.openai.com"],
             "claude": ["api.anthropic.com", "claude.ai", "platform.claude.com", "console.anthropic.com"],
             "deepseek": ["api.deepseek.com"], "commandcode": ["api.commandcode.ai"]}
# Herdr fetches its agent-detection manifests at start and every 30 minutes (ADR-0004).
HERDR_HOSTS = ["herdr.dev"]
# Operator-pasted native OAuth authorization codes (code#state). They are single-use and
# bound to the PKCE verifier held by the login process, but are still never logged.
LOGIN_CODE = r"[A-Za-z0-9._~+/=#-]{8,2048}"
LOGIN_CODE_BYTES = 4096
OPERATIONS = {"commit_triage", "commit_analysis", "version_recipe", "audit_context", "cve_analysis", "finding_artifacts", "patch_drafting"}


def safe_path(path: str) -> str:
    if not path or len(path) > 240 or "\\" in path or "\x00" in path:
        raise ValueError("invalid workspace path")
    p = PurePosixPath(path)
    if p.is_absolute() or any(part in ("", ".", "..") for part in path.split("/")):
        raise ValueError("path must be a normalized relative file")
    return path


def decode_file(item: dict, limit: int) -> bytes:
    safe_path(item["path"])
    if len(item["content_base64"]) > ((limit + 2) // 3) * 4:
        raise ValueError("file exceeds byte limit")
    try:
        data = base64.b64decode(item["content_base64"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid base64 file") from exc
    if len(data) > limit:
        raise ValueError("file exceeds byte limit")
    return data


def archive_files(prefix: str, data: bytes) -> list[tuple[str, bytes]]:
    """Expand a gzip tar input under prefix/, accepting only bounded regular files."""
    files, total = [], 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive:
                if not member.isreg():
                    raise ValueError("archive input may contain only regular files")
                total += member.size
                if len(files) >= ARCHIVE_FILES or total > ARCHIVE_BYTES:
                    raise ValueError("archive input exceeds its expanded limit")
                files.append((prefix + "/" + safe_path(member.name), archive.extractfile(member).read()))
    except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
        raise ValueError("invalid archive input") from exc
    return files


def input_files(inputs: list[dict], limit: int) -> list[tuple[str, bytes]]:
    files = []
    for item in inputs:
        data = decode_file(item, limit)
        files.extend(archive_files(item["path"], data) if item.get("archive") else [(item["path"], data)])
    return files


class InputFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    content_base64: str
    archive: bool = False


class Profile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent: Literal["pi", "claude", "codex"] = "codex"
    connection_id: str = ""
    model_id: str = Field(default="", max_length=240, pattern=r"^(?:[A-Za-z0-9][A-Za-z0-9._:/@+\-]*)?$")
    reasoning_effort: str | None = None
    provider_id: str = "openai"
    auth_type: Literal["api_key", "native_oauth"] = "api_key"
    credential: dict[str, Any] = Field(default_factory=dict, repr=False)
    operation: str | None = None
    enabled_plugins: list[str] = Field(default_factory=list)


class LoginInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(repr=False, pattern="^" + LOGIN_CODE + "$")


class SessionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["prompt", "keys", "hold", "release"]
    text: str | None = Field(default=None, min_length=1, max_length=16000)
    keys: list[Annotated[str, Field(pattern=r"^[a-z0-9+]{1,20}$")]] | None = Field(default=None, min_length=1, max_length=16)

    @model_validator(mode="after")
    def complete(self):
        if (self.action == "prompt") != (self.text is not None) or (self.action == "keys") != (self.keys is not None):
            raise ValueError("session input does not match its action")
        return self


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attempt_token: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    kind: Literal["agent", "probe", "lab", "detection_rule", "capabilities", "account_login"]
    profile: Profile = Field(default_factory=Profile)
    prompt: str = Field(default="", max_length=262144)
    output_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object"})
    inputs: list[InputFile] = Field(default_factory=list, max_length=4096)
    limits: dict[str, float] = Field(default_factory=dict)
    target_policy: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_request(self):
        maxima = CEILINGS.get(self.kind, MAXIMA)
        if set(self.limits) - set(maxima):
            raise ValueError("unknown execution limit")
        for key, value in self.limits.items():
            if key != "cpus" and not value.is_integer():
                raise ValueError(f"{key} must be a whole number")
            if not 0 < value <= maxima[key]:
                raise ValueError(f"{key} must lower the broker maximum")
        schema_text = __import__("json").dumps(self.output_schema)
        if len(schema_text.encode()) > 65536:
            raise ValueError("output schema exceeds byte limit")
        def local_references(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in {"$ref", "$dynamicRef", "$recursiveRef"} and (not isinstance(item, str) or not item.startswith("#")):
                        raise ValueError("output schema may only use local references")
                    local_references(item)
            elif isinstance(value, list):
                for item in value:
                    local_references(item)
        local_references(self.output_schema)
        Draft202012Validator.check_schema(self.output_schema)
        total, seen = 0, set()
        for item in self.inputs:
            data = decode_file(item.model_dump(), int(self.bounds["input_bytes"]))
            total += len(data)
            if item.archive and self.kind not in ("agent", "lab", "detection_rule"):
                raise ValueError("archive inputs are only supported for agent, lab and detection_rule runs")
            expanded = [path for path, _ in archive_files(item.path, data)] if item.archive else []
            for path in [item.path, *expanded]:
                if path in seen:
                    raise ValueError("duplicate input path")
                seen.add(path)
        if total > self.bounds["input_bytes"]:
            raise ValueError("aggregate input byte limit exceeded")
        if self.kind in ("lab", "detection_rule") and self.profile.credential:
            raise ValueError("a Lab or Detection rule run carries no credential")
        if self.kind in ("agent", "capabilities", "account_login"):
            p = self.profile
            if p.provider_id not in PROVIDERS:
                raise ValueError("unsupported provider")
            if (p.agent == "codex" and p.provider_id != "openai") or (p.agent == "claude" and p.provider_id != "claude"):
                raise ValueError("incompatible agent and provider")
            if p.agent == "pi" and p.auth_type != "api_key" and p.provider_id != "commandcode":
                raise ValueError("Pi native login is available only for Command Code")
            if p.provider_id == "commandcode" and "pi-commandcode-provider" not in p.enabled_plugins:
                raise ValueError("Command Code plugin is disabled")
            if self.kind != "account_login" and not p.credential:
                raise ValueError("connection credential is required")
            if self.kind == "agent" and (p.operation not in OPERATIONS or not p.model_id):
                raise ValueError("agent operation and model are required")
            if self.kind == "agent" and p.agent == "codex" and p.operation in CODEX_REFUSED:
                raise ValueError(CODEX_REFUSED[p.operation])
        return self

    @property
    def bounds(self):
        ceiling = CEILINGS.get(self.kind, MAXIMA)
        bounds = {k: self.limits.get(k, v) for k, v in ceiling.items()}
        if self.kind == "agent" and "timeout_seconds" not in self.limits:
            bounds["timeout_seconds"] = None  # Agent runs have no deadline unless one is requested.
        return bounds


# A finding bundle's outputs may be a whole application tree, so its file count is bounded like
# an archive input's; output_bytes still bounds their size.
MAX_OUTPUT_FILES = ARCHIVE_FILES


def validate_outputs(outputs: list[dict], limit: int) -> list[dict]:
    total, seen = 0, set()
    if len(outputs) > MAX_OUTPUT_FILES:
        raise ValueError("too many output files")
    for item in outputs:
        if set(item) != {"path", "content_base64", "size", "sha256"}:
            raise ValueError("invalid output manifest")
        data = decode_file(item, limit)
        if item["path"] in seen or item["size"] != len(data) or item["sha256"] != hashlib.sha256(data).hexdigest():
            raise ValueError("output integrity mismatch")
        seen.add(item["path"])
        total += len(data)
    if total > limit:
        raise ValueError("aggregate output byte limit exceeded")
    return outputs
