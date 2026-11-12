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

MAXIMA = {"timeout_seconds": 1800, "memory_mb": 2048, "cpus": 2.0, "pids": 128,
          "output_bytes": 8 * 1024 * 1024, "input_bytes": 32 * 1024 * 1024}
# A build run compiles and runs a real application, so it needs process, memory and output room
# that ordinary read-only analysis never does. Its ceiling applies only with build enabled.
BUILD_MAXIMA = {**MAXIMA, "timeout_seconds": 10800, "memory_mb": 8192, "cpus": 4.0, "pids": 2048,
                "output_bytes": 512 * 1024 * 1024}
BUILD_OPERATIONS = {"cve_analysis", "commit_analysis"}
# CONNECT destinations the build agent's own shell reaches through the credential-free proxy.
# The build daemon has its own egress; these are for the agent's clone and dependency reads.
BUILD_HOSTS = ["github.com", "codeload.github.com", "api.github.com", "objects.githubusercontent.com",
               "raw.githubusercontent.com", "registry.npmjs.org", "packagist.org", "repo.packagist.org",
               "getcomposer.org", "pypi.org", "files.pythonhosted.org", "registry-1.docker.io",
               "index.docker.io", "auth.docker.io", "production.cloudflare.docker.com"]
# Expanded bounds for a compressed archive input. A real application's own tree is tens of
# thousands of files and hundreds of megabytes before its dependencies are vendored at all.
ARCHIVE_FILES, ARCHIVE_BYTES = 65536, 512 * 1024 * 1024
# A lab run carries a whole application and builds it, so it is bounded like a build, not like a
# read-only analysis. Its ceiling applies only to that kind.
LAB_MAXIMA = {"timeout_seconds": 10800, "memory_mb": 8192, "cpus": 4.0, "pids": 4096,
              "output_bytes": 64 * 1024 * 1024, "input_bytes": 512 * 1024 * 1024}
PROVIDERS = {"openai": ["api.openai.com", "chatgpt.com", "auth.openai.com"],
             "claude": ["api.anthropic.com", "claude.ai", "platform.claude.com", "console.anthropic.com"],
             "deepseek": ["api.deepseek.com"], "commandcode": ["api.commandcode.ai"]}
# Operator-pasted native OAuth authorization codes (code#state). They are single-use and
# bound to the PKCE verifier held by the login process, but are still never logged.
LOGIN_CODE = r"[A-Za-z0-9._~+/=#-]{8,2048}"
LOGIN_CODE_BYTES = 4096
OPERATIONS = {"commit_triage", "commit_analysis", "version_recipe", "audit_context", "cve_analysis", "finding_artifacts"}


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


class Repository(BaseModel):
    """A canonical source repository Numen mirrors for a build run, with full history.

    The URL comes from the Application's own source configuration, never from an agent.
    """
    model_config = ConfigDict(extra="forbid")
    url: str = Field(max_length=200, pattern=r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    ref: str = Field(pattern=r"^[0-9a-f]{40}([0-9a-f]{24})?$")


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attempt_token: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    kind: Literal["agent", "probe", "lab", "capabilities", "account_login"]
    profile: Profile = Field(default_factory=Profile)
    prompt: str = Field(default="", max_length=262144)
    output_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object"})
    inputs: list[InputFile] = Field(default_factory=list, max_length=4096)
    limits: dict[str, float] = Field(default_factory=dict)
    target_policy: dict[str, Any] | None = None
    # Grants a private build daemon, a writable workspace and dependency egress for this run.
    build: bool = False
    # A full-history clone at /workspace/repo; only a build run has the egress to mirror it.
    repository: Repository | None = None

    @model_validator(mode="after")
    def validate_request(self):
        if self.repository is not None and not (self.build and self.kind == "agent"):
            raise ValueError("a repository is mirrored only for an agent build run")
        maxima = BUILD_MAXIMA if self.build else (LAB_MAXIMA if self.kind == "lab" else MAXIMA)
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
            if item.archive and self.kind not in ("agent", "lab"):
                raise ValueError("archive inputs are only supported for agent and lab runs")
            expanded = [path for path, _ in archive_files(item.path, data)] if item.archive else []
            for path in [item.path, *expanded]:
                if path in seen:
                    raise ValueError("duplicate input path")
                seen.add(path)
        if total > self.bounds["input_bytes"]:
            raise ValueError("aggregate input byte limit exceeded")
        if self.build and (self.kind != "agent" or self.profile.operation not in BUILD_OPERATIONS):
            raise ValueError("build runs are available only to supported agent operations")
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
        return self

    @property
    def bounds(self):
        ceiling = BUILD_MAXIMA if self.build else (LAB_MAXIMA if self.kind == "lab" else MAXIMA)
        bounds = {k: self.limits.get(k, v) for k, v in ceiling.items()}
        if self.kind == "agent" and not self.build and "timeout_seconds" not in self.limits:
            bounds["timeout_seconds"] = None  # Agent runs have no deadline unless one is requested.
            # A build run keeps the ceiling: its privileged daemon must not outlive a bounded run.
        return bounds


# A finding bundle's outputs are a whole application, so they are bounded like an archive input.
MAX_OUTPUT_FILES = ARCHIVE_FILES


def collect_outputs(fileobj, limit: int) -> list[dict]:
    """Read a workspace's outputs/ archive into an output manifest.

    Outputs leave a disk-backed workspace this way instead of through the container log, which
    Docker rotates: a bundle carrying a real application cannot fit a log and would be truncated
    into an unparseable envelope rather than refused.
    """
    outputs, total = [], 0
    try:
        with tarfile.open(fileobj=fileobj, mode="r|") as archive:
            for member in archive:
                if member.isdir():
                    continue
                if not member.isreg():
                    raise ValueError("output symlinks are not allowed")
                path = safe_path(member.name.removeprefix("outputs/"))
                total += member.size
                if total > limit or len(outputs) >= MAX_OUTPUT_FILES:
                    raise ValueError("output limit exceeded")
                data = archive.extractfile(member).read()
                outputs.append({"path": path,
                                "content_base64": base64.b64encode(data).decode(),
                                "sha256": hashlib.sha256(data).hexdigest(),
                                "size": len(data)})
    except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
        raise ValueError("invalid output archive") from exc
    return outputs


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
