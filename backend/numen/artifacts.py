import hashlib
import base64
import io
import json
import mimetypes
import re
import os
import shutil
import tempfile
import zipfile
from pathlib import Path

from sqlalchemy import select
from .models import Artifact, uid
from .schemas import safe_path
from .security import DomainError, decode_content

# A finding bundle carries a real application: its own tree is tens of thousands of files and
# hundreds of megabytes before any dependency is vendored, so these bound storage, not plausibility.
MAX_FILE = 64 * 1024 * 1024
MAX_SET = 512 * 1024 * 1024
MAX_SOURCE_FILES = 65536  # Matches the runner's expanded archive bound.
MAX_INPUTS = 4096  # Individual runtime inputs; bulk travels as one compressed archive.
MAX_SUBMISSION = 256 * 1024 * 1024  # Compressed bytes one runtime submission may carry.
REQUIRED = (
    "poc.py",
    "report.md",
    "vulnerable-app/Dockerfile",
    "vulnerable-app/compose.yaml",
    "vulnerable-app/README.md",
    "vulnerable-app/application.lock.json",
)
# The runner's validate_dockerfile is the authority on what the lab verifier accepts; these mirror
# it so a bundle is never published complete and then refused. Keep the two in step.
LAB_DIRECTIVES = frozenset(
    {
        "FROM", "RUN", "COPY", "ADD", "WORKDIR", "USER", "ENV", "ARG", "EXPOSE",
        "CMD", "ENTRYPOINT", "LABEL", "VOLUME", "STOPSIGNAL", "SHELL", "HEALTHCHECK",
    }
)
LAB_BASE = re.compile(r"(?:asset-monitor-lab:0\.1\.0|scratch)(?: AS [a-zA-Z][a-zA-Z0-9_-]*)?")
LAB_DOCKERFILE_BYTES = 262144  # The verifier's own bound on the file it parses.
# Findings cache their artifact state; a cache made under other rules is read again. Bump this
# whenever completeness() changes what it accepts.
RULES = 2


def dockerfile_instructions(text):
    """The Dockerfile's instructions as the Engine reads them, mirroring the runner's
    engine.instructions: a comment line is dropped before continuations are joined, and a parser
    directive, which could change the escape character, raises ValueError."""
    result, current = [], None
    for line in text.removeprefix("\ufeff").split("\n"):
        line = line.rstrip("\r")
        stripped = line.lstrip()
        if stripped.startswith("#"):
            if re.match(r"#\s*(?:escape|syntax)\s*=", stripped, re.I):
                raise ValueError("parser directive")
            continue
        if not stripped:
            continue
        continued = re.search(r"\\[ \t]*$", line)
        part = line[: continued.start()] if continued else line
        current = part.lstrip() if current is None else current + part
        if not continued:
            result.append(current)
            current = None
    return result if current is None else [*result, current]


def clean_files(files, secrets=()):
    result, size = {}, 0
    for path, content in files.items():
        try:
            path = safe_path(path)
        except ValueError as exc:
            raise DomainError("unsafe_artifact_path", str(exc), 422) from exc
        if path == "manifest.json":
            continue  # The application creates the authoritative integrity manifest.
        if not isinstance(content, bytes) or len(content) > MAX_FILE:
            raise DomainError("artifact_too_large", "An artifact exceeds the per-file limit", 413)
        size += len(content)
        if size > MAX_SET:
            raise DomainError("artifact_too_large", "The artifact set exceeds its limit", 413)
        if any(
            s
            and len(s) >= 8
            and (s in path or s.encode() in content or base64.b64encode(s.encode()) in content)
            for s in secrets
        ):
            raise DomainError(
                "secret_in_artifact", "Artifact output contains a configured credential", 422
            )
        result[path] = content
    if not result:
        raise DomainError("empty_artifacts", "No artifact files were supplied", 422)
    return result


def unpack_zip(content):
    if len(content) > MAX_SET:
        raise DomainError("artifact_too_large", "Archive exceeds its limit", 413)
    files = {}
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        if len(archive.infolist()) > MAX_SOURCE_FILES:
            raise DomainError("artifact_too_large", "Too many archive entries", 413)
        total = 0
        for entry in archive.infolist():
            if entry.is_dir():
                continue
            mode = entry.external_attr >> 16
            if mode & 0o170000 not in (0, 0o100000):
                raise DomainError(
                    "unsafe_artifact_path", "Archive links or special files are forbidden", 422
                )
            total += entry.file_size
            if entry.file_size > MAX_FILE or total > MAX_SET:
                raise DomainError("artifact_too_large", "Expanded archive exceeds its limit", 413)
            try:
                path = safe_path(entry.filename)
            except ValueError as exc:
                raise DomainError("unsafe_artifact_path", str(exc), 422) from exc
            if path in files:
                raise DomainError("duplicate_artifact", "Archive contains duplicate paths", 422)
            files[path] = archive.read(entry)
    return files


def output_files(outputs):
    files = {}
    for output in outputs or []:
        path = output.get("path", "")
        if path in files:
            raise DomainError("invalid_output", "Broker returned duplicate output paths", 422)
        value = decode_content(output.get("content_base64", ""))
        if output.get("sha256") and hashlib.sha256(value).hexdigest() != output["sha256"]:
            raise DomainError("invalid_output", "Broker output hash mismatch", 422)
        if output.get("size") is not None and len(value) != output["size"]:
            raise DomainError("invalid_output", "Broker output size mismatch", 422)
        files[path] = value
    return clean_files(files) if files else {}


def publish(db, root, resource_type, resource_id, files, metadata=None, secrets=()):
    files = clean_files(files, secrets)
    revision = uid()
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".staging-", dir=root))
    items = []
    manifest = {
        "schema_version": 1,
        "revision": revision,
        "resource_type": resource_type,
        "resource_id": resource_id,
        **(metadata or {}),
        "files": [],
    }
    try:
        for path, content in files.items():
            dest = stage / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(content)
            manifest["files"].append(
                {"path": path, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
            )
        files = {**files, "manifest.json": json.dumps(manifest, indent=2).encode()}
        (stage / "manifest.json").write_bytes(files["manifest.json"])
        final = root / revision
        os.replace(stage, final)
        for path, content in files.items():
            item = Artifact(
                resource_type=resource_type,
                resource_id=resource_id,
                revision=revision,
                path=path,
                storage_path=f"{revision}/{path}",
                size=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
                content_type=mimetypes.guess_type(path)[0] or "application/octet-stream",
            )
            db.add(item)
            items.append(item)
        db.flush()
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return revision, items


def read_file(root, artifact):
    path = Path(root) / artifact.storage_path
    if not path.is_file() or path.is_symlink():
        raise DomainError("artifact_missing", "Artifact bytes are unavailable", 409)
    content = path.read_bytes()
    if len(content) != artifact.size or hashlib.sha256(content).hexdigest() != artifact.sha256:
        raise DomainError("artifact_corrupt", "Artifact failed its integrity check", 409)
    return content


def resource_files(db, root, resource_type, resource_id, revision=None):
    stmt = select(Artifact).where(
        Artifact.resource_type == resource_type, Artifact.resource_id == resource_id
    )
    if revision:
        stmt = stmt.where(Artifact.revision == revision)
    return {a.path: read_file(root, a) for a in db.scalars(stmt)}


def resource_completeness(db, root, resource_type, resource_id, revision):
    conditions = (
        Artifact.resource_type == resource_type,
        Artifact.resource_id == resource_id,
        Artifact.revision == revision,
    )
    # Completeness needs contents only for these two declarations. Other published
    # files contribute their paths and nonempty sizes; integrity is checked on use.
    files = {
        path: b"present" if size else b""
        for path, size in db.execute(select(Artifact.path, Artifact.size).where(*conditions))
    }
    declarations = db.scalars(
        select(Artifact).where(
            *conditions,
            Artifact.path.in_(("vulnerable-app/Dockerfile", "vulnerable-app/application.lock.json")),
        )
    )
    files.update({row.path: read_file(root, row) for row in declarations})
    return completeness(files)


def completeness(files):
    missing = [path for path in REQUIRED if path not in files or not files[path]]
    limitations = []
    lock = {}
    if "vulnerable-app/application.lock.json" in files:
        try:
            lock = json.loads(files["vulnerable-app/application.lock.json"])
            if (
                not isinstance(lock, dict)
                or not lock.get("version")
                or not (lock.get("source_ref") or lock.get("local_inputs"))
            ):
                limitations.append(
                    "Application lock must declare a vulnerable version and pinned source_ref or local_inputs"
                )
            if not isinstance(lock, dict):
                lock = {}
            source = lock.get("source_ref") or ""
            if source and not (
                isinstance(source, str)
                and len(source) >= 7
                and all(c in "0123456789abcdef" for c in source.lower())
            ):
                limitations.append("Application source_ref must identify an immutable revision")
            local_inputs = lock.get("local_inputs", {})
            if not isinstance(local_inputs, (list, dict)):
                limitations.append("Local inputs must identify included application files")
                local_inputs = []
            for path in local_inputs:
                if not isinstance(path, str) or "vulnerable-app/" + path not in files:
                    limitations.append("A declared application input is missing from the bundle")
            for image in lock.get("images", []):
                if image != "asset-monitor-lab:0.1.0":
                    limitations.append("Lock images must be the bundled Lab base asset-monitor-lab:0.1.0")
        except (ValueError, TypeError):
            limitations.append("Application lock is not valid JSON")
    if "vulnerable-app/Dockerfile" in files:
        text = files["vulnerable-app/Dockerfile"].decode(errors="replace")
        bases = []
        if len(text) > LAB_DOCKERFILE_BYTES:
            limitations.append("Dockerfile is larger than the lab verifier parses")
        stages = set()
        try:
            lines = dockerfile_instructions(text)
        except ValueError:
            lines = []
            limitations.append("Dockerfile parser directives are refused by the lab verifier")
        for line in lines:
            line = line.strip()
            if not line:
                continue
            instruction, _, value = line.partition(" ")
            instruction = instruction.upper()
            if instruction not in LAB_DIRECTIVES:
                # The message stays application-owned: the file is agent-authored and unbounded.
                limitations.append("A Dockerfile directive is refused by the lab verifier")
                continue
            if instruction in ("FROM", "COPY", "ADD") and "$" in value:
                # The Engine expands a variable here, so what is checked would not be what it builds.
                limitations.append("Dockerfile FROM, COPY and ADD cannot use variables")
                continue
            if instruction == "FROM":
                bases.append(value)
                if " AS " in value.upper():
                    stages.add(value.split()[-1])
                if not LAB_BASE.fullmatch(value) and value.split()[0] not in stages:
                    limitations.append("Dockerfile base must be the bundled lab image, scratch or a build stage")
            # Only the flags leading the directive are inspected, so an ENV may mention one.
            leading = []
            for part in value.split():
                if not part.startswith("--"):
                    break
                leading.append(part)
            if any(flag.startswith(("--mount", "--security", "--network")) for flag in leading):
                limitations.append("Dockerfile build mounts are not accepted by the lab verifier")
            sources = [part for part in value.split()[:-1] if not part.startswith("--")]
            if instruction in ("COPY", "ADD") and "--from=" not in value and any("://" in part for part in sources):
                # The Lab builds offline: the Engine would fetch a URL source outside --network none.
                limitations.append("Dockerfile COPY and ADD sources must be bundle files, not URLs")
            elif (
                instruction in ("COPY", "ADD")
                and "--from=" not in value
                and any(part.startswith("/") or ".." in part.split("/") for part in sources)
            ):
                limitations.append("Dockerfile COPY source must stay inside the bundle")
            elif instruction in ("COPY", "ADD") and "--from=" in value:
                stage = next(
                    part.removeprefix("--from=") for part in value.split() if part.startswith("--from=")
                )
                if stage not in stages:
                    limitations.append("A Dockerfile COPY --from names no earlier build stage")
            elif instruction == "COPY":
                for part in value.split()[:-1]:
                    # A glob or the context root cannot be resolved here without the builder's rules.
                    if part in (".", "./") or any(c in part for c in "*?["):
                        continue
                    source = "vulnerable-app/" + part.removeprefix("./").rstrip("/")
                    if source not in files and not any(p.startswith(source + "/") for p in files):
                        limitations.append("A Dockerfile COPY source is missing from the bundle")
        if not bases:
            limitations.append("Dockerfile lacks a pinned base")
    limitations = sorted(set(limitations))[:20]
    return {
        "status": "complete" if not missing and not limitations else "draft",
        "missing": missing,
        "limitations": limitations,
        "vulnerable_version": lock.get("version") if isinstance(lock, dict) else None,
    }


def bundle_zip(db, root, finding):
    return resource_zip(db, root, "finding", finding.id, finding.artifact_revision)


def resource_zip(db, root, resource_type, resource_id, revision=None):
    files = resource_files(db, root, resource_type, resource_id, revision)
    if not files:
        raise DomainError("no_artifacts", f"This {resource_type} has no artifacts", 409)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path, content in files.items():
            bundle.writestr(path, content)
    return stream.getvalue()
