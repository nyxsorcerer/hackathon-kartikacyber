import hashlib
import base64
import io
import json
import mimetypes
import os
import shutil
import tempfile
import zipfile
from pathlib import Path

from sqlalchemy import select
from .models import Artifact, uid
from .schemas import safe_path
from .security import DomainError, decode_content

MAX_FILE = 16 * 1024 * 1024
MAX_SET = 64 * 1024 * 1024
MAX_SOURCE_FILES = 20000  # Matches the runner's expanded source-archive bound.
REQUIRED = (
    "poc.py",
    "report.md",
    "vulnerable-app/Dockerfile",
    "vulnerable-app/compose.yaml",
    "vulnerable-app/README.md",
    "vulnerable-app/application.lock.json",
)


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
        if len(archive.infolist()) > 1000:
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
                if not isinstance(image, str) or (
                    image != "numen-lab:0.1.0" and "@sha256:" not in image
                ):
                    limitations.append("Base images must be pinned by digest")
        except (ValueError, TypeError):
            limitations.append("Application lock is not valid JSON")
    if "vulnerable-app/Dockerfile" in files:
        for line in files["vulnerable-app/Dockerfile"].decode(errors="replace").splitlines():
            parts = line.split()
            if parts and parts[0].upper() == "FROM":
                image = next((p for p in parts[1:] if not p.startswith("--")), "")
                if image.lower() not in ("scratch", "numen-lab:0.1.0") and "@sha256:" not in image:
                    limitations.append("Dockerfile base image is not pinned by digest")
    return {
        "status": "complete" if not missing and not limitations else "draft",
        "missing": missing,
        "limitations": limitations,
        "vulnerable_version": lock.get("version") if isinstance(lock, dict) else None,
    }


def bundle_zip(db, root, finding):
    files = resource_files(db, root, "finding", finding.id, finding.artifact_revision)
    if not files:
        raise DomainError("no_artifacts", "This finding has no artifacts", 409)
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path, content in files.items():
            bundle.writestr(path, content)
    return stream.getvalue()
