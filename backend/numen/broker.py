import base64
import gzip
import io
import tarfile
import time
import httpx
from .artifacts import MAX_SET, MAX_SOURCE_FILES
from .security import DomainError


def source_archive(files):
    """Deterministic gzip tar, so a resubmitted attempt keeps an identical fingerprint."""
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(files):
            info = tarfile.TarInfo(path)
            info.size, info.mode = len(files[path]), 0o444
            archive.addfile(info, io.BytesIO(files[path]))
    return gzip.compress(payload.getvalue(), mtime=0)


class Broker:
    def __init__(self, config):
        self.client = httpx.Client(
            base_url=config.broker_url.rstrip("/"),
            timeout=30,
            headers={"X-Broker-Token": config.broker_token},
        )

    def request(self, method, path, **kwargs):
        try:
            response = self.client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise DomainError(
                "broker_unavailable", "Execution broker is unavailable", 503, retryable=True
            ) from exc
        if response.status_code >= 400:
            raise DomainError(
                "broker_error",
                f"Execution broker returned HTTP {response.status_code}",
                502,
                retryable=response.status_code >= 500,
            )
        return response.json() if response.content else {}

    def submit(
        self,
        token,
        kind,
        profile=None,
        prompt="",
        schema=None,
        files=None,
        policy=None,
        limits=None,
        build=False,
    ):
        files, source = dict(files or {}), {}
        # Agent source evidence travels as one compressed archive the runner expands read-only.
        for path in list(files):
            if kind == "agent" and path.startswith("source/"):
                source[path.removeprefix("source/")] = files.pop(path)
        archive = source_archive(source) if source else b""
        if (
            len(files) + bool(source) > 512
            or len(source) > MAX_SOURCE_FILES
            or sum(len(content) for content in source.values()) > MAX_SET
            or len(archive) + sum(len(content) for content in files.values()) > 32 * 1024 * 1024
        ):
            raise DomainError(
                "runtime_input_limit",
                "Input scope exceeds the bounded runtime; select a narrower source path",
                413,
            )
        inputs = [
            {"path": path, "content_base64": base64.b64encode(content).decode()}
            for path, content in files.items()
        ]
        if source:
            inputs.append(
                {
                    "path": "source",
                    "content_base64": base64.b64encode(archive).decode(),
                    "archive": True,
                }
            )
        defaults = {
            "timeout_seconds": 600,
            "memory_mb": 1024,
            "cpus": 1,
            "pids": 128,
            "output_bytes": 8 * 1024 * 1024,
            "input_bytes": 32 * 1024 * 1024,
        }
        if kind == "agent":
            del defaults["timeout_seconds"]  # Agent runs have no deadline; operators cancel them.
        if build:
            # A build run compiles, installs and runs a real application in its own workspace.
            defaults.update({"memory_mb": 6144, "cpus": 2, "pids": 2048, "output_bytes": 64 * 1024 * 1024})
        return self.request(
            "POST",
            "/internal/runs",
            json={
                "attempt_token": token,
                "kind": kind,
                "profile": profile or {},
                "prompt": prompt,
                "output_schema": schema or {},
                "inputs": inputs,
                "limits": limits or defaults,
                "target_policy": policy,
                "build": build,
            },
        )

    def wait(self, run_id, heartbeat, progress, deadline=900):
        started = time.monotonic()
        while deadline is None or time.monotonic() - started < deadline:
            heartbeat()
            state = self.request("GET", f"/internal/runs/{run_id}")
            progress(state)
            if state["status"] in ("succeeded", "failed", "cancelled"):
                if state["status"] != "succeeded":
                    error = state.get("error") or {}
                    raise DomainError(
                        error.get("code", "runtime_failed")
                        if isinstance(error, dict)
                        else "runtime_failed",
                        error.get("message", "Runtime did not complete successfully")
                        if isinstance(error, dict)
                        else "Runtime did not complete successfully",
                        502,
                    )
                return state
            time.sleep(0.4)
        self.cancel(run_id)
        raise DomainError("runtime_timeout", "Runtime exceeded the operation deadline", 504)

    def cancel(self, run_id):
        return self.request("POST", f"/internal/runs/{run_id}/cancel")

    def lookup_attempt(self, attempt_token):
        response = self.request("GET", f"/internal/attempts/{attempt_token}")
        if isinstance(response.get("run_id"), str) and response["run_id"]:
            return response  # Identity permits cancellation; it is not itself a stop proof.
        if (
            response.get("run_id") is None
            and response.get("status") == "absent"
            and response.get("reconciled") is True
        ):
            return None
        raise DomainError(
            "reconciliation_pending",
            "Execution broker returned no authoritative attempt state",
            503,
            retryable=True,
        )

    def login_input(self, run_id, code):
        self.request("POST", f"/internal/runs/{run_id}/login-input", json={"code": code})

    def credential(self, run_id):
        return self.request("GET", f"/internal/runs/{run_id}/credential")["credential"]

    def delete_credential(self, run_id):
        self.request("DELETE", f"/internal/runs/{run_id}/credential")
