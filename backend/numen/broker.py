import base64
import gzip
import io
import tarfile
import time
import httpx
from .artifacts import MAX_INPUTS, MAX_SET, MAX_SOURCE_FILES, MAX_SUBMISSION
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
            # A lab run's bundle and outputs can be a whole application, so the body takes a while.
            timeout=httpx.Timeout(600.0, connect=10.0),
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
            # The broker's own explanation (a contract rule, never a submitted value) makes the
            # failure diagnosable from the job alone.
            try:
                body = response.json()
            except ValueError:
                body = None
            detail = body.get("message") if isinstance(body, dict) else None
            raise DomainError(
                "broker_error",
                f"Execution broker returned HTTP {response.status_code}"
                + (f": {detail[:500]}" if isinstance(detail, str) and detail else ""),
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
    ):
        files, source = dict(files or {}), {}
        # Agent source evidence travels as one compressed archive the runner expands read-only.
        for path in list(files):
            if kind == "agent" and path.startswith("source/"):
                source[path.removeprefix("source/")] = files.pop(path)
        # A lab bundle is a whole application, so all of it travels the same way.
        prefix = "source"
        if kind == "lab":
            prefix, source, files = "bundle", files, {}
        archive = source_archive(source) if source else b""
        if (
            len(files) + bool(source) > MAX_INPUTS
            or len(source) > MAX_SOURCE_FILES
            or sum(len(content) for content in source.values()) > MAX_SET
            or len(archive) + sum(len(content) for content in files.values()) > MAX_SUBMISSION
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
                    "path": prefix,
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
        if kind == "lab":
            # A lab run builds and boots a whole application, dependencies and database included.
            defaults.update({"timeout_seconds": 7200, "memory_mb": 6144, "cpus": 2, "pids": 4096,
                             "output_bytes": 64 * 1024 * 1024, "input_bytes": MAX_SUBMISSION})
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
                # An agent run's requested bounds refine its defaults; other kinds name all of theirs.
                "limits": {**defaults, **limits} if limits and kind == "agent" else limits or defaults,
                "target_policy": policy,
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

    def session(self, run_id, body=None):
        """Read (GET) or steer (POST body) a running agent's interactive session."""
        try:
            response = self.client.request(
                "POST" if body else "GET", f"/internal/runs/{run_id}/session", json=body
            )
        except httpx.HTTPError as exc:
            raise DomainError(
                "broker_unavailable", "Execution broker is unavailable", 503, retryable=True
            ) from exc
        if response.status_code == 409:
            detail = response.json().get("detail")
            raise DomainError(
                "session_unavailable",
                detail if isinstance(detail, str) else "The agent session is unavailable",
                409,
                retryable=True,
            )
        if response.status_code >= 400:
            raise DomainError(
                "broker_error", f"Execution broker returned HTTP {response.status_code}", 502
            )
        return response.json()

    def login_input(self, run_id, code):
        self.request("POST", f"/internal/runs/{run_id}/login-input", json={"code": code})

    def credential(self, run_id):
        return self.request("GET", f"/internal/runs/{run_id}/credential")["credential"]

    def delete_credential(self, run_id):
        self.request("DELETE", f"/internal/runs/{run_id}/credential")
