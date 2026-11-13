import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from jsonschema import Draft202012Validator

from .contracts import LoginInput, RunRequest, SessionInput, validate_outputs
from .workload import secret_values

TERMINAL = {"succeeded", "failed", "cancelled"}
# Whitespace or a terminal escape sequence (CSI such as SGR colors, or OSC) between characters.
TERMINAL_GAP = r"(?:\s|\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\))*"


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self.runs = {}
        self.credentials = {}
        self.login_inputs = {}  # Memory only: authorization codes are never written to run state.
        self.session_secrets = {}  # Memory only: credential strings redacted from session screens.
        for file in self.path.glob("*.json"):
            value = json.loads(file.read_text())
            self.runs[value["run_id"]] = value

    def save(self, value):
        with self.lock:
            self.runs[value["run_id"]] = value
            target = self.path / (value["run_id"] + ".json")
            temp = target.with_suffix(".tmp")
            temp.write_text(json.dumps(value), encoding="utf-8")
            temp.chmod(0o600)
            temp.replace(target)

    def change(self, run_id, **fields):
        with self.lock:
            value = self.runs[run_id]
            value.update(fields)
            self.save(value)

    def save_session(self, run_id, state):
        with self.lock:
            directory = self.path / "sessions"
            directory.mkdir(exist_ok=True, mode=0o700)
            target = directory / (run_id + ".json")
            temp = target.with_suffix(".tmp")
            temp.write_text(json.dumps(state), encoding="utf-8")
            temp.chmod(0o600)
            temp.replace(target)

    def read_session(self, run_id):
        target = self.path / "sessions" / (run_id + ".json")
        return json.loads(target.read_text()) if target.exists() else None


def create_app(token=None, state_path=None, engine=None, execute=True, reconcile_interval=2, concurrency=None):
    token = token or read_secret("NUMEN_BROKER_TOKEN")
    if len(token) < 16 and execute:
        raise RuntimeError("NUMEN_BROKER_TOKEN must contain at least 16 characters")
    store = Store(state_path or os.getenv("NUMEN_RUNNER_STATE", "/data/runner"))
    if engine is None:
        from .engine import DockerEngine
        engine = DockerEngine()
    tasks = set()
    # Each run owns its containers, networks and gateway, so runs are independent; this bounds
    # Engine load (an agent run may use up to its memory_mb limit).
    semaphore = asyncio.Semaphore(max(1, concurrency or int(os.getenv("NUMEN_RUNNER_CONCURRENCY", "4"))))
    ready = threading.Event()
    orphan_reconciliation = True

    async def auth(x_broker_token: str = Header(default="")):
        if not hmac.compare_digest(x_broker_token.encode(), token.encode()):
            raise HTTPException(401, "broker authentication required")

    def get(run_id):
        if run_id not in store.runs:
            raise HTTPException(404, "run not found")
        return store.runs[run_id]

    def cleanup_pending(run_id):
        ready.clear()
        store.change(run_id, status="cancelling", _cleanup_pending=True,
                     error={"code": "cleanup_pending", "message": "Owned workload cleanup is pending. Replacement execution waits for confirmed reconciliation.", "retryable": True})

    def retain_completion(run_id, completion):
        with store.lock:
            if get(run_id)["status"] == "cancelling":
                completion = {**completion, "status": "cancelled",
                              "error": {"code": "cancelled", "message": "Workload stopped; validated partial outputs retained." if completion.get("outputs") else "Workload stopped; no validated partial output was retained."}}
            # Persist the intended result before cleanup, but keep it nonterminal and private.
            store.change(run_id, _completion=completion, _cleanup_pending=False)

    def publish_completion(run_id):
        with store.lock:
            completion = get(run_id).get("_completion")
            if completion is None:
                return
            store.change(run_id, **{"error": None, **completion}, progress=100,
                         _completion=None, _cleanup_pending=False)
            entry = store.credentials.get(run_id)
            if entry:
                store.credentials[run_id] = (time.monotonic() + 600, entry[1])

    def retain_session(run_id, state, final=False):
        with store.lock:
            value = get(run_id)
            if not final and (value.get("_session_final") or value["status"] != "running"):
                archived = store.read_session(run_id)
                if archived is None:
                    raise HTTPException(409, "run has no retained agent session")
                return {**archived, "live": False}
            state = dict(state)
            for secret in store.session_secrets.get(run_id, ()):
                # Terminal wrapping can split a credential across whitespace in the saved viewport,
                # and terminal styling can put escape sequences between its characters.
                pattern = TERMINAL_GAP.join(re.escape(char) for char in secret)
                state["screen"] = re.sub(pattern, "[redacted]", state.get("screen", ""))
            store.save_session(run_id, state)
            if final:
                store.change(run_id, _session_final=True)
            return state

    def report(run_id, event):
        if "session" in event:
            retain_session(run_id, event["session"])
            return  # Terminal history never enters progress events or ordinary run responses.
        store.change(run_id, events=(get(run_id)["events"] + [event])[-100:],
                     **({"execution": event["execution"]} if "execution" in event else {}))

    def do_run(run_id, request):
        with store.lock:
            if get(run_id)["status"] == "cancelled":
                request.profile.credential.clear()
                return  # The queued run never created owned resources.
            store.change(run_id, status="running", progress=5)
        completion = None
        # Only login workloads read operator input; other engines keep the original call shape.
        login = {"login_input": lambda: store.login_inputs.pop(run_id, None)} if request.kind == "account_login" else {}
        store.session_secrets[run_id] = secret_values(request.profile.credential)
        try:
            envelope = engine.run(run_id, request,
                                  lambda: get(run_id)["status"] in {"cancelling", "cancelled"},
                                  lambda event: report(run_id, event), **login)
            credential = envelope.pop("credential", None)
            if credential is not None:
                store.session_secrets[run_id].extend(secret_values(credential))
                store.credentials[run_id] = (time.monotonic() + 600, credential)
                store.change(run_id, credential_updated=True)
            outputs = validate_outputs(envelope.get("outputs", []), int(request.bounds["output_bytes"]))
            result = envelope.get("result")
            if len(json.dumps(result).encode()) + sum(o["size"] for o in outputs) > request.bounds["output_bytes"]:
                from .engine import RuntimeFailure
                raise RuntimeFailure("output_limit", "Result and artifacts exceed the configured output byte limit.")
            if request.kind == "agent" and request.profile.operation == "commit_triage":
                # Triage returns its raw reply: application code validates it against the Triage schema.
                if not (isinstance(result, dict) and set(result) == {"reply"} and isinstance(result["reply"], str)):
                    raise ValueError("Triage result is not its reply text")
            elif request.kind not in {"capabilities", "account_login"}:
                Draft202012Validator(request.output_schema).validate(result)
            completion = {"status": "succeeded", "result": result, "outputs": outputs,
                          "execution": envelope.get("execution"), "credential_updated": bool(credential)}
        except Exception as exc:
            # Never return arbitrary child logs, Docker error strings, or credential-bearing input.
            code = getattr(exc, "code", "runtime_error")
            message = getattr(exc, "safe_message", "Workload failed. Check runtime configuration and provider access.")
            refreshed = getattr(exc, "credential", None)
            if refreshed:
                store.session_secrets[run_id].extend(secret_values(refreshed))
                store.credentials[run_id] = (time.monotonic() + 600, refreshed)
                store.change(run_id, credential_updated=True)
            completion = {"status": "failed", "error": {"code": code, "message": message,
                          "retryable": code in {"engine_unavailable", "runtime_error"}}}
        finally:
            if completion is not None:
                if hasattr(engine, "session"):
                    try:
                        retain_session(run_id, {**engine.session(run_id, "read"), "live": False, "held": False}, final=True)
                    except Exception as exc:
                        if getattr(exc, "code", "no_session") != "no_session":
                            report(run_id, {"type": "session_history_unavailable",
                                "message": "Final session history could not be read; the last saved session remains available."})
                retain_completion(run_id, completion)
                try:
                    engine.cleanup(run_id)
                except Exception:
                    cleanup_pending(run_id)
                else:
                    # Terminal status means every owned resource was actually reconciled.
                    publish_completion(run_id)
            request.profile.credential.clear()
            store.login_inputs.pop(run_id, None)
            store.session_secrets.pop(run_id, None)

    async def schedule(run_id, request):
        async with semaphore:
            while not ready.is_set():
                if get(run_id)["status"] == "cancelled":
                    request.profile.credential.clear()
                    return
                await asyncio.sleep(.1)
            await asyncio.to_thread(do_run, run_id, request)

    async def reconcile_once():
        nonlocal orphan_reconciliation
        for run_id, value in list(store.runs.items()):
            if value.get("_cleanup_pending") and value.get("_completion") is not None:
                try:
                    await asyncio.to_thread(engine.cleanup, run_id)
                except Exception:
                    cleanup_pending(run_id)
                else:
                    publish_completion(run_id)
        if orphan_reconciliation:
            try:
                if execute and hasattr(engine, "reconcile"):
                    await asyncio.to_thread(engine.reconcile)
            except Exception:
                ready.clear()
            else:
                orphan_reconciliation = False
        for run_id, (expires, _) in list(store.credentials.items()):
            if expires <= time.monotonic() and get(run_id)["status"] in TERMINAL:
                store.credentials.pop(run_id, None)
        if not orphan_reconciliation and not any(v.get("_cleanup_pending") for v in store.runs.values()):
            ready.set()
        else:
            ready.clear()

    async def reconcile_loop():
        while True:
            await asyncio.sleep(reconcile_interval)
            await reconcile_once()

    @asynccontextmanager
    async def lifespan(app):
        for run_id, value in list(store.runs.items()):
            if value["status"] not in TERMINAL:
                if value.get("_completion") is None:
                    store.change(run_id, _completion={"status": "failed", "error": {
                        "code": "broker_restart", "message": "Broker restarted; prior owned workloads were removed. Retry creates a new attempt."}})
                cleanup_pending(run_id)
        await reconcile_once()
        recovery_task = asyncio.create_task(reconcile_loop())
        yield
        recovery_task.cancel()
        await asyncio.gather(recovery_task, return_exceptions=True)
        # Cancel signals are visible to active Engine loops; background jobs cannot claim a stop
        # merely because the HTTP service is shutting down.
        with store.lock:
            for run_id, value in list(store.runs.items()):
                if value["status"] == "queued":
                    store.change(run_id, status="cancelled")  # No Engine execution ever started.
                elif value["status"] == "running":
                    store.change(run_id, status="cancelling")
        # Cancelling a to_thread await does not stop its Engine thread. Wait for execution to
        # finish before a final cleanup; otherwise that thread could create a late resource.
        await asyncio.gather(*list(tasks), return_exceptions=True)
        for run_id, value in list(store.runs.items()):
            if value["status"] not in TERMINAL:
                try:
                    await asyncio.to_thread(engine.cleanup, run_id)
                except Exception:
                    if value.get("_completion") is None:
                        store.change(run_id, _completion={"status": "cancelled", "error": {
                            "code": "cancelled", "message": "Workload stopped during broker shutdown."}})
                    cleanup_pending(run_id)
                else:
                    if value.get("_completion") is None:
                        store.change(run_id, _completion={"status": "cancelled", "error": {
                            "code": "cancelled", "message": "Workload stopped during broker shutdown."}})
                    publish_completion(run_id)

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = store
    app.state.reconcile = reconcile_once

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request, exc):
        # Where the payload broke the contract and which rule it broke, never the submitted values:
        # payloads carry source evidence and credentials.
        problems = "; ".join(
            ".".join(str(part)[:64] for part in error.get("loc", ())[1:]) + ": " + str(error.get("msg", "invalid"))[:200]
            for error in exc.errors()[:3]
        )
        logging.getLogger("uvicorn.error").warning("Rejected run payload: %s", problems)
        return JSONResponse(status_code=422, content={"code": "invalid_run", "message": "Run payload failed execution contract validation: " + problems})

    @app.get("/health")
    def health():
        if not ready.is_set():
            return JSONResponse(status_code=503, content={"status": "reconciliation_pending"})
        return {"status": "ready"}

    @app.post("/internal/runs", dependencies=[Depends(auth)], status_code=202)
    async def submit(request: RunRequest):
        fingerprint_request = request.model_dump()
        fingerprint_request["profile"].pop("credential", None)
        fingerprint = hashlib.sha256(json.dumps(fingerprint_request, sort_keys=True).encode()).hexdigest()
        for value in store.runs.values():
            if value["attempt_token"] == request.attempt_token:
                if value["fingerprint"] != fingerprint:
                    raise HTTPException(409, "attempt token already has different inputs")
                return {"run_id": value["run_id"], "status": value["status"]}
        if not ready.is_set():
            return JSONResponse(status_code=503, content={"code": "reconciliation_pending",
                "message": "Owned workload cleanup is pending; replacement execution is blocked.", "retryable": True})
        run_id = str(uuid.uuid4())
        store.save({"run_id": run_id, "attempt_token": request.attempt_token, "fingerprint": fingerprint,
                    "kind": request.kind, "status": "queued", "progress": 0, "events": [], "outputs": []})
        if execute:
            task = asyncio.create_task(schedule(run_id, request))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
        return {"run_id": run_id, "status": "queued"}

    @app.get("/internal/attempts/{attempt_token}", dependencies=[Depends(auth)])
    def attempt(attempt_token: str):
        for value in store.runs.values():
            if value["attempt_token"] == attempt_token:
                return {"run_id": value["run_id"], "status": value["status"], "reconciled": value["status"] in TERMINAL}
        if not ready.is_set():
            return JSONResponse(status_code=503, content={"code":"reconciliation_pending",
                "message":"Attempt absence cannot be confirmed before owned workload reconciliation.", "retryable":True})
        return {"run_id":None, "status":"absent", "reconciled":True}

    @app.get("/internal/runs/{run_id}", dependencies=[Depends(auth)])
    def status(run_id: str):
        return {k: v for k, v in get(run_id).items() if k not in {"fingerprint", "attempt_token"} and not k.startswith("_")}

    @app.get("/internal/runs/{run_id}/outputs", dependencies=[Depends(auth)])
    def outputs(run_id: str):
        return {"outputs": get(run_id).get("outputs", [])}

    @app.post("/internal/runs/{run_id}/cancel", dependencies=[Depends(auth)])
    def cancel(run_id: str):
        with store.lock:
            value = get(run_id)
            if value["status"] not in TERMINAL:
                if value["status"] == "queued":
                    store.change(run_id, status="cancelled")
                else:
                    completion = value.get("_completion")
                    if completion is not None:
                        store.change(run_id, _completion={**completion, "status": "cancelled",
                            "error": {"code": "cancelled", "message": "Workload stopped; validated partial outputs retained." if completion.get("outputs") else "Workload stopped; no validated partial output was retained."}})
                    store.change(run_id, status="cancelling")
        return status(run_id)

    @app.post("/internal/runs/{run_id}/login-input", dependencies=[Depends(auth)], status_code=202)
    def login_input(run_id: str, body: LoginInput):
        value = get(run_id)
        if value.get("kind") != "account_login" or value["status"] != "running":
            raise HTTPException(409, "run is not waiting for login input")
        store.login_inputs[run_id] = body.code
        return {"run_id": run_id, "status": value["status"]}

    def session_call(run_id, *args):
        if get(run_id)["status"] != "running" or not hasattr(engine, "session"):
            raise HTTPException(409, "run has no live agent session")
        try:
            return engine.session(run_id, *args)
        except Exception as exc:
            raise HTTPException(409, getattr(exc, "safe_message", "The agent session is unavailable.")) from None

    @app.get("/internal/runs/{run_id}/session", dependencies=[Depends(auth)])
    def session(run_id: str):
        value = get(run_id)
        if value["status"] != "running":
            state = store.read_session(run_id)
            if state is None:
                raise HTTPException(409, "run has no retained agent session")
            return {**state, "live": False}
        state = session_call(run_id, "read")
        return retain_session(run_id, {**state, "live": state.get("live", True)})

    @app.post("/internal/runs/{run_id}/session", dependencies=[Depends(auth)], status_code=202)
    def session_input(run_id: str, body: SessionInput):
        session_call(run_id, "send", body.model_dump_json(exclude_none=True))
        return {"run_id": run_id, "status": "accepted"}

    @app.get("/internal/runs/{run_id}/credential", dependencies=[Depends(auth)])
    def credential(run_id: str):
        value = get(run_id)
        entry = store.credentials.get(run_id)
        if entry and entry[0] <= time.monotonic() and value["status"] not in TERMINAL:
            store.credentials[run_id] = entry = (time.monotonic() + 600, entry[1])
        if not entry or entry[0] <= time.monotonic():
            store.credentials.pop(run_id, None)
            raise HTTPException(404, "credential unavailable or expired")
        return {"credential": entry[1]}

    @app.delete("/internal/runs/{run_id}/credential", dependencies=[Depends(auth)], status_code=204)
    def erase_credential(run_id: str):
        get(run_id)
        store.credentials.pop(run_id, None)

    return app


def read_secret(name):
    path = os.getenv(name + "_FILE")
    return Path(path).read_text().strip() if path else os.getenv(name, "")


def main():
    import uvicorn
    uvicorn.run(create_app(), host="0.0.0.0", port=8081, access_log=False)


if __name__ == "__main__":
    main()
