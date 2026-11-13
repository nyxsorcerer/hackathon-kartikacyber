import base64
import hashlib
import json
from pathlib import Path

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from numen.api import create_app
from numen.config import Config
from numen.domain import source_repository
from numen.models import Account, Commit, Application, Repository, Setting, Snapshot
from numen.artifacts import publish

REPOSITORY_FIELDS = ("role", "source_kind", "source_url", "source_ref", "source_path", "plugin_slug", "locked_version")


@pytest.fixture
def system(tmp_path):
    config = Config(
        database_url=f"sqlite:///{tmp_path}/db.sqlite",
        artifact_root=tmp_path / "artifacts",
        secret_key=Fernet.generate_key().decode(),
        test_mode=True,
        frontend_root=Path("/missing-frontend"),
        monitor_interval_seconds=172800,
    )
    app = create_app(config=config, admin_password="test-password-long")
    with TestClient(app) as client:
        session = client.post(
            "/api/auth/login", json={"username": "admin", "password": "test-password-long"}
        ).json()
        client.headers["X-CSRF-Token"] = session["csrf_token"]
        yield app, client, config


def application(client, **overrides):
    """Creates an Application linked to one Upstream repository, built from the source_* overrides."""
    source = {
        "source_kind": "github",
        "source_url": "https://github.com/demo/plugin",
        "source_ref": "main",
        **{key: overrides.pop(key) for key in REPOSITORY_FIELDS if key in overrides},
    }
    body = {
        "asset_name": "Site",
        "asset_url": "https://example.com",
        "product_kind": "plugin",
        "product_name": "Demo",
        "monitor_interval_seconds": 172800,
    }
    result = client.post("/api/applications", json={**body, **overrides})
    assert result.status_code == 201, result.text
    ident = result.json()["id"]
    linked = client.post(f"/api/applications/{ident}/repositories", json=source)
    assert linked.status_code == 201, linked.text
    return client.get(f"/api/applications/{ident}").json()


def repository_of(db, ident):
    """The repository the Application's operations read."""
    return source_repository(db, db.get(Application, ident))


def check_now(client, ident):
    """Check now for an Application with one polled repository: that repository's job id."""
    response = client.post(f"/api/applications/{ident}/checks")
    assert response.status_code == 202, response.text
    return response.json()["items"][0]["job_id"]


def github_account(app):
    """A GitHub read token; GitHub repositories are never polled without one."""
    with app.state.factory.begin() as db:
        db.add(Account(
            label="GitHub", provider="github", auth_type="api_key",
            credential=app.state.vault.encrypt({"api_key": "fixture-github-token"}),
            data={"status": "unchecked", "models": [], "usage": None},
        ))


def connection(app, agents=None):
    models = [
        {
            "id": "test-model",
            "name": "Test",
            "reasoning_efforts": ["low", "high"],
            "default_effort": "low",
        }
    ]
    with app.state.factory.begin() as db:
        account = Account(
            label="Test access",
            provider="openai",
            auth_type="api_key",
            credential=app.state.vault.encrypt({"api_key": "fixture-key-no-real-access"}),
            data={
                "status": "ready",
                "models": models,
                "agent_models": agents or {"pi": models, "codex": models},
                "usage": None,
            },
        )
        db.add(account)
        db.flush()
        profile = {
            "agent": "pi",
            "connection_id": account.id,
            "model_id": "test-model",
            "reasoning_effort": "high",
        }
        setting = db.get(Setting, "global")
        setting.data = {
            **setting.data,
            # Codex is refused for Triage, Analysis and CVE analysis, so they run on Pi.
            "default_profiles": {
                **{
                    op: {**profile, "agent": "codex"}
                    for op in ("version_recipe", "audit_context", "finding_artifacts")
                },
                **{op: profile for op in ("commit_triage", "commit_analysis", "cve_analysis")},
            },
        }
    return profile


def source_snapshot(app, ident, revision="a" * 40, repository_id=None, files=None):
    """A snapshot holding `files` (main.py by default) and a commit at `revision` of the
    Application's source repository, or of `repository_id`."""
    files = files or {"main.py": b"def parse(value):\n    return str(value)\n"}
    with app.state.factory.begin() as db:
        row = db.get(Repository, repository_id) if repository_id else repository_of(db, ident)
        row.cursor = revision
        source = Snapshot(
            repository_id=row.id,
            source_generation=row.source_generation,
            source_ref=revision,
            files=list(files),
        )
        db.add(source)
        db.flush()
        publish(db, app.state.config.artifact_root, "snapshot", source.id, files)
        commit = Commit(
            repository_id=row.id,
            source_generation=row.source_generation,
            revision=revision,
            data={
                "message": "Fix validation",
                "author": "Fixture",
                "files": [{"path": "main.py"}],
                "diff": "-return value\n+return str(value)",
                "diff_complete": True,
            },
            triage_status="disabled",
        )
        db.add(commit)
        db.flush()
        return commit.id


class FixtureBroker:
    def __init__(self, result=None, outputs=None, handler=None):
        self.result, self.outputs, self.handler = result or {}, outputs or {}, handler
        self.calls, self.states, self.ingress_deleted = [], {}, []

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
        call = {
            "token": token,
            "kind": kind,
            "profile": profile,
            "prompt": prompt,
            "schema": schema,
            "files": files or {},
            "policy": policy,
            "limits": limits,
        }
        self.calls.append(call)
        result, outputs = self.handler(call) if self.handler else (self.result, self.outputs)
        self.states[token] = {
            "run_id": token,
            "status": "succeeded",
            "result": result,
            "outputs": [
                {
                    "path": p,
                    "content_base64": base64.b64encode(data).decode(),
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
                for p, data in outputs.items()
            ],
        }
        return {"run_id": token, "status": "queued"}

    def wait(self, run_id, heartbeat, progress, deadline=900):
        heartbeat()
        progress(self.states[run_id])
        return self.states[run_id]

    def request(self, method, path, **kwargs):
        return self.states[path.split("/")[-1]]

    def cancel(self, run_id):
        self.states[run_id]["status"] = "cancelled"
        return self.states[run_id]

    def lookup_attempt(self, attempt_token):
        state = self.states.get(attempt_token)
        return {"run_id": attempt_token, "status": state["status"]} if state else None

    def credential(self, run_id):
        return {"auth_json": {"access_token": "native-fixture-secret"}}

    def delete_credential(self, run_id):
        self.ingress_deleted.append(run_id)


class Crash(BaseException):
    """A worker that dies mid-request: run_once's `except Exception` never records it."""


class FakeGitHub:
    """The recorded GitHub API fixture at NUMEN_GITHUB_API_URL=http://github.fixture: the git data,
    ref, pull request and commit listing endpoints of one repository, with in-memory state. It records each
    request as (method, path, bearer token) and raises Crash once after the request that
    `crash_after` = (method, path suffix) names, so that request's answer is lost."""

    def __init__(self, repo="acme/shop", default_branch="main"):
        self.repo, self.default_branch, self.crash_after = repo, default_branch, None
        self.requests, self.blobs, self.trees, self.commits, self.refs, self.pulls = [], {}, {}, {}, {}, []
        self.history = []  # the default branch's commits that polling lists, newest first

    def push(self, *shas):
        """Puts commits on the default branch, oldest first."""
        for sha in shas:
            self.history.insert(0, sha)

    def blob(self, data):
        sha = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # git's object id
        self.blobs[sha] = data
        return sha

    def tree(self, entries):
        sha = hashlib.sha1(json.dumps(sorted(entries.items())).encode()).hexdigest()
        self.trees[sha] = entries
        return sha

    def commit(self, sha, files, modes=None):
        """Seeds commit `sha`, whose tree holds `files` ({path: bytes}) with mode 100644 unless
        `modes` ({path: mode}) says otherwise."""
        tree = self.tree({p: {"path": p, "mode": (modes or {}).get(p, "100644"), "type": "blob", "sha": self.blob(d)}
                          for p, d in files.items()})
        self.commits[sha] = {"sha": sha, "tree": {"sha": tree}, "message": "Base", "parents": []}

    def files(self, sha):
        """{path: (mode, bytes)} of commit `sha`'s tree."""
        return {p: (e["mode"], self.blobs[e["sha"]]) for p, e in self.trees[self.commits[sha]["tree"]["sha"]].items()}

    def writes(self):
        return [(method, path) for method, path, _ in self.requests if method != "GET"]

    def __call__(self, request):
        self.requests.append((request.method, request.url.path,
                              request.headers.get("authorization", "").removeprefix("Bearer ")))
        prefix = f"/repos/{self.repo}"
        path = request.url.path
        response = (self.answer(request.method, path.removeprefix(prefix), request)
                    if path == prefix or path.startswith(prefix + "/") else None)
        if self.crash_after and request.method == self.crash_after[0] and path.endswith(self.crash_after[1]):
            self.crash_after = None
            raise Crash(f"worker died after {request.method} {path}")
        return response if response is not None else httpx.Response(404, json={"message": "Not Found"})

    def answer(self, method, path, request):
        body = json.loads(request.content) if request.content else {}
        if (method, path) == ("GET", ""):
            return httpx.Response(200, json={"full_name": self.repo, "default_branch": self.default_branch})
        if method == "GET" and path.startswith("/git/ref/"):
            ref = path.removeprefix("/git/ref/")
            if ref in self.refs:
                return httpx.Response(200, json={"ref": f"refs/{ref}", "object": {"type": "commit", "sha": self.refs[ref]}})
        if method == "GET" and path.startswith("/git/commits/"):
            sha = path.removeprefix("/git/commits/")
            if sha in self.commits:
                return httpx.Response(200, json=self.commits[sha])
        if method == "GET" and path.startswith("/git/trees/"):
            sha = path.removeprefix("/git/trees/")
            if sha in self.trees:
                return httpx.Response(200, json={"sha": sha, "tree": list(self.trees[sha].values()), "truncated": False})
        if (method, path) == ("POST", "/git/blobs"):
            return httpx.Response(201, json={"sha": self.blob(base64.b64decode(body["content"]))})
        if (method, path) == ("POST", "/git/trees"):
            entries = dict(self.trees[body["base_tree"]])
            for entry in body["tree"]:
                if entry["sha"] is None:
                    del entries[entry["path"]]
                else:
                    entries[entry["path"]] = entry
            return httpx.Response(201, json={"sha": self.tree(entries)})
        if (method, path) == ("POST", "/git/commits"):
            sha = hashlib.sha1(json.dumps(body, sort_keys=True).encode()).hexdigest()
            self.commits[sha] = {"sha": sha, "tree": {"sha": body["tree"]}, "message": body["message"],
                                 "parents": [{"sha": p} for p in body["parents"]]}
            return httpx.Response(201, json=self.commits[sha])
        if (method, path) == ("POST", "/git/refs"):
            ref = body["ref"].removeprefix("refs/")
            if ref in self.refs:
                return httpx.Response(422, json={"message": "Reference already exists"})
            self.refs[ref] = body["sha"]
            return httpx.Response(201, json={"ref": body["ref"], "object": {"type": "commit", "sha": body["sha"]}})
        if (method, path) == ("GET", "/pulls"):
            owner = self.repo.split("/")[0]
            return httpx.Response(200, json=[p for p in self.pulls
                                             if f"{owner}:{p['head']['ref']}" == request.url.params.get("head")])
        if method == "GET" and path.startswith("/pulls/"):
            number = int(path.removeprefix("/pulls/"))
            if 0 < number <= len(self.pulls):
                return httpx.Response(200, json=self.pulls[number - 1])
        # Polling the default branch: its commit list, a comparison and each commit's detail.
        if (method, path) == ("GET", "/commits"):
            etag = f'"{hashlib.sha1(json.dumps(self.history).encode()).hexdigest()}"'
            if request.headers.get("if-none-match") == etag:
                return httpx.Response(304)
            return httpx.Response(200, headers={"etag": etag}, json=[{"sha": s} for s in self.history]
                                  if request.url.params.get("page", "1") == "1" else [])
        if method == "GET" and path.startswith("/compare/"):
            base, head = path.removeprefix("/compare/").split("...")
            unseen = self.history[self.history.index(head):self.history.index(base)][::-1]
            return httpx.Response(200, json={"status": "ahead", "total_commits": len(unseen),
                                             "commits": [{"sha": s} for s in unseen]})
        if method == "GET" and path.startswith("/commits/") and path.removeprefix("/commits/") in self.history:
            sha = path.removeprefix("/commits/")
            older = self.history[self.history.index(sha) + 1:][:1]
            return httpx.Response(200, json={
                "sha": sha, "parents": [{"sha": p} for p in older],
                "commit": {"message": "Change", "author": {"name": "Fixture"}, "committer": {"date": "2026-11-01T00:00:00Z"}},
                "files": [{"filename": "main.py", "status": "modified", "patch": "@@ -1 +1 @@\n-a\n+b"}]})
        if (method, path) == ("POST", "/pulls"):
            if f"heads/{body['head']}" not in self.refs:
                return httpx.Response(422, json={"message": "Validation Failed"})
            number = len(self.pulls) + 1
            self.pulls.append({
                "number": number, "html_url": f"https://github.com/{self.repo}/pull/{number}", "state": "open",
                "draft": body.get("draft", False), "title": body["title"], "body": body["body"],
                "head": {"ref": body["head"], "sha": self.refs[f"heads/{body['head']}"]},
                "base": {"ref": body["base"]}, "merged": False, "merge_commit_sha": None,
            })
            return httpx.Response(201, json=self.pulls[-1])
        return None


@pytest.fixture
def github(monkeypatch):
    """FakeGitHub behind every Sources client the worker builds."""
    from numen.sources import Sources

    monkeypatch.setenv("NUMEN_GITHUB_API_URL", "http://github.fixture")
    fake = FakeGitHub()
    original = Sources.__init__

    def setup(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.client = httpx.Client(transport=httpx.MockTransport(fake))

    monkeypatch.setattr(Sources, "__init__", setup)
    return fake
