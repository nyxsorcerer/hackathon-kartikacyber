"""Drafting Remediation PRs (A08, the A06 Own column): an Own-repository Vulnerability introduced
Verdict drafts a patch in a capped one-shot agent run, an Own Malicious change drafts the Cure's
revert in application code, and a pin or bump is application code too. Every diff is validated
before it can reach an Approval, and without an Own repository the steps are skipped. An Approval
opens exactly one draft pull request from exactly the approved diff, with the write token, on the
fixture GitHub API. When polling imports the merged pull request's commit on the default branch,
its Finding becomes Remediated."""

import hashlib
import json
import logging
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select

from conftest import Crash, FixtureBroker, application, check_now, connection, github_account, source_snapshot
from numen import domain, remediation
from numen.artifacts import publish
from numen.models import (
    Account, Action, Application, Commit, Finding, Job, JobEvent, RemediationPR, Repository, Setting, Snapshot,
    Transcript, now,
)
from numen.queue import recover
from test_analysis import CAPS, flag, started, state
from test_artifacts import finding as manual_finding
from test_commit_review import assessment, pinned_bundle
from test_intake import transport
from test_remediation import new_file
from numen.worker import run_once

SHOP = "https://github.com/acme/shop"
INTRODUCED, PARENT, HEAD = "a" * 40, "f" * 40, "e" * 40
VULNERABLE = {"main.py": b"def parse(value):\n    return eval(value)\n"}
# The default-branch head has moved on since the commit.
LATER = {**VULNERABLE, "later.py": b"x = 1\n"}
FIXED = {"main.py": b"def parse(value):\n    return str(value)\n"}
PATCH = (b"--- a/main.py\n+++ b/main.py\n@@ -1,2 +1,2 @@\n def parse(value):\n-    return eval(value)\n"
         b"+    return str(value)\n")
# Analysis' Alerts and Detection rule validations, and the drafts (bundle drafts among them), stay
# queued until drain().
QUEUED = ("notification", "detection_rule", "patch_drafting", "remediation_draft", "finding_artifacts")


def tree(app, repository_id, revision, files, head=False):
    """The snapshot of `revision` that intake keeps; the repository's head when `head`."""
    with app.state.factory.begin() as db:
        repository = db.get(Repository, repository_id)
        row = Snapshot(repository_id=repository_id, source_generation=repository.source_generation,
                       source_ref=revision, files=list(files))
        db.add(row)
        db.flush()
        publish(db, app.state.config.artifact_root, "snapshot", row.id, files)
        if head:
            repository.cursor = revision


def own(system, files=VULNERABLE, head=LATER):
    """An Application whose Own repository acme/shop holds commit INTRODUCED (`files`) and has
    moved on to HEAD (`head`), with a patch_drafting default profile: (application, commit id)."""
    app, client, _ = system
    profile = connection(app)
    with app.state.factory.begin() as db:
        setting = db.get(Setting, "global")
        setting.data = {**setting.data, "default_profiles": {**setting.data["default_profiles"], "patch_drafting": profile}}
    p = application(client, role="own", source_url=SHOP)
    ident = source_snapshot(app, p["id"], INTRODUCED, files=files)
    with app.state.factory.begin() as db:
        commit = db.get(Commit, ident)
        commit.data = {**commit.data, "parent_revisions": [PARENT]}
    tree(app, commit_repository(app, ident), HEAD, head, head=True)
    return p, ident


def commit_repository(app, ident):
    with app.state.factory() as db:
        return db.get(Commit, ident).repository_id


def agent(patch=PATCH, ref=INTRODUCED, **result):
    """Analysis finds Vulnerability introduced at `ref`; patch drafting writes `patch`."""
    def handler(call):
        if call["profile"]["operation"] == "patch_drafting":
            return {"summary": "Parses the value as a string instead of evaluating it", **result}, {"patch.diff": patch}
        return assessment("Vulnerability introduced", ref=ref), pinned_bundle(ref)
    return FixtureBroker(handler=handler)


def analysed(system, ident, broker):
    """Analyses commit `ident` by hand: the Finding it opened."""
    app, client, config = system
    queued = client.post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    assert run_once(config, app.state.factory, broker, exclude=QUEUED)
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "succeeded", job
    return client.get(f"/api/findings/{job['result']['finding_id']}").json()


def drain(system, broker):
    app, _, config = system
    while run_once(config, app.state.factory, broker, exclude=("notification", "detection_rule")):
        pass


def drafts(client, finding_id):
    return client.get(f"/api/findings/{finding_id}").json()["remediation_prs"]


def test_an_own_vulnerability_introduced_verdict_drafts_a_patch(system):
    app, client, _ = system
    p, ident = own(system)
    broker = agent()
    found = analysed(system, ident, broker)
    assert (found["own_repository"], found["remediation_actions"]) == (True, ["patch", "revert"])
    (draft,) = found["remediation_prs"]
    assert (draft["action"], draft["status"], draft["subject"], draft["revision"]) == ("patch", "drafting", ident, INTRODUCED)
    with app.state.factory() as db:
        job = db.get(Job, draft["job_id"])
        assert (job.kind, job.application_id) == ("patch_drafting", p["id"])
        assert job.input == {"remediation_pr_id": draft["id"], "finding_id": found["id"], "automatic": True, "shared": False}
        assert job.profile["agent"] == "pi"
    drain(system, broker)
    # One one-shot run with a 20-minute deadline, reading the default-branch head.
    call = broker.calls[-1]
    assert [c["profile"]["operation"] for c in broker.calls] == ["commit_analysis", "patch_drafting"]
    assert call["limits"] == {"timeout_seconds": 1200}
    assert call["files"]["source/later.py"] == LATER["later.py"]
    assert {"commit.json", "analysis-report.md"} <= set(call["files"])
    assert "/workspace/outputs/patch.diff" in call["prompt"]
    # The draft is git's own diff of the validated result: exactly what an Approval approves.
    (draft,) = drafts(client, found["id"])
    canonical = remediation.tree_diff({"main.py": LATER["main.py"]}, FIXED)
    assert (draft["status"], draft["base_ref"], draft["error"]) == ("ready", HEAD, None)
    assert draft["diff"] == canonical and "index " in canonical
    assert draft["diff_sha256"] == hashlib.sha256(canonical.encode()).hexdigest()
    assert (draft["paths"], draft["flags"]) == (["main.py"], [])
    assert draft["summary"] == "Parses the value as a string instead of evaluating it"
    assert client.get(f"/api/findings/{found['id']}").json()["status"] == "open"
    # A manual draft while one is running is refused; a ready one can be drafted again.
    again = client.post(f"/api/findings/{found['id']}/remediation-prs", json={"action": "patch"})
    assert again.status_code == 202, again.text
    busy = client.post(f"/api/findings/{found['id']}/remediation-prs", json={"action": "patch"})
    assert (busy.status_code, busy.json()["code"]) == (409, "remediation_busy")
    (draft,) = drafts(client, found["id"])
    assert (draft["status"], draft["diff"], draft["job_id"]) == ("drafting", None, again.json()["job_id"])


@pytest.mark.parametrize("patch,check", [
    (PATCH.replace(b"eval(value)", b"exec(value)"), "does not apply"),
    (new_file("../x").encode(), "not a safe relative path"),
    (new_file("/etc/passwd").encode(), "not a safe relative path"),
    (new_file(".git/config").encode(), "inside .git"),
    (new_file(".github/workflows/ci.yml").encode(), ".github/workflows"),
], ids=["does-not-apply", "dot-dot", "absolute", "dot-git", "workflows"])
def test_a_rejected_patch_is_a_failed_draft_before_any_github_call(system, monkeypatch, patch, check):
    app, client, _ = system
    monkeypatch.setenv("NUMEN_GITHUB_API_URL", "http://github.fixture")
    requests = []
    transport(monkeypatch, lambda request: requests.append(request) or httpx.Response(404))
    _, ident = own(system)
    broker = agent(patch)
    found = analysed(system, ident, broker)
    drain(system, broker)
    (draft,) = drafts(client, found["id"])
    assert (draft["status"], draft["error"]["code"]) == ("draft_failed", "diff_rejected")
    assert check in draft["error"]["message"], draft["error"]
    assert (draft["diff"], draft["diff_sha256"], draft["base_ref"]) == (None, None, None)
    assert requests == []
    # The rest of the Finding is unaffected.
    after = client.get(f"/api/findings/{found['id']}").json()
    assert (after["status"], after["artifact_state"]) == ("open", found["artifact_state"])


def test_patch_drafting_counts_against_the_analysis_caps(system):
    app, client, _ = system
    p, first = own(system)
    started(app, p["id"], CAPS["application"] - 1)
    found = analysed(system, first, agent())  # A manual Analysis is not counted.
    (draft,) = found["remediation_prs"]
    assert draft["status"] == "drafting"
    # The automatic patch draft took the Application's last place today.
    (later,) = flag(app, p["id"], "c" * 40)
    assert (state(client, later)["status"], state(client, later)["cap"]) == ("waiting_for_cap", "application")
    # Over the cap, the next automatic patch draft waits.
    second = source_snapshot(app, p["id"], "b" * 40, files=VULNERABLE)
    (waiting,) = analysed(system, second, agent(ref="b" * 40))["remediation_prs"]
    assert (waiting["status"], waiting["cap"], waiting["revision"]) == ("waiting_for_cap", "application", "b" * 40)
    assert waiting["since"] and "job_id" not in waiting
    with app.state.factory() as db:
        assert len(db.scalars(select(Action).where(Action.data["action"].as_string() == "analysis_cap_reached")).all()) == 1
    # A manual Draft patch is neither capped nor counted.
    third = source_snapshot(app, p["id"], "d" * 40, files=VULNERABLE)
    blocked = analysed(system, third, agent(ref="d" * 40))
    assert blocked["remediation_prs"][0]["status"] == "waiting_for_cap"
    manual = client.post(f"/api/findings/{blocked['id']}/remediation-prs", json={"action": "patch"})
    assert manual.status_code == 202, manual.text
    with app.state.factory() as db:
        assert db.get(Job, manual.json()["job_id"]).input["automatic"] is False
    # After 00:00 UTC the waiting change and the waiting draft start, oldest first.
    with app.state.factory.begin() as db:
        for job in db.scalars(select(Job)):
            job.created_at -= timedelta(days=1)
    with app.state.factory.begin() as db:
        domain.schedule(db)
    assert state(client, later)["status"] == "queued"
    (resumed,) = drafts(client, waiting["finding_id"])
    assert resumed["status"] == "drafting" and "cap" not in resumed
    with app.state.factory() as db:
        job = db.get(Job, resumed["job_id"])
        assert (job.kind, job.input["automatic"]) == ("patch_drafting", True)


# The Malicious change adds a payload and a workflow; its parent is the clean tree.
CLEAN = {"main.py": b"def parse(value):\n    return str(value)\n", "README.md": b"# Shop\n"}
PAYLOAD = {**CLEAN, "main.py": b"import loader\ndef parse(value):\n    return str(value)\n", "loader.py": b"steal()\n",
           ".github/workflows/ci.yml": b"on: push\njobs: {}\n"}


def test_an_own_malicious_change_drafts_a_revert(system):
    app, client, _ = system
    head = {**PAYLOAD, "later.py": b"x = 1\n"}
    _, ident = own(system, files=PAYLOAD, head=head)
    tree(app, commit_repository(app, ident), PARENT, CLEAN)
    rule = b'rule loader { strings: $a = "steal()" condition: $a }'
    broker = FixtureBroker(assessment("Malicious change", ref=INTRODUCED),
                           {"report.md": b"# A loader", "detection-rule.yar": rule})
    found = analysed(system, ident, broker)
    assert found["remediation_actions"] == ["revert"]
    (draft,) = found["remediation_prs"]
    assert (draft["action"], draft["status"]) == ("revert", "drafting")
    drain(system, broker)
    # The revert is application code: no agent run drafts it.
    assert [call["profile"]["operation"] for call in broker.calls] == ["commit_analysis"]
    (draft,) = drafts(client, found["id"])
    assert (draft["status"], draft["base_ref"], draft["error"]) == ("ready", HEAD, None)
    assert draft["flags"] == ["workflows"]
    assert sorted(draft["paths"]) == [".github/workflows/ci.yml", "loader.py", "main.py"]
    assert draft["diff_sha256"] == hashlib.sha256(draft["diff"].encode()).hexdigest()
    # It applies to the default-branch head and leaves the parent's tree plus the later work.
    applied = remediation.apply_diff(draft["diff"], head, workflows=True)
    result = {p: d for p, d in head.items() if p not in applied["deleted"]} | applied["changed"]
    assert result == {**CLEAN, "later.py": b"x = 1\n"}
    # A Malicious change is never patched.
    refused = client.post(f"/api/findings/{found['id']}/remediation-prs", json={"action": "patch"})
    assert (refused.status_code, refused.json()["code"]) == (422, "remediation_unavailable")


def test_without_an_own_repository_remediation_prs_are_skipped(system):
    app, client, _ = system
    connection(app)
    p = application(client)  # An Upstream repository only
    ident = source_snapshot(app, p["id"], INTRODUCED, files=VULNERABLE)
    found = analysed(system, ident, agent())
    assert (found["own_repository"], found["remediation_actions"], found["remediation_prs"]) == (False, [], [])
    assert {s["step"]: s["status"] for s in found["playbook"]}["remediation_pr"] == "no_own_repository"
    with app.state.factory.begin() as db:
        assert domain.draft_remediation(db, db.get(Application, p["id"]), db.get(Finding, found["id"]), ident, "patch",
                                        INTRODUCED, automatic=True) is None
        assert not db.scalars(select(Job).where(Job.kind.in_(["patch_drafting", "remediation_draft"]))).all()
    refused = client.post(f"/api/findings/{found['id']}/remediation-prs", json={"action": "patch"})
    assert refused.status_code == 422
    assert refused.json() == {"code": "remediation_unavailable", "retryable": False,
                                       "message": "No Own repository: Remediation PR steps are skipped"}
    # With an Own repository, an Upstream Verdict drafts its pin once Exposure knows the release to
    # pin (A06): this repository's tags cannot be read, so there is none, and nothing is drafted.
    linked = client.post(f"/api/applications/{p['id']}/repositories",
                         json={"role": "own", "source_kind": "github", "source_url": SHOP})
    assert linked.status_code == 201, linked.text
    found = analysed(system, ident, agent())
    assert (found["own_repository"], found["remediation_actions"], found["remediation_prs"]) == (True, [], [])
    assert found["exposure"]["state"] == "unknown" and found["exposure"]["target"] is None
    assert {s["step"]: s["status"] for s in found["playbook"]}["remediation_pr"] == "no_safe_release"
    with app.state.factory() as db:
        assert not db.scalars(select(Job).where(Job.kind.in_(["patch_drafting", "remediation_draft"]))).all()
    refused = client.post(f"/api/findings/{found['id']}/remediation-prs", json={"action": "revert"})
    assert refused.json()["message"] == (
        "Only a Vulnerability introduced or Malicious change commit of the Own repository gets a patch or revert, "
        "and an exposed Upstream Verdict a pin or bump once its release is known")


def test_a_bump_draft_edits_package_json_and_the_lockfile(system, monkeypatch):
    app, client, _ = system
    monkeypatch.setenv("NUMEN_NPM_REGISTRY_URL", "http://npm.fixture")
    dist = {"tarball": "http://npm.fixture/left-pad/-/left-pad-1.3.0.tgz", "integrity": "sha512-fixture"}
    requests = []
    transport(monkeypatch, lambda request: requests.append(request) or httpx.Response(
        200, json={"name": "left-pad", "version": "1.3.0", "dist": dist}))
    manifest = json.dumps({"name": "shop", "dependencies": {"left-pad": "^1.1.0"}}, indent=2).encode() + b"\n"
    lock = json.dumps({"name": "shop", "lockfileVersion": 3, "packages": {
        "": {"name": "shop", "dependencies": {"left-pad": "^1.1.0"}},
        "node_modules/left-pad": {"version": "1.1.0", "resolved": "old", "integrity": "sha512-old"}}}, indent=2).encode()
    head = {**LATER, "package.json": manifest, "package-lock.json": lock}
    p, _ = own(system, head=head)
    found = manual_finding(client, p["id"])
    dependency = {"ecosystem": "npm", "name": "left-pad", "version": "1.3.0"}
    with app.state.factory.begin() as db:
        draft = domain.draft_remediation(db, db.get(Application, p["id"]), db.get(Finding, found["id"]),
                                         "GHSA-fixture", "bump", HEAD, dependency=dependency)
        assert (draft.status, draft.data["dependency"]) == ("drafting", dependency)
    broker = FixtureBroker()
    drain(system, broker)
    assert broker.calls == []
    assert [(r.url.host, r.url.path) for r in requests] == [("npm.fixture", "/left-pad/1.3.0")]
    (draft,) = drafts(client, found["id"])
    assert (draft["status"], draft["action"], draft["base_ref"]) == ("ready", "bump", HEAD)
    assert sorted(draft["paths"]) == ["package-lock.json", "package.json"]
    assert draft["summary"] == "Bumps left-pad to 1.3.0"
    applied = remediation.apply_diff(draft["diff"], head)["changed"]
    assert json.loads(applied["package.json"])["dependencies"] == {"left-pad": "^1.3.0"}
    locked = json.loads(applied["package-lock.json"])["packages"]
    assert locked["node_modules/left-pad"] == {"version": "1.3.0", "resolved": dist["tarball"], "integrity": "sha512-fixture"}


def test_the_write_token_never_reaches_a_patch_drafting_run(system):
    app, client, _ = system
    write = "github_pat_fixture-write-token-0123456789"
    p, ident = own(system)
    with app.state.factory.begin() as db:
        db.add(Account(label="GitHub write", provider="github_write", auth_type="api_key",
                       credential=app.state.vault.encrypt({"api_key": write}),
                       data={"status": "unchecked", "models": [], "usage": None}))
    broker = agent()
    found = analysed(system, ident, broker)
    drain(system, broker)
    assert [call["profile"]["operation"] for call in broker.calls] == ["commit_analysis", "patch_drafting"]
    for call in broker.calls:
        assert write not in json.dumps({k: call[k] for k in ("prompt", "profile", "policy", "limits")})
        assert not any(write.encode() in data for data in call["files"].values())
    assert drafts(client, found["id"])[0]["status"] == "ready"
    # A checkout that holds the token fails the draft before any agent run.
    tree(app, commit_repository(app, ident), "d" * 40, {**LATER, "config.js": f"token = '{write}'\n".encode()}, head=True)
    queued = client.post(f"/api/findings/{found['id']}/remediation-prs", json={"action": "patch"})
    assert queued.status_code == 202, queued.text
    drain(system, broker)
    assert len(broker.calls) == 2
    (draft,) = drafts(client, found["id"])
    assert (draft["status"], draft["error"]["code"]) == ("draft_failed", "secret_in_input")
    after = client.get(f"/api/findings/{found['id']}").json()
    assert after["status"] == "open" and write not in json.dumps(after)
    assert write not in json.dumps(client.get(f"/api/jobs/{queued.json()['job_id']}").json())


# Opening the approved draft (A08): the Approval, the write token and the fixture GitHub API.
PASSWORD = "test-password-long"
READ, WRITE = "fixture-github-token", "github_pat_fixture-write-token-0123456789"
BRANCH = f"asset-monitor/{INTRODUCED[:7]}-patch"


def write_token(app):
    with app.state.factory.begin() as db:
        db.add(Account(label="GitHub write", provider="github_write", auth_type="api_key",
                       credential=app.state.vault.encrypt({"api_key": WRITE}),
                       data={"status": "unchecked", "models": [], "usage": None}))


def ready(system, github, token=True, modes=None, remote=LATER):
    """A ready patch draft of an Own-repository Finding whose head HEAD is on the fixture GitHub
    (holding `remote`), with the read token and, when `token`, the write token: (Finding, draft)."""
    app, client, _ = system
    github_account(app)
    if token:
        write_token(app)
    github.commit(HEAD, remote, modes)
    _, ident = own(system)
    broker = agent()
    found = analysed(system, ident, broker)
    drain(system, broker)
    (draft,) = drafts(client, found["id"])
    assert draft["status"] == "ready", draft
    return found, draft


def approve(client, draft, password=PASSWORD, digest=None):
    return client.post(f"/api/findings/{draft['finding_id']}/remediation-prs/{draft['id']}/approvals",
                       json={"password": password, "diff_sha256": digest or draft["diff_sha256"]})


def pr_jobs(app):
    with app.state.factory() as db:
        return db.scalars(select(Job).where(Job.kind == "remediation_pr")).all()


def test_an_approved_draft_opens_a_draft_pull_request_from_exactly_the_approved_diff(system, github):
    app, client, _ = system
    # main.py is executable on GitHub; the snapshot cannot tell, the base tree can.
    found, draft = ready(system, github, modes={"main.py": "100755"})
    assert github.requests == []
    approved = approve(client, draft)
    assert approved.status_code == 202, approved.text
    with app.state.factory() as db:
        job = db.get(Job, approved.json()["job_id"])
        assert (job.kind, job.input) == ("remediation_pr", {
            "remediation_pr_id": draft["id"], "finding_id": found["id"], "diff_sha256": draft["diff_sha256"]})
        assert job.profile is None
        (event,) = db.scalars(select(Action).where(Action.data["approved"].as_string() == "remediation_pr")).all()
        assert (event.resource_type, event.resource_id) == ("finding", found["id"])
        assert event.data == {"action": "approved", "approved": "remediation_pr", "remediation": "patch",
                              "remediation_pr_id": draft["id"], "diff_sha256": draft["diff_sha256"], "job_id": job.id}
    assert drafts(client, found["id"])[0]["status"] == "approved"
    drain(system, FixtureBroker())
    (opened,) = drafts(client, found["id"])
    assert (opened["status"], opened["error"]) == ("open", None)
    (pull,) = github.pulls
    assert (opened["branch"], opened["pull_number"], opened["pull_url"]) == (BRANCH, 1, pull["html_url"])
    assert (pull["head"]["ref"], pull["base"]["ref"], pull["draft"]) == (BRANCH, "main", True)
    assert pull["title"] == f"Asset Monitor patch of {INTRODUCED[:7]}"
    assert "Approval" in pull["body"] and "Parses the value" not in pull["body"]  # no agent text
    # One new commit on the base revision, holding exactly the approved diff, modes kept.
    head = github.refs[f"heads/{BRANCH}"]
    assert opened["head_sha"] == head and github.commits[head]["parents"] == [{"sha": HEAD}]
    assert draft["diff_sha256"] in github.commits[head]["message"]
    assert github.files(head) == {"main.py": ("100755", FIXED["main.py"]), "later.py": ("100644", LATER["later.py"])}
    assert github.writes() == [("POST", f"/repos/acme/shop/git/{kind}") for kind in ("blobs", "trees", "commits", "refs")] + [
        ("POST", "/repos/acme/shop/pulls")]
    assert set(github.refs) == {f"heads/{BRANCH}"}  # main is never written
    with app.state.factory() as db:
        (event,) = db.scalars(select(Action).where(Action.data["action"].as_string() == "remediation_pr_opened")).all()
        assert (event.resource_id, event.data["pull_url"], event.data["diff_sha256"]) == (
            found["id"], pull["html_url"], draft["diff_sha256"])
    # The Finding stays open until the Operator merges.
    assert client.get(f"/api/findings/{found['id']}").json()["status"] == "open"


def test_approving_twice_opens_one_pull_request(system, github):
    app, client, _ = system
    found, draft = ready(system, github)
    first, second = approve(client, draft), approve(client, draft)
    assert first.status_code == second.status_code == 202
    assert first.json()["job_id"] == second.json()["job_id"]
    assert len(pr_jobs(app)) == 1
    drain(system, FixtureBroker())
    third = approve(client, draft)
    assert (third.status_code, third.json()["job_id"]) == (202, first.json()["job_id"])
    drain(system, FixtureBroker())
    assert len(pr_jobs(app)) == 1
    assert github.writes().count(("POST", "/repos/acme/shop/pulls")) == 1 and len(github.pulls) == 1
    with app.state.factory() as db:
        assert len(db.scalars(select(Action).where(Action.data["approved"].as_string() == "remediation_pr")).all()) == 1


@pytest.mark.parametrize("crash", [("POST", "/git/refs"), ("POST", "/pulls")], ids=["after-ref", "after-pull"])
def test_a_recovered_job_reuses_the_branch_and_pull_request(system, github, crash):
    app, client, config = system
    found, draft = ready(system, github)
    assert approve(client, draft).status_code == 202
    github.crash_after = crash
    with pytest.raises(Crash):
        run_once(config, app.state.factory, FixtureBroker(), exclude=QUEUED)
    assert drafts(client, found["id"])[0]["status"] == "approved"
    with app.state.factory.begin() as db:
        (job,) = db.scalars(select(Job).where(Job.kind == "remediation_pr")).all()
        assert job.status == "running"
        job.lease_until = now() - timedelta(seconds=1)
    assert recover(app.state.factory, FixtureBroker()) == 1
    drain(system, FixtureBroker())
    writes = github.writes()
    assert writes.count(("POST", "/repos/acme/shop/git/refs")) == 1 and len(github.refs) == 1
    assert writes.count(("POST", "/repos/acme/shop/pulls")) == 1 and len(github.pulls) == 1
    (opened,) = drafts(client, found["id"])
    assert (opened["status"], opened["pull_number"], opened["head_sha"]) == ("open", 1, github.refs[f"heads/{BRANCH}"])
    # The recovered attempt found the branch by its name and wrote no second commit.
    assert writes.count(("POST", "/repos/acme/shop/git/commits")) == 1


def test_a_branch_holding_another_change_is_never_reused(system, github):
    _, client, _ = system
    found, draft = ready(system, github)
    github.commit("9" * 40, {"main.py": b"other\n"})
    github.refs[f"heads/{BRANCH}"] = "9" * 40
    assert approve(client, draft).status_code == 202
    drain(system, FixtureBroker())
    (failed,) = drafts(client, found["id"])
    assert (failed["status"], failed["error"]["code"]) == ("failed", "branch_exists")
    assert github.writes() == [] and github.pulls == []


def test_a_path_that_is_a_symlink_on_github_is_refused(system, github):
    _, client, _ = system
    found, draft = ready(system, github, modes={"main.py": "120000"})
    assert approve(client, draft).status_code == 202
    drain(system, FixtureBroker())
    (failed,) = drafts(client, found["id"])
    assert (failed["status"], failed["error"]["code"]) == ("failed", "diff_rejected")
    assert "symlink" in failed["error"]["message"]
    assert github.writes() == []


def test_without_the_write_token_the_pr_step_fails_visibly(system, github):
    app, client, _ = system
    found, draft = ready(system, github, token=False)
    # A second draft of the same Finding: the Cure-style revert to the commit's parent.
    tree(app, commit_repository(app, draft["subject"]), PARENT, {"main.py": FIXED["main.py"]})
    assert client.post(f"/api/findings/{found['id']}/remediation-prs", json={"action": "revert"}).status_code == 202
    drain(system, FixtureBroker())
    before = client.get(f"/api/findings/{found['id']}").json()
    other = next(r for r in before["remediation_prs"] if r["action"] == "revert")
    assert other["status"] == "ready"
    approved = approve(client, draft)
    assert approved.status_code == 202, approved.text
    drain(system, FixtureBroker())
    with app.state.factory() as db:
        job = db.get(Job, approved.json()["job_id"])
        assert (job.status, job.error["code"]) == ("failed", "github_write_token_required")
    after = client.get(f"/api/findings/{found['id']}").json()
    failed = next(r for r in after["remediation_prs"] if r["action"] == "patch")
    assert (failed["status"], failed["error"]["code"]) == ("failed", "github_write_token_required")
    assert "write token" in failed["error"]["message"]
    for key in ("status", "artifact_revision", "artifact_state", "lab_runs"):
        assert after[key] == before[key], key
    assert next(r for r in after["remediation_prs"] if r["action"] == "revert") == other
    assert github.requests == []
    # Like a Lab, a failed PR step is not retried: it needs a new Approval.
    retried = client.post(f"/api/jobs/{approved.json()['job_id']}/retry")
    assert (retried.status_code, retried.json()["code"]) == (409, "approval_required")
    # With the token added, approving again opens the pull request.
    write_token(app)
    again = approve(client, draft)
    assert again.status_code == 202 and again.json()["job_id"] != approved.json()["job_id"]
    drain(system, FixtureBroker())
    assert next(r for r in drafts(client, found["id"]) if r["action"] == "patch")["status"] == "open"
    assert len(github.pulls) == 1


def test_a_failed_draft_cannot_be_approved(system, github):
    app, client, _ = system
    github_account(app)
    write_token(app)
    _, ident = own(system)
    broker = agent(PATCH.replace(b"eval(value)", b"exec(value)"))
    found = analysed(system, ident, broker)
    (drafting,) = found["remediation_prs"]
    refused = approve(client, drafting, digest="0" * 64)
    assert (refused.status_code, refused.json()["code"]) == (409, "remediation_not_ready")
    drain(system, broker)
    (draft,) = drafts(client, found["id"])
    assert (draft["status"], draft["diff_sha256"]) == ("draft_failed", None)
    refused = approve(client, draft, digest="0" * 64)
    assert (refused.status_code, refused.json()["code"]) == (409, "remediation_not_ready")
    # A retried draft would only be discarded; it is drafted again from the Finding instead.
    retried = client.post(f"/api/jobs/{draft['job_id']}/retry")
    assert (retried.status_code, retried.json()["code"]) == (409, "job_not_retryable")
    assert pr_jobs(app) == [] and github.requests == []


def test_remediation_approval_needs_the_password_and_the_current_diff(system, github):
    app, client, _ = system
    found, draft = ready(system, github)
    url = f"/api/findings/{found['id']}/remediation-prs/{draft['id']}/approvals"
    missing = client.post(url, json={"diff_sha256": draft["diff_sha256"]})
    wrong = approve(client, draft, password="wrong-password")
    for refused in (missing, wrong):
        assert (refused.status_code, refused.json()["code"]) == (403, "approval_refused")
    stale = approve(client, draft, digest="0" * 64)
    assert (stale.status_code, stale.json()["code"]) == (409, "diff_changed")
    assert stale.json()["message"] == "The draft changed since you reviewed it; review the new diff"
    assert client.post(url, json={"password": PASSWORD, "diff_sha256": "not-a-hash"}).status_code == 422
    elsewhere = client.post(f"/api/findings/{manual_finding(client, found['application_id'])['id']}"
                            f"/remediation-prs/{draft['id']}/approvals",
                            json={"password": PASSWORD, "diff_sha256": draft["diff_sha256"]})
    assert elsewhere.status_code == 404
    assert pr_jobs(app) == [] and drafts(client, found["id"])[0]["status"] == "ready"
    assert approve(client, draft).status_code == 202
    # Straight after a good Approval, a wrong password is still refused.
    again = approve(client, draft, password="wrong-password")
    assert (again.status_code, again.json()["code"]) == (403, "approval_refused")
    assert len(pr_jobs(app)) == 1 and github.requests == []


def test_only_the_own_repository_receives_a_remediation_pr(system, github):
    app, client, _ = system
    found, draft = ready(system, github)
    upstream = client.post(f"/api/applications/{found['application_id']}/repositories", json={
        "role": "upstream", "source_kind": "github", "source_url": "https://github.com/demo/plugin"})
    assert upstream.status_code == 201, upstream.text
    upstream_id = upstream.json()["repository_id"]
    with app.state.factory.begin() as db:
        db.get(RemediationPR, draft["id"]).repository_id = upstream_id
    refused = approve(client, draft)
    assert (refused.status_code, refused.json()["code"]) == (409, "not_own_repository")
    assert pr_jobs(app) == []
    # Approved for the Own repository, then the Own link is removed before the job runs.
    with app.state.factory.begin() as db:
        db.get(RemediationPR, draft["id"]).repository_id = draft["repository_id"]
    assert approve(client, draft).status_code == 202
    removed = client.delete(f"/api/applications/{found['application_id']}/repositories/{draft['repository_id']}")
    assert removed.status_code in (200, 204), removed.text
    drain(system, FixtureBroker())
    (failed,) = drafts(client, found["id"])
    assert (failed["status"], failed["error"]["code"]) == ("failed", "not_own_repository")
    assert github.requests == []


def test_the_write_token_appears_only_on_pr_step_requests(system, github, caplog):
    app, client, _ = system
    caplog.set_level(logging.DEBUG)
    found, draft = ready(system, github)
    before = len(github.requests)
    assert approve(client, draft).status_code == 202
    drain(system, FixtureBroker())
    assert drafts(client, found["id"])[0]["status"] == "open"
    # The write token authorizes every PR step request and nothing before it; the read token no write.
    assert {token for _, _, token in github.requests[before:]} == {WRITE}
    assert all(token != WRITE for _, _, token in github.requests[:before])
    assert all(method == "GET" for method, _, token in github.requests if token == READ)
    with app.state.factory() as db:
        stored = [
            *[(j.input, j.result, j.error) for j in db.scalars(select(Job))],
            *[e.data for e in db.scalars(select(JobEvent))],
            *[a.data for a in db.scalars(select(Action))],
            *[(t.kind, t.data) for t in db.scalars(select(Transcript))],
            *[(r.diff, r.data) for r in db.scalars(select(RemediationPR))],
        ]
    assert WRITE not in json.dumps(stored, default=str)
    assert WRITE not in json.dumps(client.get(f"/api/findings/{found['id']}").json())
    assert WRITE not in caplog.text


# Merging (A08): the Operator merges; polling the Own repository's default branch sees it.
def opened(system, github):
    """An open Remediation PR on the fixture GitHub, whose default branch is at HEAD: (Finding, row)."""
    _, client, _ = system
    found, draft = ready(system, github)
    github.push(HEAD)
    assert approve(client, draft).status_code == 202
    drain(system, FixtureBroker())
    (row,) = drafts(client, found["id"])
    assert row["status"] == "open", row
    return found, row


def poll(system, application_id):
    """Check now on the Application's Own repository; the source check succeeds."""
    _, client, _ = system
    queued = check_now(client, application_id)
    drain(system, FixtureBroker())
    job = client.get(f"/api/jobs/{queued}").json()
    assert job["status"] == "succeeded", job
    return job


def pull_reads(github):
    return [token for method, path, token in github.requests if (method, path) == ("GET", "/repos/acme/shop/pulls/1")]


@pytest.mark.parametrize("how", ["merge", "squash"])
def test_a_merged_remediation_pr_remediates_its_finding(system, github, how):
    app, client, _ = system
    found, row = opened(system, github)
    pull, merged = github.pulls[0], "1" * 40
    pull.update(state="closed", merged=True, merge_commit_sha=merged)
    # GitHub's history does not show the merge commit yet: the next poll that imports it decides.
    github.push("2" * 40)
    poll(system, found["application_id"])
    assert pull_reads(github) == [WRITE]
    assert drafts(client, found["id"])[0]["status"] == "open"
    assert client.get(f"/api/findings/{found['id']}").json()["status"] == "open"
    # A merge commit over the pull request's head commit, or one squash commit, lands on main.
    github.push(*([row["head_sha"]] if how == "merge" else []), merged)
    poll(system, found["application_id"])
    (after,) = drafts(client, found["id"])
    assert (after["status"], after["merge_commit_sha"], after["error"]) == ("merged", merged, None)
    finding = client.get(f"/api/findings/{found['id']}").json()
    assert finding["status"] == "remediated"
    assert {k: v for k, v in finding["cause"].items() if k != "at"} == {
        "by": "remediation_pr", "remediation_pr_id": row["id"], "pull_request": pull["html_url"],
        "merge_commit": merged}
    with app.state.factory() as db:
        (event,) = db.scalars(select(Action).where(Action.data["action"].as_string() == "remediation_pr_merged")).all()
        assert (event.resource_id, event.data["merge_commit_sha"]) == (found["id"], merged)
    # A merged pull request is not read again.
    github.push("3" * 40)
    poll(system, found["application_id"])
    assert len(pull_reads(github)) == 2


def test_a_closed_pull_request_changes_nothing(system, github):
    app, client, _ = system
    found, row = opened(system, github)
    before = client.get(f"/api/findings/{found['id']}").json()
    # Without the write token the pull request cannot be read: the poll still succeeds.
    with app.state.factory.begin() as db:
        db.delete(db.scalar(select(Account).where(Account.provider == "github_write")))
    github.push("2" * 40)
    job = poll(system, found["application_id"])
    assert job["result"]["imported"] == 1 and pull_reads(github) == []
    (waiting,) = drafts(client, found["id"])
    assert (waiting["status"], waiting["error"]["code"]) == ("open", "github_write_token_required")
    # Closed without merging: the row is closed and the Finding unchanged.
    write_token(app)
    github.pulls[0].update(state="closed")
    github.push("3" * 40)
    poll(system, found["application_id"])
    (closed,) = drafts(client, found["id"])
    assert (closed["status"], closed["error"], closed["pull_number"]) == ("closed", None, 1)
    after = client.get(f"/api/findings/{found['id']}").json()
    assert (after["status"], after["cause"]) == (before["status"], before["cause"])
    assert [e for e in after["events"] if e.get("action") == "transition"] == []
    # A closed pull request is not read again, and no poll ever writes to GitHub.
    github.push("4" * 40)
    poll(system, found["application_id"])
    assert pull_reads(github) == [WRITE]
    assert github.writes().count(("POST", "/repos/acme/shop/pulls")) == 1


def test_an_own_vulnerability_fix_gets_no_remediation_pr(system):
    """A06's Own column gives a Vulnerability fix a report only: reverting it would bring the
    vulnerability back."""
    _, client, _ = system
    _, ident = own(system)
    broker = FixtureBroker(handler=lambda call: (assessment("Vulnerability fix", ref=INTRODUCED), pinned_bundle(INTRODUCED)))
    found = analysed(system, ident, broker)
    assert (found["own_repository"], found["remediation_actions"], found["remediation_prs"]) == (True, [], [])
    for action in ("patch", "revert"):
        refused = client.post(f"/api/findings/{found['id']}/remediation-prs", json={"action": action})
        assert (refused.status_code, refused.json()["code"]) == (422, "remediation_unavailable")


def test_a_revert_that_cannot_restore_every_changed_file_fails_its_draft(system):
    app, client, _ = system
    _, ident = own(system, files=PAYLOAD, head={**PAYLOAD, "later.py": b"x = 1\n"})
    tree(app, commit_repository(app, ident), PARENT, CLEAN)
    # The commit also added an image, which no snapshot holds.
    with app.state.factory.begin() as db:
        commit = db.get(Commit, ident)
        commit.data = {**commit.data, "files": [{"path": "main.py"}, {"path": "assets/logo.png", "status": "added"}]}
    broker = FixtureBroker(assessment("Malicious change", ref=INTRODUCED),
                           {"report.md": b"# A loader", "detection-rule.yar": b'rule loader { strings: $a = "steal()" condition: $a }'})
    found = analysed(system, ident, broker)
    drain(system, broker)
    (draft,) = drafts(client, found["id"])
    assert (draft["status"], draft["error"]["code"], draft["diff"]) == ("draft_failed", "revert_incomplete", None)
    assert "assets/logo.png" in draft["error"]["message"]


def test_a_waiting_patch_draft_fails_when_the_own_repository_is_replaced(system):
    app, client, _ = system
    p, ident = own(system)
    (draft,) = analysed(system, ident, agent())["remediation_prs"]
    with app.state.factory.begin() as db:
        row = db.get(RemediationPR, draft["id"])
        row.status, row.data = "waiting_for_cap", {**row.data, "since": now().isoformat(), "cap": "application"}
    removed = client.delete(f"/api/applications/{p['id']}/repositories/{draft['repository_id']}")
    assert removed.status_code in (200, 204), removed.text
    linked = client.post(f"/api/applications/{p['id']}/repositories",
                         json={"role": "own", "source_kind": "github", "source_url": "https://github.com/acme/other"})
    assert linked.status_code == 201, linked.text
    with app.state.factory.begin() as db:
        domain.start_waiting(db)
    (failed,) = drafts(client, draft["finding_id"])
    assert (failed["status"], failed["error"]["code"]) == ("draft_failed", "not_own_repository")
    assert failed["repository_id"] == draft["repository_id"]


def test_a_cancelled_remediation_pr_job_is_approved_again(system, github):
    app, client, config = system
    found, draft = ready(system, github)
    first = approve(client, draft).json()["job_id"]
    assert client.post(f"/api/jobs/{first}/cancel").status_code == 202
    (failed,) = drafts(client, found["id"])
    assert (failed["status"], failed["error"]["code"]) == ("failed", "cancelled")
    # A cancelling attempt whose lease expired, finalized by recovery, leaves it the same way.
    second = approve(client, draft).json()["job_id"]
    assert second != first
    github.crash_after = ("POST", "/git/refs")
    with pytest.raises(Crash):
        run_once(config, app.state.factory, FixtureBroker(), exclude=QUEUED)
    with app.state.factory.begin() as db:
        job = db.get(Job, second)
        job.status, job.lease_until = "cancelling", now() - timedelta(seconds=1)
    assert recover(app.state.factory, FixtureBroker()) == 1
    (failed,) = drafts(client, found["id"])
    assert (failed["status"], failed["error"]["code"]) == ("failed", "cancelled")
    # Approved again, it reuses the branch the cancelled attempt left: one pull request.
    third = approve(client, draft).json()["job_id"]
    assert third not in (first, second)
    drain(system, FixtureBroker())
    assert drafts(client, found["id"])[0]["status"] == "open"
    assert len(github.pulls) == 1 and github.writes().count(("POST", "/repos/acme/shop/git/refs")) == 1


def test_a_file_github_holds_differently_from_the_snapshot_is_never_pushed(system, github):
    _, client, _ = system
    # .gitattributes eol=crlf: the tarball's main.py has LF line endings, the repository's CRLF.
    found, draft = ready(system, github, remote={**LATER, "main.py": LATER["main.py"].replace(b"\n", b"\r\n")})
    assert approve(client, draft).status_code == 202
    drain(system, FixtureBroker())
    (failed,) = drafts(client, found["id"])
    assert (failed["status"], failed["error"]["code"]) == ("failed", "diff_rejected")
    assert ".gitattributes" in failed["error"]["message"]
    assert github.writes() == []


@pytest.mark.parametrize("source_ref,base", [("release", "release"), (None, "main")])
def test_the_pull_request_targets_the_branch_the_diff_was_drafted_on(system, github, source_ref, base):
    app, client, _ = system
    found, draft = ready(system, github)
    with app.state.factory.begin() as db:
        db.get(Repository, draft["repository_id"]).source_ref = source_ref
    assert approve(client, draft).status_code == 202
    drain(system, FixtureBroker())
    (pull,) = github.pulls
    assert pull["base"]["ref"] == base


def test_a_merge_whose_read_failed_remediates_on_a_later_quiet_poll(system, github):
    app, client, _ = system
    found, row = opened(system, github)
    merged = "1" * 40
    github.pulls[0].update(state="closed", merged=True, merge_commit_sha=merged)
    # The poll that imports the squash commit cannot read the pull request.
    with app.state.factory.begin() as db:
        db.delete(db.scalar(select(Account).where(Account.provider == "github_write")))
    github.push(merged)
    assert poll(system, found["application_id"])["result"]["imported"] == 1
    assert drafts(client, found["id"])[0]["status"] == "open"
    # Nothing new on the default branch (a 304), and the pull request is read again.
    write_token(app)
    assert poll(system, found["application_id"])["result"]["not_modified"] is True
    (after,) = drafts(client, found["id"])
    assert (after["status"], after["merge_commit_sha"], after["error"]) == ("merged", merged, None)
    assert client.get(f"/api/findings/{found['id']}").json()["status"] == "remediated"
