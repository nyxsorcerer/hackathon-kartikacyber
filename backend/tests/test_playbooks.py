"""Playbooks (A06, the Own and Upstream columns): each Verdict runs only the steps of its (role,
Verdict) cell, and a step that needs Approval waits, visibly, without blocking the others. An
Upstream Verdict's Remediation PR pins the newest release without the change, or bumps to the
first release that contains a fix, both chosen by tag containment in a local fixture repository
(git_repository). The Disclosure report is shown for copying and never sent (A15). No test reaches
github.com or a package registry."""

import json
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from conftest import FixtureBroker, application, connection, git_repository, source_snapshot
from numen import domain, remediation
from numen.artifacts import publish
from numen.models import (
    Application, ApplicationRepository, Commit, Job, JobEvent, LabRun, Notification, Repository, Setting,
    VersionRecipe,
)
from numen.sources import Sources
from numen.worker import run_once
from test_analysis import analyze
from test_artifacts import APPROVAL, automatic_bundle, upload, without_package
from test_commit_review import assessment, pinned_bundle
from test_dependencies import npm_files
from test_exposure import FIX, INTRODUCED, MALICIOUS, LIB, PACKAGE, REACT, RULE, library, react, upstream
from test_remediation_prs import HEAD, LATER, PARENT, QUEUED, SHOP, VULNERABLE, tree

# The Own repository's head depends on numen/lib and on React's react-dom and
# react-server-dom-webpack, locked at 19.0.0.
DEPENDENCIES = {"lib": "^1.1.0", "react-dom": "19.0.0", PACKAGE: "19.0.0"}
HEAD_FILES = {**LATER, **{path: text.encode() for path, text in npm_files(
    DEPENDENCIES, {"lib": "1.1.0", "react-dom": "19.0.0", PACKAGE: "19.0.0"}).items()}}
DISCLOSURE = b"# Disclosure marker: index.js loads an unchecked module\n<script>alert(1)</script>\n"


def shop(system, version, packages=("npm:lib",), url=LIB):
    """Shop: its Own repository acme/shop at HEAD (HEAD_FILES), with a patch_drafting profile, and
    the Upstream repository `url` locked at `version`, standing for `packages`. (Application id,
    Own repository id, Upstream repository id)"""
    app, client, _ = system
    profile = connection(app)
    with app.state.factory.begin() as db:
        setting = db.get(Setting, "global")
        setting.data = {**setting.data, "default_profiles": {**setting.data["default_profiles"], "patch_drafting": profile}}
    ident = application(client, asset_name="Shop", role="own", source_url=SHOP)["id"]
    linked = client.post(f"/api/applications/{ident}/repositories",
                         json={"source_kind": "github", "source_url": url, "locked_version": version})
    assert linked.status_code == 201, linked.text
    with app.state.factory.begin() as db:
        link = db.scalar(select(ApplicationRepository).where(
            ApplicationRepository.application_id == ident, ApplicationRepository.role == "upstream"))
        link.packages = list(packages)
        own = db.scalar(select(Repository.id).where(Repository.source_url == SHOP))
    tree(app, own, HEAD, HEAD_FILES, head=True)
    return ident, own, linked.json()["repository_id"]


def commit(app, application_id, repository_id, revision, parent, files=None):
    """The stored commit `revision` of `repository_id`, whose parent is `parent`: its id."""
    ident = source_snapshot(app, application_id, revision, repository_id=repository_id, files=files)
    with app.state.factory.begin() as db:
        row = db.get(Commit, ident)
        row.data = {**row.data, "parent_revisions": [parent]}
    return ident


def analyse(system, ident, verdict, ref):
    """Analyses commit `ident` to `verdict` at `ref`. A Malicious change drafts its report and
    Detection rule; any other Verdict the pinned bundle and a Disclosure report. (The Finding, the
    broker)"""
    _, client, _ = system
    outputs = ({"report.md": b"# A loader", "detection-rule.yar": RULE} if verdict == MALICIOUS
               else {**pinned_bundle(ref), "disclosure-report.md": DISCLOSURE})
    job, broker = analyze(system, ident, assessment(verdict, ref=ref), outputs)
    assert job["status"] == "succeeded", job
    (finding_id,) = job["result"]["finding_ids"]
    return client.get(f"/api/findings/{finding_id}").json(), broker


def steps(finding):
    return {row["step"]: row["status"] for row in finding["playbook"]}


def own_head_bundle(system, finding_id, ref):
    """Shop's Upstream Proof builds its Own repository's head with the Locked version installed
    (A07), which the Analysis did not draft for: it gets the reports, and the automatic bundle draft
    queued for that app completes it. The Finding."""
    job, _ = automatic_bundle(system, finding_id, without_package(pinned_bundle(ref)))
    assert job["status"] == "succeeded", job
    drafted = system[1].get(f"/api/findings/{finding_id}").json()
    assert drafted["artifact_state"]["status"] == "complete", drafted["artifact_state"]
    return drafted


def registry(monkeypatch):
    """The npm registry (NUMEN_NPM_REGISTRY_URL) a pin or bump reads, holding every version: the
    (name, version) pairs asked for."""
    asked = []

    def npm_version(self, name, version):
        asked.append((name, version))
        return {"name": name, "version": version, "dist": {
            "tarball": f"http://npm.fixture/{name}/-/{name}-{version}.tgz", "integrity": f"sha512-{name}-{version}"}}

    monkeypatch.setattr(Sources, "npm_version", npm_version)
    return asked


def drain(system, broker, exclude=("notification", "detection_rule", "finding_artifacts")):
    """Runs every queued job but Alerts, Detection rule validations and bundle drafts (which
    own_head_bundle runs): Remediation PR drafts, never a Lab or a PR step, which only an Approval
    queues."""
    app, _, config = system
    while run_once(config, app.state.factory, broker, exclude=exclude):
        pass


def kinds(app):
    with app.state.factory() as db:
        return sorted(job.kind for job in db.scalars(select(Job)))


CELLS = [
    ("own", INTRODUCED, ["proof", "report", "remediation_pr"], ["patch"], 202),
    ("own", MALICIOUS, ["static_proof", "detection_rule", "remediation_pr", "cleanup_report"], ["revert"], 409),
    ("own", FIX, ["report", "deployed_version_check"], [], 409),
    ("upstream", INTRODUCED, ["proof", "disclosure_report", "remediation_pr"], ["pin"], 202),
    ("upstream", MALICIOUS, ["static_proof", "detection_rule", "cleanup_report", "remediation_pr"], ["pin"], 409),
    ("upstream", FIX, ["proof", "remediation_pr"], ["bump"], 202),
]


@pytest.mark.parametrize("role,verdict,cell,actions,lab", CELLS, ids=[f"{r}-{v}" for r, v, *_ in CELLS])
def test_each_verdict_runs_only_the_steps_in_its_cell(system, tmp_path, role, verdict, cell, actions, lab):
    app, client, _ = system
    repo, change = library(tmp_path / "git")
    # An exposed Upstream Application: a fix that v1.0.0 lacks, a change that v1.1.0 contains.
    ident, own, lib = shop(system, "1.0.0" if verdict == FIX else "1.1.0")
    if role == "own":
        revision, parent = "a" * 40, PARENT
        commit_id = commit(app, ident, own, revision, parent, VULNERABLE)
    else:
        revision, parent = change, repo.git("rev-parse", "v1.0.0^{commit}")
        commit_id = commit(app, ident, lib, revision, parent)
    finding, _ = analyse(system, commit_id, verdict, parent if verdict == FIX else revision)
    assert [row["step"] for row in finding["playbook"]] == cell
    assert [row["action"] for row in finding["remediation_prs"]] == actions
    # Only an Upstream Vulnerability introduced shows the Disclosure report the agent drafted.
    assert (finding["disclosure_report"] is not None) is ((role, verdict) == ("upstream", INTRODUCED))
    assert (finding["exposure"] or {}).get("state") == (None if role == "own" else "exposed")
    if role == "upstream" and "proof" in cell:
        assert steps(finding)["proof"] == "draft"
        own_head_bundle(system, finding["id"], revision)
    started = client.post(f"/api/findings/{finding['id']}/lab-runs", json=APPROVAL)
    assert started.status_code == lab, started.text
    if lab == 409:
        assert started.json()["code"] == "lab_not_allowed"
    # No other side effect: one Alert, the Detection rule validation of a Malicious change, the
    # cell's one Remediation PR draft, and a Lab only where the cell has a Proof.
    expected = ["commit_analysis", "notification"]
    expected += ["detection_rule"] if verdict == MALICIOUS else []
    expected += ["patch_drafting"] if actions == ["patch"] else ["remediation_draft"] if actions else []
    expected += ["lab_run"] if lab == 202 else []
    # An Upstream Proof's Lab builds Shop's head, which its automatic bundle draft is for.
    expected += ["finding_artifacts"] if role == "upstream" and "proof" in cell else []
    assert kinds(app) == sorted(expected)
    with app.state.factory() as db:
        assert db.scalar(select(func.count(Notification.id))) == 1
        assert db.scalar(select(func.count(LabRun.id))) == (1 if lab == 202 else 0)


def test_a_step_that_needs_approval_waits_visibly_without_blocking_the_others(system, tmp_path, monkeypatch):
    app, client, _ = system
    registry(monkeypatch)
    _, change = library(tmp_path / "git")
    ident, _, lib = shop(system, "1.1.0")
    finding, broker = analyse(system, commit(app, ident, lib, change, PARENT), INTRODUCED, change)
    assert steps(finding) == {"proof": "draft", "disclosure_report": "ready", "remediation_pr": "drafting"}
    own_head_bundle(system, finding["id"], change)
    # The pin drafts while the Proof waits for its Approval.
    drain(system, broker)
    finding = client.get(f"/api/findings/{finding['id']}").json()
    assert steps(finding) == {"proof": "waiting_for_approval", "disclosure_report": "ready",
                              "remediation_pr": "ready"}
    (pin,) = finding["remediation_prs"]
    assert (pin["action"], pin["summary"], sorted(pin["paths"])) == (
        "pin", "Pins lib to 1.0.0", ["package-lock.json", "package.json"])
    assert finding["remediation_actions"] == ["pin"]
    assert finding["disclosure_report"]["text"] == DISCLOSURE.decode()
    # Nothing ran that needs an Approval: no Lab and no pull request.
    assert "lab_run" not in kinds(app) and "remediation_pr" not in kinds(app)
    # Approving the Lab leaves the pin waiting for its own Approval.
    assert client.post(f"/api/findings/{finding['id']}/lab-runs", json=APPROVAL).status_code == 202
    finding = client.get(f"/api/findings/{finding['id']}").json()
    assert steps(finding) == {"proof": "queued", "disclosure_report": "ready", "remediation_pr": "ready"}


def test_without_an_own_repository_upstream_remediation_steps_are_skipped(system, tmp_path):
    app, client, _ = system
    connection(app)
    _, change = library(tmp_path / "git")
    blog = upstream(client, "Blog", "1.1.0", LIB)
    with app.state.factory.begin() as db:
        link = db.scalar(select(ApplicationRepository).where(ApplicationRepository.application_id == blog))
        link.packages, lib = ["npm:lib"], link.repository_id
    finding, _ = analyse(system, commit(app, blog, lib, change, PARENT), INTRODUCED, change)
    # The release to pin is known, but there is no Own repository to pin it in.
    assert finding["exposure"]["target"] == {"tag": "v1.0.0", "version": "1.0.0"}
    assert steps(finding)["remediation_pr"] == "no_own_repository"
    assert (finding["own_repository"], finding["remediation_actions"], finding["remediation_prs"]) == (False, [], [])
    assert not {"patch_drafting", "remediation_draft"} & set(kinds(app))
    refused = client.post(f"/api/findings/{finding['id']}/remediation-prs", json={"action": "pin"})
    assert (refused.status_code, refused.json()["message"]) == (422, "No Own repository: Remediation PR steps are skipped")


def test_an_upstream_malicious_change_pins_the_latest_release_without_it(system, tmp_path, monkeypatch):
    app, client, _ = system
    asked = registry(monkeypatch)
    repo = git_repository(tmp_path / "git", "numen/lib")
    base = repo.commit("Release 1.0.0", {"index.js": "module.exports = 1;\n"})
    repo.tag("v1.0.0")
    change = repo.commit("Add a loader", {"loader.js": "require('child_process').exec(process.env.X);\n"})
    repo.tag("v1.1.0")
    repo.branch("1.0.x", base)
    repo.commit("Release 1.0.1", {"CHANGELOG.md": "1.0.1\n"})
    repo.tag("v1.0.1")
    repo.cherry_pick(change)  # the payload reaches the maintenance line as well
    repo.tag("v1.0.2")
    ident, _, lib = shop(system, "1.1.0")
    with app.state.factory.begin() as db:
        db.get(Repository, lib).watched_branches = {"1.0.x": {}}
    finding, broker = analyse(system, commit(app, ident, lib, change, base), MALICIOUS, change)
    # v1.0.2 is the highest version below v1.1.0, but tag containment finds the payload in it: the
    # safe version is v1.0.1, the newest release without it.
    assert finding["exposure"]["target"] == {"tag": "v1.0.1", "version": "1.0.1"}
    assert finding["cleanup_report"]["releases"] == ["v1.0.2", "v1.1.0"]
    (pin,) = finding["remediation_prs"]
    assert (pin["action"], pin["dependency"]) == ("pin", {"ecosystem": "npm", "names": ["lib"], "version": "1.0.1"})
    drain(system, broker)
    (pin,) = client.get(f"/api/findings/{finding['id']}").json()["remediation_prs"]
    assert (pin["status"], pin["summary"]) == ("ready", "Pins lib to 1.0.1")
    assert asked == [("lib", "1.0.1")]
    applied = remediation.apply_diff(pin["diff"], HEAD_FILES)["changed"]
    assert json.loads(applied["package.json"])["dependencies"]["lib"] == "1.0.1"


def test_the_react2shell_fix_bumps_to_the_first_release_that_contains_it(system, tmp_path, monkeypatch):
    app, client, config = system
    asked = registry(monkeypatch)
    repo, release, fix = react(tmp_path / "git")
    # The React monorepo link stands for both of the Application's React packages.
    ident, _, react_id = shop(system, "19.0.0", ("npm:react-dom", f"npm:{PACKAGE}"), REACT)
    finding, broker = analyse(system, commit(app, ident, react_id, fix, release), FIX, release)
    assert (finding["exposure"]["state"], finding["exposure"]["reason"]) == ("exposed", "no release contains the fix yet")
    # No release contains the fix yet: the bump waits for one. Shop's Proof waits for its own bundle.
    assert steps(finding) == {"proof": "draft", "remediation_pr": "waiting_for_release"}
    assert (finding["remediation_prs"], finding["remediation_actions"]) == ([], [])
    # The fix is backported to the 19.x Release branch and tagged v19.0.1.
    repo.branch("19.x", release)
    backport = repo.cherry_pick(fix)
    repo.tag("v19.0.1")
    # The next source check that is not a 304 sees the Release branch and checks Exposure again.
    monkeypatch.setattr(Sources, "github_branch", lambda self, repository, name: name == "19.x")
    monkeypatch.setattr(Sources, "github_commits", lambda self, repository, branch=None, cursor=None, etag=None: (
        backport if branch else fix, [], f'"{branch or "main"}"'))
    with app.state.factory.begin() as db:
        checked = domain.enqueue(db, "source_check", db.get(Application, ident),
                                 domain.repository_input(db.get(Repository, react_id))).id
    assert run_once(config, app.state.factory, broker, exclude=QUEUED)
    assert client.get(f"/api/jobs/{checked}").json()["status"] == "succeeded"
    with app.state.factory() as db:
        (job,) = db.scalars(select(Job).where(Job.kind == "exposure_check"))
        assert (job.application_id, job.input["repository_id"], job.status) == (ident, react_id, "queued")
    assert run_once(config, app.state.factory, broker, exclude=QUEUED)
    finding = client.get(f"/api/findings/{finding['id']}").json()
    exposure = finding["exposure"]
    assert (exposure["state"], exposure["reason"], exposure["target"]) == (
        "exposed", "v19.0.0 does not contain the fix", {"tag": "v19.0.1", "version": "19.0.1"})
    assert steps(finding)["remediation_pr"] == "drafting"
    # The bump drafts to the first release that contains the fix, ready for Approval.
    drain(system, broker)
    finding = client.get(f"/api/findings/{finding['id']}").json()
    (bump,) = finding["remediation_prs"]
    assert (bump["action"], bump["status"], bump["summary"]) == (
        "bump", "ready", f"Bumps react-dom, {PACKAGE} to 19.0.1")
    assert sorted(bump["paths"]) == ["package-lock.json", "package.json"]
    assert asked == [("react-dom", "19.0.1"), (PACKAGE, "19.0.1")]
    applied = remediation.apply_diff(bump["diff"], HEAD_FILES)["changed"]
    assert json.loads(applied["package.json"])["dependencies"] == {**DEPENDENCIES, "react-dom": "19.0.1", PACKAGE: "19.0.1"}
    locked = json.loads(applied["package-lock.json"])["packages"][f"node_modules/{PACKAGE}"]
    assert locked == {"version": "19.0.1", "resolved": f"http://npm.fixture/{PACKAGE}/-/{PACKAGE}-19.0.1.tgz",
                      "integrity": f"sha512-{PACKAGE}-19.0.1"}
    assert (steps(finding)["remediation_pr"], finding["remediation_actions"], finding["status"]) == ("ready", ["bump"], "open")
    # A second Application locked at 19.0.1, the backport's release, is not exposed.
    upstream(client, "Blog", "19.0.1")
    assert run_once(config, app.state.factory, broker, exclude=QUEUED)
    exposures = {row["application_name"]: row for row in client.get(f"/api/commits/{finding['source_commit_id']}").json()["exposures"]}
    assert (exposures["Blog"]["state"], exposures["Blog"]["reason"]) == ("not_exposed", "v19.0.1 contains the fix")
    assert [f["application_id"] for f in client.get("/api/findings").json()["items"]] == [ident]
    # A {package}@ release moves only the package it names.
    with app.state.factory() as db:
        assert domain.upstream_dependency(db, db.get(Application, ident), db.get(Repository, react_id), {
            "tag": f"{PACKAGE}@19.0.2", "version": "19.0.2"}) == {"ecosystem": "npm", "names": [PACKAGE], "version": "19.0.2"}


def test_an_upstream_vulnerability_introduced_shows_its_disclosure_report_and_never_sends_it(
        system, tmp_path, monkeypatch, github):
    app, client, _ = system
    registry(monkeypatch)
    _, change = library(tmp_path / "git")
    ident, _, lib = shop(system, "1.1.0")
    finding, broker = analyse(system, commit(app, ident, lib, change, PARENT), INTRODUCED, change)
    # The Analysis is told to draft it for an Upstream repository.
    prompt = broker.calls[0]["prompt"]
    assert json.loads(prompt.rsplit("\n\nFacts:\n", 1)[1])["upstream"] is True and "disclosure-report.md" in prompt
    assert finding["disclosure_report"] == {
        "text": DISCLOSURE.decode(), "form_url": "https://github.com/numen/lib/security/advisories/new"}
    drain(system, broker)
    # The bundle drafted for Shop's head, which the agent writes without one, keeps the Disclosure report.
    drafted = own_head_bundle(system, finding["id"], change)
    assert (drafted["disclosure_report"], steps(drafted)["disclosure_report"]) == (finding["disclosure_report"], "ready")
    monkeypatch.setattr(Sources, "npm_tarball", lambda self, dist: b"lib 1.1.0")
    # It goes nowhere else: not even an approved Lab gets it, and no Alert, job or GitHub request
    # carries it.
    assert client.post(f"/api/findings/{finding['id']}/lab-runs", json=APPROVAL).status_code == 202
    lab = FixtureBroker({"verified": False, "status": "not_reproduced"})
    drain(system, lab)
    ((kind, files),) = [(call["kind"], call["files"]) for call in lab.calls]
    assert kind == "lab" and "poc.py" in files and "disclosure-report.md" not in files
    assert len(broker.calls) == 1 and github.requests == []
    marker = "Disclosure marker"
    with app.state.factory() as db:
        assert db.scalar(select(func.count(Notification.id))) == 1
        for row in [*db.scalars(select(Notification)), *db.scalars(select(JobEvent))]:
            assert marker not in json.dumps(row.data, default=str)
        for job in db.scalars(select(Job)):
            assert marker not in json.dumps([job.input, job.result], default=str), job.kind
    # It is read from the current revision as text, at most 64 KiB of it.
    uploaded = upload(client, finding["id"], {"disclosure-report.md": b"\xff" + b"x" * 70_000})
    assert uploaded.status_code == 200, uploaded.text
    text = uploaded.json()["disclosure_report"]["text"]
    assert len(text) == 64 * 1024 and text.startswith("�x")


def own_release(system, tmp_path):
    """Shop (shop()), whose Own repository acme/shop released v1.0.0, then two Vulnerability fixes,
    then v1.1.0, and has an active version recipe. Its Upstream numen/lib (library()) is locked at
    1.0.0, which lacks lib's change. (Application id, Own repository id, Upstream repository id,
    the v1.0.0 commit, the two fixes, numen/lib's fixture repository and change)"""
    app, _, config = system
    repo = git_repository(tmp_path / "git", "acme/shop")
    base = repo.commit("Release 1.0.0", {"main.py": "def parse(value):\n    return eval(value)\n"})
    repo.tag("v1.0.0")
    fixes = (repo.commit("Parse safely", {"main.py": "def parse(value):\n    return str(value)\n"}),
             repo.commit("Reject long input", {"limit.py": "LIMIT = 64\n"}))
    repo.tag("v1.1.0")
    lib_repo, change = library(tmp_path / "git")
    ident, own, lib = shop(system, "1.0.0")
    with app.state.factory.begin() as db:
        row = db.get(Application, ident)
        recipe = VersionRecipe(application_id=ident, source_generation=row.source_generation,
                               source_ref="a" * 40, status="active", data={})
        db.add(recipe)
        db.flush()
        publish(db, config.artifact_root, "recipe", recipe.id,
                {"determine_version.py": b"print('script')", "recipe.json": b"{}"})
        row.config = {**row.config, "active_recipe_id": recipe.id}
    return ident, own, lib, base, fixes, lib_repo, change


def version_check(system, ident, observed):
    """Runs the Application's version check, whose probe reports `observed`: the observation id."""
    app, client, config = system
    queued = client.post(f"/api/applications/{ident}/version-checks")
    assert queued.status_code == 202, queued.text
    probe = {"version": None, "candidates": [], "method": "html_markers", "evidence": ["page"], "limitations": [],
             **observed}
    assert run_once(config, app.state.factory, FixtureBroker(probe), exclude=QUEUED)
    job = client.get(f"/api/jobs/{queued.json()['job_id']}").json()
    assert job["status"] == "succeeded", job
    return job["result"]["observation_id"]


def cause(finding):
    return {k: v for k, v in finding["cause"].items() if k != "at"}


DEPLOYED = [
    ("before-the-fix", {"status": "detected", "version": "1.0.0"}, "before_fix", "v1.0.0 does not contain the fix"),
    ("serving-the-fix", {"status": "detected", "version": "v1.1.0"}, "serving_fix", "v1.1.0 contains the fix"),
    ("ambiguous", {"status": "ambiguous", "candidates": ["1.0.0", "1.1.0"]}, "unknown",
     "No fingerprint matches one version: the version check reported ambiguous"),
    ("unknown", {"status": "unknown"}, "unknown",
     "No fingerprint matches one version: the version check reported unknown"),
    ("no-tag", {"status": "detected", "version": "2.0.0"}, "unknown",
     "No release tag of the Own repository matches 2.0.0"),
    ("other-repository", {"status": "detected", "version": "1.1.0"}, "unknown",
     "The version recipe reads numen/lib, not the Own repository"),
]


@pytest.mark.parametrize("observed,state,reason", [row[1:] for row in DEPLOYED], ids=[row[0] for row in DEPLOYED])
def test_the_deployed_version_check_reports_before_the_fix_serving_the_fix_or_unknown(
        system, tmp_path, observed, state, reason):
    app, client, _ = system
    ident, own, lib, base, (fix, _), *_ = own_release(system, tmp_path)
    finding, _ = analyse(system, commit(app, ident, own, fix, base), FIX, base)
    # Opened before any version check: unknown, never a guess.
    assert (finding["deployed_version"], finding["deployed_version_check"]["reason"]) == (
        "unknown", "No version check has run")
    assert steps(finding) == {"report": "ready", "deployed_version_check": "unknown"}
    if reason.startswith("The version recipe reads"):
        # The recipe reads the repository linked first: make that the Upstream one.
        with app.state.factory.begin() as db:
            link = db.scalar(select(ApplicationRepository).where(ApplicationRepository.repository_id == lib))
            link.created_at = link.created_at - timedelta(days=1)
    observation = version_check(system, ident, observed)
    finding = client.get(f"/api/findings/{finding['id']}").json()
    check = finding["deployed_version_check"]
    assert (finding["deployed_version"], check["state"], check["reason"]) == (state, state, reason)
    assert (check["version"], check["observation_id"]) == (observed.get("version"), observation)
    assert steps(finding)["deployed_version_check"] == state
    if state == "serving_fix":
        assert finding["status"] == "remediated"
        assert cause(finding) == {"by": "deployed_version", "observation_id": observation, "version": "v1.1.0"}
    else:
        assert (finding["status"], finding["cause"]["by"]) == ("open", "verdict")
    (summary,) = client.get("/api/findings?view=summary").json()["items"]
    assert summary["deployed_version"] == state


def test_serving_the_fix_remediates_only_an_own_vulnerability_fix_finding(system, tmp_path):
    app, client, _ = system
    ident, own, lib, base, (fix, later), lib_repo, change = own_release(system, tmp_path)
    fixed, _ = analyse(system, commit(app, ident, own, fix, base), FIX, base)
    introduced, _ = analyse(system, commit(app, ident, own, "a" * 40, PARENT, VULNERABLE), INTRODUCED, "a" * 40)
    lib_base = lib_repo.git("rev-parse", "v1.0.0^{commit}")
    upstream_fix, _ = analyse(system, commit(app, ident, lib, change, lib_base), FIX, lib_base)
    assert upstream_fix["exposure"]["state"] == "exposed"
    observation = version_check(system, ident, {"status": "detected", "version": "1.1.0"})
    rows = {row["id"]: row for row in client.get("/api/findings").json()["items"]}
    assert rows[fixed["id"]]["status"] == "remediated"
    assert cause(rows[fixed["id"]]) == {"by": "deployed_version", "observation_id": observation, "version": "1.1.0"}
    # Neither an Own Vulnerability introduced nor an Upstream Vulnerability fix is remediated by it.
    for other in (introduced, upstream_fix):
        row = rows[other["id"]]
        assert (row["status"], row["cause"], row["deployed_version_check"], row["deployed_version"]) == (
            "open", other["cause"], None, "unknown")
    # A fix analysed after the observation is checked against it when its Finding opens.
    opened, _ = analyse(system, commit(app, ident, own, later, fix), FIX, fix)
    assert (opened["status"], cause(opened)) == (
        "remediated", {"by": "deployed_version", "observation_id": observation, "version": "1.1.0"})
    assert opened["deployed_version_check"]["state"] == "serving_fix"
