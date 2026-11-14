"""Exposure (A05): an Upstream Verdict reaches an Application only where release-tag containment at
its Locked version says so. Containment is read from a blobless bare mirror of a local fixture
repository (git_repository) or a local SVN repository; no test reaches github.com. A not-exposed
Verdict is recorded on the Upstream repository only (AC-A12)."""

import shutil
import subprocess
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from conftest import FixtureBroker, application, connection, git_repository, source_snapshot
from numen import domain, exposure
from numen.config import Config
from numen.models import (
    Application, ApplicationRepository, Artifact, Commit, Exposure, Finding, Job, Notification, RemediationPR,
    Repository,
)
from numen.security import DomainError
from numen.sources import Sources
from numen.worker import run_once
from numen.workflows import Workflows
from test_analysis import analyze
from test_commit_review import assessment, pinned_bundle
from test_dependencies import npm_files

FIX, INTRODUCED, MALICIOUS = "Vulnerability fix", "Vulnerability introduced", "Malicious change"
REACT = "https://github.com/numen/react"
PACKAGE = "react-server-dom-webpack"
SERVER = "packages/react-server-dom-webpack/src/ReactFlightDOMServerNode.js"


def react(base):
    """The numen/react stand-in: v19.0.0 on main, then the React2Shell fix commit. (repository,
    the v19.0.0 commit, the fix commit)."""
    repo = git_repository(base, "numen/react")
    release = repo.commit("Release 19.0.0", {SERVER: "export function decodeReply(body) {\n  return resolve(body);\n}\n"})
    repo.tag("v19.0.0")
    fix = repo.commit("Check that a server reference is the module's own", {
        SERVER: "export function decodeReply(body) {\n  if (!ownProperty(body)) throw new Error();\n  return resolve(body);\n}\n"})
    return repo, release, fix


def upstream(client, name, version=None, url=REACT):
    """An Application with one Upstream repository locked at `version`; its id."""
    return application(client, asset_name=name, source_url=url, locked_version=version)["id"]


def analysed(system, application_id, revision, verdict=FIX, parent=None, ident=None):
    """Analyses the commit at `revision` of the Application's repository (or the stored commit
    `ident` again) to `verdict`: the commit as GET /api/commits/{id} shows it."""
    app, client, _ = system
    if ident is None:
        ident = source_snapshot(app, application_id, revision)
        with app.state.factory.begin() as db:
            row = db.get(Commit, ident)
            row.data = {**row.data, "parent_revisions": [parent] if parent else []}
    ref = parent if verdict == FIX else revision
    job, _ = analyze(system, ident, assessment(verdict, ref=ref), pinned_bundle(ref))
    assert job["status"] == "succeeded", job
    return client.get(f"/api/commits/{ident}").json()


def states(commit):
    return {row["application_name"]: (row["state"], row["reason"]) for row in commit["exposures"]}


def opened(commit):
    return sorted(row["application_name"] for row in commit["findings"] if row["relation"] == "source")


def stands_for(app, application_id, package):
    """Makes the Application's Upstream link a derived one, standing for `package`."""
    with app.state.factory.begin() as db:
        link = db.scalar(select(ApplicationRepository).where(ApplicationRepository.application_id == application_id))
        link.packages = [package]


def test_an_application_locking_19_0_0_is_exposed_to_the_react2shell_fix(system, tmp_path):
    app, client, _ = system
    connection(app)
    repo, release, fix = react(tmp_path / "git")
    shop = upstream(client, "Shop", "19.0.0")
    stands_for(app, shop, f"npm:{PACKAGE}")
    commit = analysed(system, shop, fix, parent=release)
    assert commit["exposures"] == [{
        "application_id": shop, "application_name": "Shop", "verdict": FIX, "state": "exposed",
        "reason": "no release contains the fix yet", "locked_version": "19.0.0", "tag": "v19.0.0", "target": None,
    }]
    (finding,) = commit["findings"]
    assert (finding["application_id"], finding["status"], finding["relation"]) == (shop, "open", "source")
    # A release that contains the fix appears; a repeat Analysis updates the same Exposure, which now
    # names the first release to bump to, and opens no second Finding.
    repo.tag(f"{PACKAGE}@19.0.1")
    again = analysed(system, shop, fix, parent=release, ident=commit["id"])
    (row,) = again["exposures"]
    assert (row["state"], row["reason"], row["target"]) == (
        "exposed", "v19.0.0 does not contain the fix", {"tag": f"{PACKAGE}@19.0.1", "version": "19.0.1"})
    assert again["findings"] == commit["findings"]
    with app.state.factory() as db:
        (stored,) = db.scalars(select(Exposure))
        assert stored.data["analysis_id"] == again["analyses"][0]["id"] != commit["analyses"][0]["id"]


def test_a_locked_version_whose_tag_contains_the_fix_is_not_exposed(system, tmp_path):
    app, client, _ = system
    connection(app)
    repo, release, fix = react(tmp_path / "git")
    repo.commit("Release 19.0.1", {"CHANGELOG.md": "19.0.1\n"})
    repo.tag("v19.0.1")
    repo.tag("v2.0.0")  # semantically older, but cut after the fix
    repo.branch("old", release)
    repo.commit("Release 99.0.0", {"CHANGELOG.md": "99.0.0\n"})
    repo.tag("v99.0.0")  # semantically newer, but cut from a branch without the fix
    names = {"Fixed": "19.0.1", "Low": "2.0.0", "High": "99.0.0"}
    ids = {name: upstream(client, name, version) for name, version in names.items()}
    commit = analysed(system, ids["Fixed"], fix, parent=release)
    assert states(commit) == {
        "Fixed": ("not_exposed", "v19.0.1 contains the fix"),
        "Low": ("not_exposed", "v2.0.0 contains the fix"),
        "High": ("exposed", "v99.0.0 does not contain the fix"),
    }
    assert opened(commit) == ["High"]
    # The first release that contains the fix, by tag date: the bump target for the exposed one.
    assert {row["target"]["tag"] for row in commit["exposures"]} == {"v19.0.1"}


def test_a_release_branch_backport_with_the_same_patch_id_is_not_exposed(system, tmp_path, monkeypatch):
    app, client, _ = system
    connection(app)
    repo, release, fix = react(tmp_path / "git")
    repo.branch("19.x", release)
    repo.cherry_pick(fix)  # a different SHA with the same patch-id
    repo.tag("v19.0.1")
    repo.branch("18.x", release)
    repo.cherry_pick(fix)
    repo.tag("v18.0.1")  # the same change, on a branch that is not watched
    repo.branch("17.x", release)
    repo.commit("Reject unknown references", {SERVER: "export function decodeReply(body) {\n  return resolve(owned(body));\n}\n"})
    repo.tag("v17.0.1")  # a different patch, on a watched branch
    names = {"Backported": "19.0.1", "Unwatched": "18.0.1", "Rewritten": "17.0.1"}
    ids = {name: upstream(client, name, version) for name, version in names.items()}
    with app.state.factory.begin() as db:
        db.scalar(select(Repository).where(Repository.source_url == REACT)).watched_branches = {"19.x": {}, "17.x": {}}
    commit = analysed(system, ids["Backported"], fix, parent=release)
    assert states(commit) == {
        "Backported": ("not_exposed", "v19.0.1 contains the fix"),
        "Unwatched": ("exposed", "v18.0.1 does not contain the fix"),
        "Rewritten": ("exposed", "v17.0.1 does not contain the fix"),
    }
    assert opened(commit) == ["Rewritten", "Unwatched"]

    # A backport scan that fails or times out leaves the commit's own containment, never every
    # Exposure unknown: with no backport known, no release contains the fix, so every version is exposed.
    def timed_out(*args):
        raise DomainError("git_failed", "git log took longer than 300 s", 422)

    monkeypatch.setattr(exposure, "equivalents", timed_out)
    again = analysed(system, ids["Backported"], fix, parent=release, ident=commit["id"])
    assert set(states(again).values()) == {("exposed", "no release contains the fix yet")}


def test_an_unresolvable_tag_is_unknown_and_counts_as_exposed(system, tmp_path):
    app, client, _ = system
    connection(app)
    repo, _, _ = react(tmp_path / "git")
    introduced = repo.commit("Resolve references lazily", {SERVER: "export const decodeReply = resolve;\n"})
    repo.tag("v19.1.0")
    ids = {"Unlocked": upstream(client, "Unlocked"), "Untagged": upstream(client, "Untagged", "9.9.9")}
    commit = analysed(system, ids["Unlocked"], introduced, INTRODUCED)
    assert states(commit) == {
        "Unlocked": ("unknown", "No Locked version"),
        "Untagged": ("unknown", "No release tag matches the Locked version 9.9.9"),
    }
    assert opened(commit) == ["Unlocked", "Untagged"]
    # The target is found even without a Locked version: the newest release without the commit.
    assert {row["target"]["tag"] for row in commit["exposures"]} == {"v19.0.0"}
    # A repository whose tags cannot be read is unknown for every Application.
    gone = upstream(client, "Unreadable", "1.0.0", url="https://github.com/numen/gone")
    commit = analysed(system, gone, "e" * 40, INTRODUCED)
    ((state, reason),) = states(commit).values()
    assert state == "unknown" and reason.startswith("The release tags could not be read: numen/gone could not be cloned")
    assert opened(commit) == ["Unreadable"]


def test_the_locked_version_maps_to_the_first_existing_tag(tmp_path):
    repo, _, _ = react(tmp_path / "git")
    for name in ("19.0.0", f"{PACKAGE}@19.0.0", f"{PACKAGE}@19.0.1", "react@19.0.2", "nightly"):
        repo.tag(name)

    def first(version, package=PACKAGE):
        with Sources(Config(test_mode=True)).github_mirror(SimpleNamespace(source_url=REACT)) as run:
            return exposure.locked_tag(run, version, package)

    assert first("19.0.0") == "v19.0.0"
    repo.git("tag", "-d", "v19.0.0")
    assert first("19.0.0") == "19.0.0"
    repo.git("tag", "-d", "19.0.0")
    assert first("19.0.0") == f"{PACKAGE}@19.0.0"
    assert first("19.0.1") == f"{PACKAGE}@19.0.1"
    assert first("19.0.2") is None  # only another package's tag
    assert first("19.0.1", None) is None  # a hand-added link names no package
    assert exposure.tag_forms("19.0.0", PACKAGE) == ["v19.0.0", "19.0.0", f"{PACKAGE}@19.0.0"]
    names = ("v19.0.0", "19.0.1", f"{PACKAGE}@19.0.2", "react@19.0.2", "nightly")
    assert [exposure.tag_version(name, PACKAGE) for name in names] == ["19.0.0", "19.0.1", "19.0.2", None, None]


def test_the_mirror_takes_the_read_token_only_from_its_environment(monkeypatch):
    repository = SimpleNamespace(source_url=REACT)
    # GitHub itself is cloned over https only, and never without the read token.
    with pytest.raises(DomainError) as refused, Sources(Config()).github_mirror(repository):
        pass
    assert refused.value.code == "github_token_required"
    calls = []

    def git(root, *args, stdin=None, env=None, timeout=None):
        calls.append((args, env))
        raise DomainError("git_failed", "fatal: unable to access", 422)

    monkeypatch.setattr("numen.remediation.git", git)
    with pytest.raises(DomainError) as failed, Sources(Config(), "fixture-github-token").github_mirror(repository):
        pass
    assert (failed.value.code, failed.value.message) == ("mirror_unavailable", "numen/react could not be cloned: fatal: unable to access")
    ((args, env),) = calls
    assert args == ("clone", "--bare", "--filter=blob:none", "--quiet", "https://github.com/numen/react.git", ".")
    assert not any("fixture-github-token" in arg for arg in args)
    assert env == {"GIT_ALLOW_PROTOCOL": "https", "GIT_CONFIG_COUNT": "1",
                   "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
                   "GIT_CONFIG_VALUE_0": "Authorization: Basic eC1hY2Nlc3MtdG9rZW46Zml4dHVyZS1naXRodWItdG9rZW4="}


def svn(*argv):
    subprocess.run(["svn", *argv, "--non-interactive"], check=True, capture_output=True)


def test_a_wordpress_commit_is_contained_in_tags_copied_at_or_after_it(system, tmp_path, monkeypatch):
    if not shutil.which("svn") or not shutil.which("svnadmin"):
        pytest.skip("Real SVN client/repository are exercised in the Docker backend suite")
    app, client, _ = system
    connection(app)
    root, seed, checkout = tmp_path / "svn", tmp_path / "seed", tmp_path / "checkout"
    (seed / "fixture" / "trunk").mkdir(parents=True)
    (seed / "fixture" / "tags").mkdir()
    (seed / "fixture" / "trunk" / "plugin.php").write_text("<?php /* Version: 1.0.0 */\n")
    subprocess.run(["svnadmin", "create", str(root)], check=True, capture_output=True)
    url = root.as_uri() + "/fixture"
    svn("import", str(seed), root.as_uri(), "-m", "Release 1.0.0")  # r1
    svn("checkout", url + "/trunk", str(checkout))
    (checkout / "plugin.php").write_text("<?php /* Version: 1.0.1 */ eval($_GET['x']);\n")
    svn("commit", str(checkout), "-m", "Evaluate the request")  # r2: the Vulnerability introduced
    svn("copy", url + "/trunk@1", url + "/tags/1.0.0", "-m", "Tag 1.0.0")  # r3, copied from r1
    svn("copy", url + "/trunk@2", url + "/tags/1.0.1", "-m", "Tag 1.0.1")  # r4, copied from r2
    svn("mkdir", url + "/tags/1.0.2", "-m", "Tag 1.0.2 by hand")  # r5, no copy
    monkeypatch.setenv("NUMEN_WORDPRESS_SVN_URL", root.as_uri())
    blog = SimpleNamespace(source_url="https://plugins.svn.wordpress.org/fixture", plugin_slug="fixture")
    assert Sources(Config(test_mode=True)).svn_tags(blog) == {"1.0.0": 1, "1.0.1": 2, "1.0.2": 5}
    ids = {
        version: application(client, asset_name=f"Blog {version}", source_kind="wordpress", source_url=None,
                             plugin_slug="fixture", source_ref="trunk", locked_version=version)["id"]
        for version in ("1.0.0", "1.0.1", "1.0.2")
    }
    commit = analysed(system, ids["1.0.0"], "2", INTRODUCED)
    assert states(commit) == {
        "Blog 1.0.0": ("not_exposed", "1.0.0 does not contain the commit"),
        "Blog 1.0.1": ("exposed", "1.0.1 contains the commit"),
        "Blog 1.0.2": ("exposed", "1.0.2 contains the commit"),
    }
    assert opened(commit) == ["Blog 1.0.1", "Blog 1.0.2"]
    assert {row["target"]["tag"] for row in commit["exposures"]} == {"1.0.0"}


@pytest.mark.parametrize("verdict", [INTRODUCED, MALICIOUS])
def test_an_introduced_or_malicious_commit_exposes_only_releases_that_contain_it(system, tmp_path, verdict):
    app, client, _ = system
    connection(app)
    repo = git_repository(tmp_path / "git", "numen/lib")
    repo.commit("Release 1.0.0", {"index.js": "module.exports = 1;\n"})
    repo.tag("v1.0.0")
    change = repo.commit("Change the export", {"index.js": "module.exports = require('./loader');\n"})
    release = repo.commit("Release 1.1.0", {"CHANGELOG.md": "1.1.0\n"})
    repo.tag("v1.1.0")
    url = "https://github.com/numen/lib"
    ids = {name: upstream(client, name, version, url) for name, version in (("Old", "1.0.0"), ("New", "1.1.0"))}
    commit = analysed(system, ids["Old"], change, verdict)
    assert states(commit) == {"Old": ("not_exposed", "v1.0.0 does not contain the commit"),
                              "New": ("exposed", "v1.1.0 contains the commit")}
    assert opened(commit) == ["New"]
    # The safe version a pin moves to: the newest release without the commit.
    assert [row["target"] for row in commit["exposures"]] == [{"tag": "v1.0.0", "version": "1.0.0"}] * 2
    if verdict == MALICIOUS:
        (row,) = commit["findings"]
        report = client.get(f"/api/findings/{row['id']}").json()["cleanup_report"]
        assert report["commits"] == [{"revision": change, "commit_id": commit["id"]}, {"revision": release, "commit_id": None}]
        assert (report["releases"], report["commits_truncated"]) == (["v1.1.0"], False)


@pytest.mark.parametrize("verdict", [FIX, MALICIOUS])
def test_a_not_exposed_verdict_is_recorded_on_the_upstream_repository_only(system, tmp_path, verdict):
    app, client, config = system
    connection(app)
    repo = git_repository(tmp_path / "git", "numen/lib")
    base = repo.commit("Release 1.0.0", {"index.js": "module.exports = 1;\n"})
    repo.tag("v1.0.0")
    fix = repo.commit("Escape the name", {"index.js": "module.exports = escape(1);\n"})
    repo.tag("v1.1.0")
    malicious = repo.commit("Add a loader", {"loader.js": "require('child_process').exec(process.env.X);\n"})
    # The Application has an Own repository too, so a Remediation PR could be drafted if it were exposed.
    shop = application(client, asset_name="Shop", role="own", source_url="https://github.com/acme/shop")["id"]
    linked = client.post(f"/api/applications/{shop}/repositories",
                         json={"source_kind": "github", "source_url": "https://github.com/numen/lib", "locked_version": "1.1.0"})
    assert linked.status_code == 201, linked.text
    revision, parent = (fix, base) if verdict == FIX else (malicious, None)
    ident = source_snapshot(app, shop, revision, repository_id=linked.json()["repository_id"])
    with app.state.factory.begin() as db:
        row = db.get(Commit, ident)
        row.data = {**row.data, "parent_revisions": [parent or fix]}
    commit = analysed(system, shop, revision, verdict, parent, ident=ident)
    reason = "v1.1.0 contains the fix" if verdict == FIX else "v1.1.0 does not contain the commit"
    assert states(commit) == {"Shop": ("not_exposed", reason)}
    assert commit["verdict"] == verdict and commit["findings"] == []
    with app.state.factory() as db:
        assert db.scalar(select(func.count(Finding.id))) == 0
        assert db.scalar(select(func.count(Notification.id))) == 0
        assert db.scalar(select(func.count(RemediationPR.id))) == 0
        assert [job.kind for job in db.scalars(select(Job).where(Job.kind != "source_check"))] == ["commit_analysis"]
    # A repeat Analysis updates the same record.
    first = commit["analyses"][0]["id"]
    again = analysed(system, shop, revision, verdict, parent, ident=ident)
    assert states(again) == states(commit) and again["findings"] == []
    with app.state.factory() as db:
        (stored,) = db.scalars(select(Exposure))
        assert stored.data["analysis_id"] == again["analyses"][0]["id"] != first
        assert db.scalar(select(func.count(Notification.id))) == 0
    # The commit list carries it too.
    (listed,) = [c for c in client.get(f"/api/applications/{shop}/commits").json()["items"] if c["id"] == ident]
    assert listed["exposures"] == again["exposures"]


# Recomputing Exposure when a Locked version changes (A05): an exposure_check runs the Playbook for
# each Verdict that now reaches the Application and opened no Finding for it yet.
LIB = "https://github.com/numen/lib"
QUEUED_ONLY = ("notification", "detection_rule", "patch_drafting", "remediation_draft", "finding_artifacts")
RULE = b'rule loader { strings: $a = "str(value)" condition: $a }'


def library(base):
    """numen/lib: v0.9.0, v1.0.0, then the analysed change, then v1.1.0. (repository, change)."""
    repo = git_repository(base, "numen/lib")
    repo.commit("Release 0.9.0", {"index.js": "module.exports = 0;\n"})
    repo.tag("v0.9.0")
    repo.commit("Release 1.0.0", {"index.js": "module.exports = 1;\n"})
    repo.tag("v1.0.0")
    change = repo.commit("Change the export", {"index.js": "module.exports = require('./loader');\n"})
    repo.commit("Release 1.1.0", {"CHANGELOG.md": "1.1.0\n"})
    repo.tag("v1.1.0")
    return repo, change


def exposure_checks(app):
    with app.state.factory() as db:
        return [(job.application_id, job.input["repository_id"], job.status)
                for job in db.scalars(select(Job).where(Job.kind == "exposure_check").order_by(Job.created_at))]


def upstream_link(client, application_id):
    (link,) = [r for r in client.get(f"/api/applications/{application_id}").json()["repositories"] if r["role"] == "upstream"]
    return link


def run_check(system, application_id, repository_id):
    """Runs the one queued exposure_check, which is the Application's for `repository_id`; that job."""
    app, client, config = system
    with app.state.factory() as db:
        (job,) = db.scalars(select(Job).where(Job.kind == "exposure_check", Job.status == "queued"))
        assert (job.application_id, job.input["repository_id"]) == (application_id, repository_id)
        ident = job.id
    assert run_once(config, app.state.factory, FixtureBroker(), exclude=QUEUED_ONLY)
    job = client.get(f"/api/jobs/{ident}").json()
    assert job["status"] == "succeeded", job
    return job


def relock(system, application_id, version):
    """Sets the Application's Upstream Locked version to `version` and runs the exposure_check that
    queues; that job."""
    _, client, _ = system
    link = upstream_link(client, application_id)
    patched = client.patch(f"/api/applications/{application_id}/repositories/{link['repository_id']}",
                           json={"locked_version": version})
    assert patched.status_code == 200, patched.text
    return run_check(system, application_id, link["repository_id"])


def counts(app):
    with app.state.factory() as db:
        return {"findings": db.scalar(select(func.count(Finding.id))),
                "alerts": db.scalar(select(func.count(Notification.id))),
                "artifacts": db.scalar(select(func.count(Artifact.id)).where(Artifact.resource_type == "finding"))}


def test_bumping_a_locked_version_into_a_release_with_a_known_malicious_change_opens_a_finding(system, tmp_path):
    app, client, _ = system
    connection(app)
    _, change = library(tmp_path / "git")
    shop = upstream(client, "Shop", "1.0.0", LIB)
    ident = source_snapshot(app, shop, change)
    job, _ = analyze(system, ident, assessment(MALICIOUS, ref=change), {"report.md": b"# A loader", "detection-rule.yar": RULE})
    assert job["status"] == "succeeded", job
    commit = client.get(f"/api/commits/{ident}").json()
    assert states(commit) == {"Shop": ("not_exposed", "v1.0.0 does not contain the commit")}
    assert commit["findings"] == [] and counts(app)["alerts"] == 0
    # The Locked version moves into a release that contains the Malicious change: the Finding opens then.
    checked = relock(system, shop, "1.1.0")
    commit = client.get(f"/api/commits/{ident}").json()
    assert states(commit) == {"Shop": ("exposed", "v1.1.0 contains the commit")}
    (row,) = commit["findings"]
    assert checked["result"]["finding_ids"] == [row["id"]]
    finding = client.get(f"/api/findings/{row['id']}").json()
    assert (finding["status"], finding["cause"]["by"], finding["cause"]["verdict"]) == ("open", "verdict", MALICIOUS)
    assert finding["cause"]["analysis_id"] == commit["analyses"][0]["id"] and finding["malicious_change"] is True
    # The cleanup report's releases come from tag containment.
    report = finding["cleanup_report"]
    assert report["commits"][0] == {"revision": change, "commit_id": ident}
    assert (report["releases"], report["commits_truncated"]) == (["v1.1.0"], False)
    # The static Proof is a Draft until its Detection rule validates; its job is queued.
    proof = finding["static_proof"]
    assert proof["status"] == "pending" and proof["rule"] == RULE.decode()
    assert {"report.md", "indicators.json", "detection-rule.yar"} <= set(proof["files"])
    with app.state.factory() as db:
        rule = db.get(Job, proof["job_id"])
        assert (rule.kind, rule.status, rule.input["finding_id"]) == ("detection_rule", "queued", row["id"])
        (alert,) = db.scalars(select(Notification))
        assert alert.data["link"] == f"/findings/{row['id']}" and alert.data["application"] == "Shop"


def unchanged(finding):
    """The Finding without its Exposure, which a recomputation updates."""
    return {key: value for key, value in finding.items() if key != "exposure"}


def test_recomputing_exposure_runs_the_playbook_only_when_it_becomes_exposed(system, tmp_path):
    app, client, _ = system
    connection(app)
    _, change = library(tmp_path / "git")
    shop = upstream(client, "Shop", "1.0.0", LIB)
    commit = analysed(system, shop, change, INTRODUCED)
    assert states(commit) == {"Shop": ("not_exposed", "v1.0.0 does not contain the commit")}
    # Not exposed to not exposed: recorded, nothing opens.
    relock(system, shop, "0.9.0")
    commit = client.get(f"/api/commits/{commit['id']}").json()
    assert states(commit) == {"Shop": ("not_exposed", "v0.9.0 does not contain the commit")}
    assert counts(app) == {"findings": 0, "alerts": 0, "artifacts": 0}
    # Exposed: the Playbook runs, with the drafted bundle.
    opened_by = relock(system, shop, "1.1.0")
    commit = client.get(f"/api/commits/{commit['id']}").json()
    assert states(commit) == {"Shop": ("exposed", "v1.1.0 contains the commit")}
    (row,) = commit["findings"]
    assert opened_by["result"]["finding_ids"] == [row["id"]]
    finding = client.get(f"/api/findings/{row['id']}").json()
    assert (finding["status"], finding["cause"]["verdict"]) == ("open", INTRODUCED)
    assert finding["artifact_revision"] and finding["evidence"] == assessment(INTRODUCED, ref=change)["evidence"]
    after = counts(app)
    assert (after["findings"], after["alerts"]) == (1, 1) and after["artifacts"] > 0
    # Exposed to not exposed: the Finding stays as it is.
    relock(system, shop, "1.0.0")
    commit = client.get(f"/api/commits/{commit['id']}").json()
    assert states(commit) == {"Shop": ("not_exposed", "v1.0.0 does not contain the commit")}
    assert unchanged(client.get(f"/api/findings/{row['id']}").json()) == unchanged(finding)
    assert client.get(f"/api/findings/{row['id']}").json()["exposure"]["state"] == "not_exposed"
    # Exposed again: the Finding exists, so nothing is re-published or alerted.
    again = relock(system, shop, "1.1.0")
    assert again["result"]["finding_ids"] == []
    assert states(client.get(f"/api/commits/{commit['id']}").json()) == {"Shop": ("exposed", "v1.1.0 contains the commit")}
    assert client.get(f"/api/findings/{row['id']}").json() == finding and counts(app) == after
    # A PATCH that leaves the Locked version as it is queues nothing.
    link = upstream_link(client, shop)
    client.patch(f"/api/applications/{shop}/repositories/{link['repository_id']}", json={"locked_version": "1.1.0"})
    client.patch(f"/api/applications/{shop}/repositories/{link['repository_id']}", json={"enabled": True})
    assert [status for *_, status in exposure_checks(app)] == ["succeeded"] * 4


def test_a_locked_version_changed_during_analysis_is_checked_again(system, tmp_path, monkeypatch):
    app, client, _ = system
    connection(app)
    _, change = library(tmp_path / "git")
    shop = upstream(client, "Shop", "1.0.0", LIB)
    link = upstream_link(client, shop)
    original, raced = Workflows.exposures, []

    def racing(self, db, *args, **kwargs):
        found = original(self, db, *args, **kwargs)
        if not raced:
            # The Operator bumps the Locked version after this Analysis computed its Exposure. No
            # Verdict is stored yet, so the PATCH has nothing to recompute.
            raced.append(client.patch(f"/api/applications/{shop}/repositories/{link['repository_id']}",
                                      json={"locked_version": "1.1.0"}).status_code)
            assert exposure_checks(app) == []
        return found

    monkeypatch.setattr(Workflows, "exposures", racing)
    commit = analysed(system, shop, change, INTRODUCED)
    assert raced == [200]
    assert states(commit) == {"Shop": ("not_exposed", "v1.0.0 does not contain the commit")}
    assert commit["findings"] == []
    # The Analysis saw the change after its fence and queued the check, which opens the Finding.
    assert exposure_checks(app) == [(shop, link["repository_id"], "queued")]
    run_check(system, shop, link["repository_id"])
    commit = client.get(f"/api/commits/{commit['id']}").json()
    assert states(commit) == {"Shop": ("exposed", "v1.1.0 contains the commit")}
    assert opened(commit) == ["Shop"]


def manifests(monkeypatch):
    """{ref: files} of the Own repository acme/shop's manifests, which derive() reads; every npm
    package's repository is numen/lib."""
    found = {}
    monkeypatch.setattr(Sources, "github_file", lambda self, repository, name, ref: found[ref].get(name))
    monkeypatch.setattr(Sources, "npm_repository", lambda self, name, version: "git+https://github.com/numen/lib.git")
    return found


def derive(system, application_id, ref):
    """Runs the Application's derivation of its Own repository acme/shop's Upstream repositories at `ref`."""
    app, client, config = system
    with app.state.factory.begin() as db:
        own = db.scalar(select(Repository).where(Repository.source_url == "https://github.com/acme/shop"))
        ident = domain.enqueue(db, "derive_upstreams", db.get(Application, application_id),
                               domain.repository_input(own, source_ref=ref)).id
    assert run_once(config, app.state.factory, FixtureBroker(), exclude=QUEUED_ONLY)
    job = client.get(f"/api/jobs/{ident}").json()
    assert job["status"] == "succeeded", job


def test_a_lockfile_rederivation_recomputes_exposure(system, tmp_path, monkeypatch):
    app, client, _ = system
    connection(app)
    _, change = library(tmp_path / "git")
    files = manifests(monkeypatch)

    def lock(ref, version):
        files[ref] = npm_files({"lib": "^1.0.0"}, {"lib": version})
        derive(system, shop, ref)

    shop = application(client, asset_name="Shop", role="own", source_url="https://github.com/acme/shop")["id"]
    # The first derivation links numen/lib at 1.0.0. It has no Verdict yet, so nothing is recomputed.
    lock("r1", "1.0.0")
    link = upstream_link(client, shop)
    assert (link["source_url"], link["locked_version"], link["enabled"]) == (LIB, "1.0.0", True)
    assert exposure_checks(app) == []
    ident = source_snapshot(app, shop, change, repository_id=link["repository_id"])
    job, _ = analyze(system, ident, assessment(INTRODUCED, ref=change), pinned_bundle(change))
    assert job["status"] == "succeeded", job
    commit = client.get(f"/api/commits/{ident}").json()
    assert states(commit) == {"Shop": ("not_exposed", "v1.0.0 does not contain the commit")}
    assert commit["findings"] == []
    # A lockfile bump re-derives the Locked version, which recomputes Exposure and opens the Finding.
    lock("r2", "1.1.0")
    assert upstream_link(client, shop)["locked_version"] == "1.1.0"
    run_check(system, shop, link["repository_id"])
    commit = client.get(f"/api/commits/{ident}").json()
    assert states(commit) == {"Shop": ("exposed", "v1.1.0 contains the commit")}
    (row,) = commit["findings"]
    assert client.get(f"/api/findings/{row['id']}").json()["cause"]["verdict"] == INTRODUCED
    # A re-derivation that keeps the Locked version recomputes nothing.
    lock("r3", "1.1.0")
    assert [status for *_, status in exposure_checks(app)] == ["succeeded"]


def test_a_dependency_turned_on_later_gets_its_exposure_and_playbook(system, tmp_path, monkeypatch):
    """A dependency that a later derivation adds starts off (A01). Turning it on recomputes its
    Exposure to the Verdicts stored on its shared repository while it was off (A05), so a Locked
    version that holds a known Malicious change opens the Finding and its Alert then. So does
    restoring an archived Application."""
    app, client, _ = system
    connection(app)
    _, change = library(tmp_path / "git")
    files = manifests(monkeypatch)
    # Blog uses numen/lib at 1.0.0, which lacks the Malicious change its Analysis finds.
    blog = upstream(client, "Blog", "1.0.0", LIB)
    ident = source_snapshot(app, blog, change)
    job, _ = analyze(system, ident, assessment(MALICIOUS, ref=change), {"report.md": b"# A loader", "detection-rule.yar": RULE})
    assert job["status"] == "succeeded", job
    # Shop's first derivation has no dependency; the next adds numen/lib at 1.1.0, which holds it.
    shop = application(client, asset_name="Shop", role="own", source_url="https://github.com/acme/shop")["id"]
    files["r1"] = npm_files({}, {})
    derive(system, shop, "r1")
    files["r2"] = npm_files({"lib": "^1.1.0"}, {"lib": "1.1.0"})
    derive(system, shop, "r2")
    link = upstream_link(client, shop)
    assert (link["locked_version"], link["enabled"]) == ("1.1.0", False)
    assert exposure_checks(app) == [] and counts(app)["findings"] == 0
    # Turned on, it is checked: the Finding and its Alert open then.
    turned = client.patch(f"/api/applications/{shop}/repositories/{link['repository_id']}", json={"enabled": True})
    assert turned.status_code == 200, turned.text
    checked = run_check(system, shop, link["repository_id"])
    commit = client.get(f"/api/commits/{ident}").json()
    assert states(commit) == {"Blog": ("not_exposed", "v1.0.0 does not contain the commit"),
                              "Shop": ("exposed", "v1.1.0 contains the commit")}
    (row,) = commit["findings"]
    assert (row["application_id"], checked["result"]["finding_ids"]) == (shop, [row["id"]])
    with app.state.factory() as db:
        (alert,) = db.scalars(select(Notification))
        assert alert.data["link"] == f"/findings/{row['id']}"
    # An archived Application gets its check when it is restored.
    client.patch(f"/api/applications/{shop}", json={"archived": True})
    assert [status for *_, status in exposure_checks(app)] == ["succeeded"]
    client.patch(f"/api/applications/{shop}", json={"archived": False})
    assert exposure_checks(app)[-1] == (shop, link["repository_id"], "queued")


def test_an_upstream_link_added_during_analysis_gets_its_own_exposure_check(system, tmp_path, monkeypatch):
    app, client, _ = system
    connection(app)
    _, change = library(tmp_path / "git")
    shop = upstream(client, "Shop", "1.0.0", LIB)
    original, late = Workflows.exposures, []

    def racing(self, db, *args, **kwargs):
        found = original(self, db, *args, **kwargs)
        if not late:
            # Blog links numen/lib, at a release that holds the change, after this Analysis read the
            # tags and before its Verdict is stored.
            late.append(upstream(client, "Blog", "1.1.0", LIB))
        return found

    monkeypatch.setattr(Workflows, "exposures", racing)
    commit = analysed(system, shop, change, INTRODUCED)
    (blog,) = late
    # With no Exposure read for Blog, nothing opens for it (AC-A12): its exposure_check decides.
    assert states(commit) == {"Shop": ("not_exposed", "v1.0.0 does not contain the commit")}
    assert commit["findings"] == [] and counts(app)["alerts"] == 0
    link = upstream_link(client, blog)
    assert exposure_checks(app) == [(blog, link["repository_id"], "queued")]
    run_check(system, blog, link["repository_id"])
    commit = client.get(f"/api/commits/{commit['id']}").json()
    assert states(commit)["Blog"] == ("exposed", "v1.1.0 contains the commit")
    assert opened(commit) == ["Blog"]
