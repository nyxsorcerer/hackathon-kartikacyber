import json
import socket

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from conftest import application
from numen import remediation
from numen.models import RemediationPR
from numen.security import DomainError
from test_artifacts import finding

FILES = {"main.py": b"a\nb\n", "src/f.txt": b"x\n", "manifest.json": b"{}"}


def new_file(path, mode="100644", body="+root\n"):
    return f"diff --git a/{path} b/{path}\nnew file mode {mode}\n--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n{body}"


EDIT = "diff --git a/main.py b/main.py\n--- a/main.py\n+++ b/main.py\n@@ -1,2 +1,2 @@\n a\n-b\n+c\n"


@pytest.fixture
def offline(monkeypatch):
    """The mechanics never reach a network: git runs on temporary checkouts."""
    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: pytest.fail("network access"))


offline_test = pytest.mark.usefixtures("offline")


def test_the_application_subject_action_key_is_unique(system):
    app, client, _ = system
    p = application(client)
    found = finding(client, p["id"])
    key = {"application_id": p["id"], "finding_id": found["id"],
           "repository_id": p["repositories"][0]["repository_id"], "subject": "c1"}
    with app.state.factory.begin() as db:
        db.add_all([RemediationPR(**key, action="patch"), RemediationPR(**key, action="revert")])
    with app.state.factory() as db:
        db.add(RemediationPR(**key, action="patch"))
        with pytest.raises(IntegrityError):
            db.flush()
    with app.state.factory() as db:
        rows = db.scalars(select(RemediationPR).order_by(RemediationPR.action)).all()
        assert [(row.action, row.status, row.data) for row in rows] == [("patch", "drafting", {}), ("revert", "drafting", {})]
    # Deleting a Finding recorded in error takes its Remediation PRs with it.
    assert client.delete(f"/api/findings/{found['id']}").status_code == 204
    with app.state.factory() as db:
        assert db.scalars(select(RemediationPR)).all() == []


def test_branch_names_carry_the_short_sha_and_the_action():
    assert remediation.branch_name("0123456789abcdef", "revert") == "asset-monitor/0123456-revert"


@offline_test
@pytest.mark.parametrize("diff,kwargs,check", [
    ("", {}, "empty"),
    ("x" * (remediation.MAX_DIFF + 1), {}, "larger than 1 MiB"),
    (b"\xff\xfe", {}, "not UTF-8"),
    ("not a diff\n", {}, "could not be read"),
    (EDIT.replace(" a\n", " z\n"), {}, "does not apply"),
    (new_file("main.py"), {}, "does not apply"),
    (new_file("/etc/passwd"), {}, "not a safe relative path"),
    (new_file("../outside"), {}, "not a safe relative path"),
    (new_file("src/../../outside"), {}, "not a safe relative path"),
    (new_file(".git/config"), {}, "inside .git"),
    (new_file("src/.GIT/hooks/pre-commit"), {}, "inside .git"),
    (new_file("link", "120000", "+/etc/passwd\n"), {}, "symlink or submodule"),
    (new_file("link", "120755", "+/etc/passwd\n"), {}, "symlink or submodule"),  # git reads it as a symlink
    ("diff --git a/sub b/sub\nnew file mode 160000\nindex 0000000..1234567\n--- /dev/null\n+++ b/sub\n"
     "@@ -0,0 +1 @@\n+Subproject commit 1234567890123456789012345678901234567890\n", {}, "symlink or submodule"),
    (EDIT, {"prefix": "src"}, "outside the repository's source path"),
    # --numstat lists only a rename's target, so this rename from outside the source path would pass.
    ("diff --git a/main.py b/src/main.py\nsimilarity index 100%\nrename from main.py\nrename to src/main.py\n",
     {"prefix": "src"}, "renames or copies"),
    ("diff --git a/main.py b/copy.py\nsimilarity index 100%\ncopy from main.py\ncopy to copy.py\n", {}, "renames or copies"),
    (new_file(".github/workflows/ci.yml"), {}, ".github/workflows"),
])
def test_apply_diff_rejects(diff, kwargs, check):
    with pytest.raises(DomainError) as error:
        remediation.apply_diff(diff, FILES, **kwargs)
    assert error.value.code == "diff_rejected" and error.value.status == 422
    assert check in error.value.message, error.value.message


@offline_test
def test_apply_diff_returns_changed_and_deleted_files():
    removal = "diff --git a/src/f.txt b/src/f.txt\ndeleted file mode 100644\n--- a/src/f.txt\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
    workflow = new_file(".github/workflows/ci.yml", body="+on: push\n")
    result = remediation.apply_diff(EDIT + removal + new_file("src/new.py") + workflow, FILES, workflows=True)
    assert result == {
        "changed": {"main.py": b"a\nc\n", "src/new.py": b"root\n", ".github/workflows/ci.yml": b"on: push\n"},
        "deleted": ["src/f.txt"],
        "paths": ["main.py", "src/f.txt", "src/new.py", ".github/workflows/ci.yml"],
        "flags": ["workflows"],
    }
    inside = remediation.apply_diff(new_file("src/new.py").encode(), FILES, prefix="src/")
    assert inside == {"changed": {"src/new.py": b"root\n"}, "deleted": [], "paths": ["src/new.py"], "flags": []}


@offline_test
def test_tree_diff_reverts_a_commit():
    parent = {
        "main.py": b"def run():\n    return 1\n",
        "old.txt": b"removed by the commit\n",
        ".gitignore": b"dist/\n",
        "dist/app.js": b"clean()\n",
        "logo.bin": b"\x00\x01\x02",
        "manifest.json": b"{}",
    }
    commit = {
        "main.py": b"def run():\n    exfiltrate()\n    return 1\n",
        "payload.js": b"steal()\n",
        ".gitignore": b"dist/\n",
        "dist/app.js": b"clean();steal()\n",  # tracked although ignored
        "logo.bin": b"\x00\xff\x02",
        "manifest.json": b"{}",
    }
    diff = remediation.tree_diff(commit, parent)
    assert "manifest.json" not in diff and "GIT binary patch" in diff
    result = remediation.apply_diff(diff, commit)
    reverted = {path: data for path, data in commit.items() if path not in result["deleted"]} | result["changed"]
    assert reverted == parent
    assert result["deleted"] == ["payload.js"]
    assert remediation.tree_diff(parent, parent) == ""


def lock(**fields):
    return json.dumps({"name": "app", "lockfileVersion": 3, **fields}, indent=2).encode()


@offline_test
def test_dependency_files_pins_and_bumps_npm_and_composer():
    old = {"version": "19.0.0", "resolved": "https://registry.npmjs.org/react/-/react-19.0.0.tgz", "integrity": "sha512-old"}
    npm = {
        "package.json": json.dumps({"name": "app", "dependencies": {"react": "^19.0.0"},
                                    "devDependencies": {"vite": "~5.0.0"}}).encode(),
        "package-lock.json": lock(packages={"": {"name": "app", "dependencies": {"react": "^19.0.0"},
                                                 "devDependencies": {"vite": "~5.0.0"}},
                                            "node_modules/react": old}),
    }
    dist = {"tarball": "https://registry.npmjs.org/react/-/react-19.0.1.tgz", "integrity": "sha512-new"}
    pinned = remediation.dependency_files(npm, "npm", "react", "19.0.1", "pin", dist)
    assert set(pinned) == {"package.json", "package-lock.json"}
    assert pinned["package.json"].decode() == json.dumps(
        {"name": "app", "dependencies": {"react": "19.0.1"}, "devDependencies": {"vite": "~5.0.0"}},
        indent=2, ensure_ascii=False) + "\n"
    locked = json.loads(pinned["package-lock.json"])
    assert locked["packages"][""]["dependencies"] == {"react": "19.0.1"}
    assert locked["packages"]["node_modules/react"] == {
        "version": "19.0.1", "resolved": dist["tarball"], "integrity": "sha512-new"}
    bumped = remediation.dependency_files(npm, "npm", "vite", "5.0.12", "bump")
    assert json.loads(bumped["package.json"])["devDependencies"] == {"vite": "~5.0.12"}
    assert json.loads(bumped["package-lock.json"])["packages"][""]["devDependencies"] == {"vite": "~5.0.12"}
    # lockfileVersion 1 keeps each package under dependencies; without a dist, npm resolves it again.
    v1 = {"package.json": npm["package.json"],
          "package-lock.json": lock(lockfileVersion=1, dependencies={"react": old})}
    assert json.loads(remediation.dependency_files(v1, "npm", "react", "19.0.1", "bump")["package-lock.json"]) == {
        "name": "app", "lockfileVersion": 1, "dependencies": {"react": {"version": "19.0.1"}}}
    assert set(remediation.dependency_files({"package.json": npm["package.json"]}, "npm", "react", "19.0.1", "pin")) == {"package.json"}

    composer = {"composer.json": json.dumps({"require": {"php": ">=8.1", "monolog/monolog": "^2.9"},
                                             "require-dev": {"phpunit/phpunit": ">=10.0"}}).encode()}
    edited = remediation.dependency_files(composer, "composer", "monolog/monolog", "2.9.3", "pin")
    assert edited["composer.json"].decode() == json.dumps(
        {"require": {"php": ">=8.1", "monolog/monolog": "2.9.3"}, "require-dev": {"phpunit/phpunit": ">=10.0"}},
        indent=4, ensure_ascii=False) + "\n"
    edited = remediation.dependency_files(composer, "composer", "phpunit/phpunit", "10.5.1", "bump")
    assert json.loads(edited["composer.json"])["require-dev"] == {"phpunit/phpunit": ">=10.5.1"}

    for files, ecosystem, name in ((npm, "npm", "lodash"), (composer, "composer", "guzzlehttp/guzzle"), ({}, "npm", "react")):
        with pytest.raises(DomainError) as error:
            remediation.dependency_files(files, ecosystem, name, "1.0.0", "pin")
        assert error.value.code == "dependency_not_found" and error.value.status == 422
