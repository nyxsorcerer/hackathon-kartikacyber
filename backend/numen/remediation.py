"""Remediation PR mechanics (A08), all application code: validating and applying a drafted diff,
writing a revert as git's own diff and editing a dependency pin or bump, with no network; and
opening the draft pull request through the GitHub REST API. git runs on a temporary checkout with
no system or user configuration and no hooks."""

import base64
import hashlib
import json
import os
import re
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .dependencies import NPM_SECTIONS
from .schemas import safe_path
from .security import DomainError

ACTIONS = ("patch", "revert", "pin", "bump")
MAX_DIFF = 1024 * 1024
GIT_TIMEOUT = 60
# ecosystem: (manifest, sections, JSON indent)
MANIFESTS = {
    "npm": ("package.json", NPM_SECTIONS, 2),
    "composer": ("composer.json", ("require", "require-dev"), 4),
}


def branch_name(revision, action):
    return f"asset-monitor/{revision[:7]}-{action}"


def rejected(check):
    return DomainError("diff_rejected", check, 422)


def git(root, *args, stdin=None, env=None, timeout=GIT_TIMEOUT):
    """git's stdout, run in the checkout or bare repository `root` with HOME set to its temporary
    parent; `env` adds to its configuration-free environment."""
    fixed = {"PATH": os.environ.get("PATH", os.defpath), "HOME": str(root.parent), "LC_ALL": "C",
             "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}
    try:
        return subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", *args], cwd=root, env={**fixed, **(env or {})},
            input=stdin, capture_output=True, timeout=timeout, check=True,
        ).stdout
    except subprocess.CalledProcessError as exc:
        raise DomainError("git_failed", exc.stderr.decode(errors="replace")[-2000:].strip(), 422) from exc
    except subprocess.TimeoutExpired as exc:
        raise DomainError("git_failed", f"git {args[0]} took longer than {timeout} s", 422) from exc


def git_part(path):
    return any(part.lower() == ".git" for part in path.split("/"))


def kept(path):
    """Whether a snapshot path is written to a checkout: not its artifact manifest.json (as
    workflows.source_inputs leaves it out) and nothing inside .git."""
    return path != "manifest.json" and not git_part(path)


def write(root, files):
    """Writes the kept snapshot files as regular files."""
    for path, data in files.items():
        if not kept(path):
            continue
        target = root / safe_path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data if isinstance(data, bytes) else data.encode())


@contextmanager
def checkout(files):
    with tempfile.TemporaryDirectory(prefix="remediation-") as tmp:
        root = Path(tmp, "checkout")
        root.mkdir()
        git(root, "init", "-q")
        write(root, files)
        yield root


def text(diff):
    raw = diff if isinstance(diff, bytes) else diff.encode()
    if not raw:
        raise rejected("The diff is empty")
    if len(raw) > MAX_DIFF:
        raise rejected("The diff is larger than 1 MiB")
    try:
        return raw.decode()
    except UnicodeDecodeError as exc:
        raise rejected("The diff is not UTF-8 text") from exc


def tree_diff(before, after):
    """git's unified diff (binary-safe, renames as delete and add) that turns the files `before`
    into the files `after`, both {path: bytes}; "" when they are the same."""
    with checkout(before) as root:
        git(root, "add", "-A", "-f")
        first = git(root, "write-tree").strip()
        for path in filter(kept, before):
            (root / path).unlink(missing_ok=True)
        write(root, after)
        git(root, "add", "-A", "-f")  # -f: a tracked file can match .gitignore
        second = git(root, "write-tree").strip()
        diff = git(root, "diff", "--binary", "--no-renames", "--no-ext-diff", first, second)
    return text(diff) if diff else ""


def numstat_paths(output):
    """The path of each file in `git apply --numstat -z` output: its new path, or a deleted
    file's old one. A rename's source is not listed, so apply_diff refuses renames and copies."""
    try:
        entries = output.decode().split("\0")[:-1]
    except UnicodeDecodeError as exc:
        raise rejected("The diff names a path that is not UTF-8") from exc
    return list(dict.fromkeys(entry.split("\t", 2)[2] for entry in entries))


def apply_diff(diff, files, workflows=False, prefix=None):
    """Checks a drafted diff against the snapshot `files` ({path: bytes}) and applies it in a
    temporary checkout. Returns {changed: {path: bytes}, deleted: [path], paths, flags}; raises
    diff_rejected naming the failed check. A .github/workflows change is refused unless the caller
    allows it (workflows=True), which flags it; `prefix` is the repository's source_path."""
    raw = text(diff).encode()
    prefix = (prefix or "").strip("/")
    with checkout(files) as root:
        # git's own parse of the diff, not a pattern over its header lines.
        try:
            summary = git(root, "apply", "--summary", stdin=raw)
            numstat = git(root, "apply", "--numstat", "-z", stdin=raw)
        except DomainError as exc:
            raise rejected(f"The diff could not be read: {exc.message}") from exc
        if re.search(rb"^ (?:rename|copy) ", summary, re.M):
            raise rejected("The diff renames or copies a file; write it as a deletion and an addition")
        paths = numstat_paths(numstat)
        if not paths:
            raise rejected("The diff changes no file")
        flags = []
        for path in paths:
            try:
                safe_path(path)
            except ValueError as exc:
                raise rejected(f"{path[:240]!r} is not a safe relative path") from exc
            if git_part(path):
                raise rejected(f"{path!r} is inside .git")
            if prefix and path != prefix and not path.startswith(prefix + "/"):
                raise rejected(f"{path!r} is outside the repository's source path {prefix!r}")
            if path.lower().startswith(".github/workflows/"):
                if not workflows:
                    raise rejected(f"{path!r} changes .github/workflows, which this fix may not do")
                flags = ["workflows"]
        # git apply is atomic and refuses paths outside the work tree or beyond a symlink.
        try:
            git(root, "apply", stdin=raw)
        except DomainError as exc:
            raise rejected(f"The diff does not apply cleanly: {exc.message}") from exc
        changed = {}
        for path in paths:
            target = root / path
            # git, not a mode-line pattern, decides what a mode means (it reads 120755 as a symlink).
            if target.is_symlink() or (target.exists() and not target.is_file()):
                raise rejected(f"{path!r} would be a symlink or submodule, not a regular file")
            if target.exists():
                changed[path] = target.read_bytes()
    return {"changed": changed, "deleted": [p for p in paths if p not in changed], "paths": paths,
            "flags": flags}


def dump(data, indent):
    return (json.dumps(data, indent=indent, ensure_ascii=False) + "\n").encode()


def load(files, name):
    try:
        data = json.loads(files.get(name) or "{}")
    except ValueError as exc:
        raise DomainError("manifest_invalid", f"{name} is not valid JSON", 422) from exc
    if not isinstance(data, dict):
        raise DomainError("manifest_invalid", f"{name} is not a JSON object", 422)
    return data


def dependency_files(files, ecosystem, name, version, action, dist=None, spec=None):
    """The manifest files ({name: bytes}) edited to pin `name` to exactly `version`, or to bump it
    to `version` keeping its ^, ~ or >= prefix. `files` maps manifest names to their content;
    `dist` is the npm registry's dist for that version (tarball and integrity). A `spec`, such as a
    vendored file: tarball, is written in place of the version, and the lock entry keeps `version`."""
    manifest, sections, indent = MANIFESTS[ecosystem]
    data = load(files, manifest)
    found = [s for s in sections if isinstance(data.get(s), dict) and name in data[s]]
    if not found:
        raise DomainError("dependency_not_found", f"{name} is not a direct dependency in {manifest}", 422)
    for section in found:
        prefix = re.match(r"\^|~|>=", str(data[section][name])) if action == "bump" else None
        data[section][name] = spec or (prefix.group() if prefix else "") + version
    edited = {manifest: dump(data, indent)}
    if ecosystem == "npm" and files.get("package-lock.json"):
        # ponytail: only the package's own lock entry is rewritten; transitive entries,
        # composer.lock, pnpm-lock.yaml and yarn.lock stay (npm install / composer update refresh them).
        lock = load(files, "package-lock.json")
        packages = lock.get("packages") or {}
        root = packages.get("") or {}
        for section in found:
            if name in (root.get(section) or {}):
                root[section][name] = data[section][name]
        for entry in (packages.get(f"node_modules/{name}"), (lock.get("dependencies") or {}).get(name)):
            if isinstance(entry, dict):
                entry["version"] = version
                for key, value in (("resolved", (dist or {}).get("tarball")),
                                   ("integrity", (dist or {}).get("integrity"))):
                    if value:
                        entry[key] = value
                    else:  # a stale integrity would fail npm ci; npm resolves the version again
                        entry.pop(key, None)
        edited["package-lock.json"] = dump(lock, 2)
    return edited


def blob_sha(data):
    """git's object id of a blob holding `data`, as GitHub's tree lists it."""
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def open_pull_request(source, repository, branch, base_ref, files, applied, title, body, message):
    """Opens a draft pull request on `repository` (A08) from `base_ref` changed by `applied`
    (apply_diff's result against the snapshot `files` of base_ref), on the new branch `branch`,
    through `source` (a Sources client holding the write token): {branch, pull_number, pull_url,
    head_sha}. A branch or pull request that a crashed attempt left is found by the branch name
    and reused, so at most one is ever opened. It only creates blobs, a tree, a commit, a ref and a
    draft pull request against the repository's watched branch (its source_ref, else its default
    branch): it never moves a ref, never merges and never writes to that branch."""
    if not branch.startswith("asset-monitor/"):
        raise DomainError("unsafe_branch", f"{branch!r} is not an asset-monitor/ branch", 422)
    repo = repository.source_url.removeprefix("https://github.com/")
    api, headers = f"{source.github}/repos/{repo}", source.github_headers()
    ref = source.find(f"{api}/git/ref/heads/{branch}", headers=headers)
    if ref is not None:
        head = ref.json()["object"]["sha"]
        # Reused only when it holds this very change: the message names the approved diff's hash.
        commit = source.get(f"{api}/git/commits/{head}", headers=headers).json()
        if (commit.get("message") or "").strip() != message.strip() or [
                p.get("sha") for p in commit.get("parents") or []] != [base_ref]:
            raise DomainError("branch_exists", f"The branch {branch} already holds another change; delete it on "
                              "GitHub and approve again", 409)
    else:
        tree = source.get(f"{api}/git/commits/{base_ref}", headers=headers).json()["tree"]["sha"]
        listing = source.get(f"{api}/git/trees/{tree}", {"recursive": "1"}, headers).json()
        if listing.get("truncated"):
            raise DomainError("tree_truncated", "GitHub listed only part of the repository tree", 422)
        # The snapshot has no modes: GitHub's tree keeps each file's, and shows symlinks and submodules.
        listed = {entry["path"]: entry for entry in listing["tree"]}
        modes = {path: entry["mode"] for path, entry in listed.items()}
        for path in applied["paths"]:  # all checked before the first write
            parts = path.split("/")
            if any(modes.get("/".join(parts[:i])) in ("120000", "160000") for i in range(1, len(parts) + 1)):
                raise rejected(f"{path!r} is, or sits under, a symlink or submodule in the repository")
            # A tarball applies .gitattributes (line endings, export-subst, export-ignore), so each
            # touched file must be on GitHub exactly as the snapshot held it, and a new one absent.
            before = blob_sha(files[path]) if kept(path) and path in files else None
            if (listed.get(path) or {}).get("sha") != before:
                raise rejected(f"{path!r} on GitHub is not the file the diff was checked against "
                               "(a .gitattributes export rule?); the diff is not pushed")
        entries = []
        for path in applied["paths"]:
            blob = None  # deletes the file
            if path in applied["changed"]:
                content = base64.b64encode(applied["changed"][path]).decode()
                blob = source.send("POST", f"{api}/git/blobs", {"content": content, "encoding": "base64"})["sha"]
            entries.append({"path": path, "mode": modes.get(path, "100644"), "type": "blob", "sha": blob})
        tree = source.send("POST", f"{api}/git/trees", {"base_tree": tree, "tree": entries})["sha"]
        head = source.send("POST", f"{api}/git/commits", {"message": message, "tree": tree, "parents": [base_ref]})["sha"]
        source.send("POST", f"{api}/git/refs", {"ref": f"refs/heads/{branch}", "sha": head})
    owner = repo.split("/")[0]
    pulls = source.get(f"{api}/pulls", {"head": f"{owner}:{branch}", "state": "all"}, headers).json()
    if pulls:
        pull = pulls[0]
    else:
        # The branch the diff was drafted on and the merge check polls.
        base = repository.source_ref or source.get(api, headers=headers).json()["default_branch"]
        pull = source.send("POST", f"{api}/pulls", {"title": title, "head": branch, "base": base, "body": body,
                                                    "draft": True})
    return {"branch": branch, "pull_number": pull["number"], "pull_url": pull["html_url"], "head_sha": head}


def pull_state(source, repository, number):
    """{state, merged, merge_commit_sha} of pull request `number` on `repository`, read through
    `source` (a Sources client holding the write token)."""
    repo = repository.source_url.removeprefix("https://github.com/")
    pull = source.get(f"{source.github}/repos/{repo}/pulls/{number}", headers=source.github_headers()).json()
    return {key: pull.get(key) for key in ("state", "merged", "merge_commit_sha")}
