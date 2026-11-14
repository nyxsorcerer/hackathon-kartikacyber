"""A Malicious change's static Proof and cleanup report (A07, ADR-0004 point 6). The agent drafts
them; these helpers check the drafts against the commit. The payload is only ever read as bytes."""

import hashlib

from .security import DomainError

# A static Proof revision holds these files (AC-12's required set for a Malicious change).
STATIC_REQUIRED = ("report.md", "detection-rule.yar", "indicators.json")
RULE_BYTES = 64 * 1024
UNVALIDATED = "The Detection rule has not been validated yet"
REMOVED = ("removed", "D")  # GitHub's and SVN's status for a deleted file
# The trees a Detection rule is scanned against, each sent to the runner as its own archive.
TREES = ("changed", "parent", "baseline")


def changed_files(commit, tree):
    """{commit path: tree path} for each file the commit added or changed that the snapshot `tree`
    holds. An SVN path such as /slug/trunk/x names the snapshot's x by suffix."""
    found = {}
    for entry in commit.data.get("files", []):
        path = entry.get("path") or ""
        if entry.get("status") in REMOVED:
            continue
        # ponytail: the longest suffix on a directory boundary; an SVN revision that also touches
        # tags/ maps those paths onto trunk's file. Match the svn_url prefix if that matters.
        matches = [t for t in tree if t != "manifest.json" and (path == t or path.endswith("/" + t))]
        if matches:
            found[path] = max(matches, key=len)
    return found


def added_lines(diff):
    return [line[1:] for line in (diff or "").splitlines() if line.startswith("+") and not line.startswith("+++")]


def check_indicators(commit, tree, indicators):
    """The agent's indicators as application code checked them: a file must be one the commit added
    or changed, hashed here from `tree`, and a host, URL or command must occur in a line the diff
    adds. Everything else is listed in rejected, with the reason."""
    changed, added = changed_files(commit, tree), added_lines(commit.data.get("diff"))
    named = {entry.get("path") for entry in commit.data.get("files", []) if entry.get("status") not in REMOVED}
    checked = {"files": [], "hosts": [], "urls": [], "commands": [], "rejected": []}
    for path in dict.fromkeys(indicators["files"]):
        if path in changed:
            checked["files"].append({"path": path, "sha256": hashlib.sha256(tree[changed[path]]).hexdigest()})
        else:
            reason = "The stored snapshot does not hold this file" if path in named else "Not a file this commit added or changed"
            checked["rejected"].append({"kind": "file", "value": path, "reason": reason})
    for key in ("hosts", "urls", "commands"):
        for value in dict.fromkeys(indicators[key]):
            if value and any(value in line for line in added):
                checked[key].append(value)
            else:
                checked["rejected"].append({"kind": key[:-1], "value": value, "reason": "Not in the lines this commit added"})
    return checked


def rule_text(files):
    """(the drafted Detection rule's text, None), or (None, the failed rule check)."""
    content = files.get("detection-rule.yar")
    message = None
    if not content:
        message = "No Detection rule was drafted"
    elif len(content) > RULE_BYTES:
        message = "The Detection rule is larger than 64 KiB"
    else:
        try:
            return content.decode(), None
        except UnicodeDecodeError:
            message = "The Detection rule is not UTF-8 text"
    return None, {"name": "rule", "status": "failed", "message": message}


def static_state(proof):
    """AC-12's artifact state of a static Proof: complete only once its Detection rule validated.
    Each check is {name, status, message}; the failed ones' messages are its limitations."""
    missing = [path for path in STATIC_REQUIRED if path not in proof.get("files", [])]
    failed = [check["message"] for check in proof.get("checks", []) if check["status"] == "failed"]
    validated = proof.get("status") == "validated"
    return {
        "status": "complete" if validated and not missing else "draft",
        "missing": missing,
        "limitations": failed or ([] if validated else [UNVALIDATED]),
        "vulnerable_version": None,
    }


# Each tree's check: (tree, whether the rule must match it, passed message, failed message), for a
# commit and, with served=True, for served content, whose trees are the changed, previous and
# Baseline fetches' stored bytes (A07).
COMMIT_CHECKS = (
    ("changed", True, "The Detection rule matches files this commit added or changed",
     "The Detection rule matches none of the files this commit added or changed"),
    ("parent", False, "The Detection rule matches no file in the parent tree",
     "The Detection rule also matches files in the parent tree"),
    ("baseline", False, "The Detection rule matches no file in the Baseline tree",
     "The Detection rule also matches files in the Baseline tree"),
)
SERVED_CHECKS = (
    ("changed", True, "The Detection rule matches the changed fetch's stored bytes",
     "The Detection rule matches none of the changed fetch's stored bytes"),
    ("parent", False, "The Detection rule matches none of the previous fetch's stored bytes",
     "The Detection rule also matches the previous fetch's stored bytes"),
    ("baseline", False, "The Detection rule matches none of the Baseline fetch's stored bytes",
     "The Detection rule also matches the Baseline fetch's stored bytes"),
)


def checks(result, scanned, baseline_skipped, served=False):
    """A07's validation checks from a detection_rule run's result: the rule compiles, matches a file
    the commit added or changed, and matches no file in the parent tree or, unless `baseline_skipped`
    says why not, the Baseline tree. `scanned` names the trees sent with files; one sent empty, such
    as a root commit's parent, matches nothing. Each check is {name, status, message[, files, count]}.
    With served, the messages name a served-content change's fetches."""
    malformed = DomainError("invalid_rule_result", "The Detection rule run returned a malformed result", 422)
    if not isinstance(result, dict) or not isinstance(result.get("compiled"), bool):
        raise malformed
    if not result["compiled"]:
        if not isinstance(result.get("error"), str):
            raise malformed
        return [{"name": "rule", "status": "failed", "message": "The Detection rule does not compile: " + result["error"]}]
    matches = result.get("matches")
    if not isinstance(matches, dict):
        raise malformed
    found = [{"name": "rule", "status": "passed", "message": "The Detection rule compiles"}]
    for tree, wanted, passed, failed in SERVED_CHECKS if served else COMMIT_CHECKS:
        if tree == "baseline" and baseline_skipped:
            found.append({"name": tree, "status": "skipped", "message": baseline_skipped})
            continue
        entry = matches.get(tree) if tree in scanned else {"files": [], "count": 0}
        if not (isinstance(entry, dict) and isinstance(entry.get("files"), list) and isinstance(entry.get("count"), int)):
            raise malformed
        ok = bool(entry["count"]) == wanted
        found.append({"name": tree, "status": "passed" if ok else "failed", "message": passed if ok else failed,
                      "files": entry["files"], "count": entry["count"]})
    return found
