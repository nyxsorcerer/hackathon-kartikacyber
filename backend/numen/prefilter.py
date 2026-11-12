"""The Pre-filter: rule-based flags for a change that touches sensitive files. It never decides
anything on its own; Triage and the Operator see its flags."""

import re
from pathlib import PurePosixPath

MANIFESTS = frozenset({
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
    "composer.json", "composer.lock",
})
RULES = ("dependency_manifest", "package_scripts", "ci_workflow", "minified_or_obfuscated", "auth_or_crypto")
CI = re.compile(
    r"(^|/)(\.github/workflows|\.circleci)/"
    r"|(^|/)(\.gitlab-ci\.yml|Jenkinsfile|azure-pipelines\.yml|bitbucket-pipelines\.yml)$"
)
AUTH = re.compile(
    r"auth|login|session|token|oauth|jwt|passw|crypt|cipher|hash|sign|secret|key|permission|acl|csrf",
    re.IGNORECASE,
)
SCRIPTS = re.compile(r'"scripts"\s*:')
# npm lifecycle hooks, flagged even when the hunk does not show the "scripts" line above them.
LIFECYCLE = re.compile(
    r'"(install|prepare|prepublishOnly'
    r'|(pre|post)(install|pack|publish|start|test|stop|restart|version|shrinkwrap))"\s*:'
)
OBFUSCATED = re.compile(r"_0x[0-9a-f]{4,}|eval\(atob\(|String\.fromCharCode\(")


def prefilter(files, diff):
    """[{rule, paths}] for each rule the change matches, in RULES order."""
    hits = {}
    for file in files:
        for path in {file.get("path"), file.get("previous_path")} - {None}:
            name = PurePosixPath(path).name
            for rule, matched in (
                ("dependency_manifest", name in MANIFESTS),
                ("ci_workflow", CI.search(path)),
                ("minified_or_obfuscated", name.endswith((".min.js", ".min.css"))),
                ("auth_or_crypto", AUTH.search(path)),
            ):
                if matched:
                    hits.setdefault(rule, set()).add(path)
    path = None  # the file the current diff lines belong to, from its +++ header
    scripts = False  # whether the line is inside package.json's "scripts" object
    for line in (diff or "").splitlines():
        if line.startswith("+++ "):
            path, scripts = line[4:].split("\t")[0].strip(), False
            continue
        if path is None:
            continue
        if line.startswith(("@@", "--- ")):
            # A new hunk or file. A hunk that starts inside "scripts" without showing that line
            # is caught only by the lifecycle hook names.
            scripts = False
        elif PurePosixPath(path).name == "package.json":
            changed, body = line[:1] in ("+", "-"), line[1:]
            if match := SCRIPTS.search(body):
                # Script values are strings, so the object ends at the first closing brace.
                rest = body[match.end():].lstrip()
                scripts = rest.startswith("{") and "}" not in rest
                flagged = changed
            elif scripts and body.lstrip().startswith("}"):
                scripts, flagged = False, changed
            else:
                flagged = changed and (scripts or LIFECYCLE.search(body))
            if flagged:
                hits.setdefault("package_scripts", set()).add(path)
        if line.startswith("+") and (len(line) > 1001 or OBFUSCATED.search(line)):
            hits.setdefault("minified_or_obfuscated", set()).add(path)
    return [{"rule": rule, "paths": sorted(hits[rule])} for rule in RULES if rule in hits]
