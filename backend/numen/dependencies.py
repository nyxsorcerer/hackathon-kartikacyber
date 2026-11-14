"""Direct dependencies of an Own repository, their Locked versions and their GitHub sources.
`files` maps a manifest or lockfile name (prefilter.MANIFESTS) to its text."""

import json
import re

import yaml

NPM_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")
# A yarn.lock spec: name@range, the name possibly scoped and the range possibly npm:-prefixed (Berry).
YARN_SPEC = re.compile(r"(@[^/@]+/[^@]+|[^@]+)@(?:npm:)?(.*)")
YARN_VERSION = re.compile(r'\s+version:? "?([^"]+)"?')
GITHUB = re.compile(
    r"(?:github:|(?:git\+)?(?:https?|ssh|git)://(?:git@)?(?:www\.)?github\.com/|git@github\.com:)?"
    r"([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:[/#].*)?"
)
# How the readers below fail on a manifest or lockfile that cannot be read: invalid JSON or YAML,
# or valid JSON or YAML of the wrong shape (an array, a string entry, a package without a name).
UNREADABLE = (ValueError, yaml.YAMLError, AttributeError, KeyError, TypeError)


def load(files, name):
    return json.loads(files.get(name) or "{}")


def direct_dependencies(files):
    """[(ecosystem, name, range)] named in package.json and composer.json, first section wins."""
    found = {}
    for ecosystem, manifest, sections in (
        ("npm", "package.json", NPM_SECTIONS),
        ("composer", "composer.json", ("require", "require-dev")),
    ):
        data = load(files, manifest)
        for section in sections:
            for name, spec in (data.get(section) or {}).items():
                # Composer platform packages (php, ext-*, lib-*, composer-*) have no vendor.
                if ecosystem == "npm" or "/" in name:
                    found.setdefault((ecosystem, name), spec)
    return [(ecosystem, name, spec) for (ecosystem, name), spec in found.items()]


def composer_lock(files):
    lock = load(files, "composer.lock")
    return [*(lock.get("packages") or []), *(lock.get("packages-dev") or [])]


def locked_versions(files):
    """{(ecosystem, name): version} from package-lock.json (or npm-shrinkwrap.json),
    pnpm-lock.yaml, yarn.lock and composer.lock; the first lockfile that has a package wins."""
    versions = {}
    npm = load(files, "npm-shrinkwrap.json") or load(files, "package-lock.json")
    for name, entry in (npm.get("dependencies") or {}).items():  # v1
        versions.setdefault(("npm", name), entry.get("version"))
    for path, entry in (npm.get("packages") or {}).items():  # v2 and v3
        if path.startswith("node_modules/"):
            versions.setdefault(("npm", path.removeprefix("node_modules/")), entry.get("version"))
    pnpm = yaml.safe_load(files.get("pnpm-lock.yaml") or "") or {}
    importer = (pnpm.get("importers") or {}).get(".") or pnpm  # v6+, else the v5 top-level maps
    for section in NPM_SECTIONS:
        for name, entry in (importer.get(section) or {}).items():
            version = str(entry.get("version") if isinstance(entry, dict) else entry)
            # Peers are a suffix: 19.0.0(react@19.0.0) from v6, 17.0.2_react@17.0.2 in v5.
            versions.setdefault(("npm", name), re.split(r"[(_]", version)[0])
    ranges = {name: spec for ecosystem, name, spec in direct_dependencies(files) if ecosystem == "npm"}
    entries, specs = {}, []
    for line in (files.get("yarn.lock") or "").splitlines():
        if line and not line[0].isspace() and not line.startswith("#") and line.endswith(":"):
            specs = [m.groups() for s in line[:-1].split(",") if (m := YARN_SPEC.fullmatch(s.strip().strip('"')))]
        elif specs and (m := YARN_VERSION.fullmatch(line)):
            for name, spec in specs:
                entries.setdefault(name, {})[spec] = m.group(1)
            specs = []  # a dependency named "version" further down is not this entry's version
    for name, found in entries.items():
        versions.setdefault(("npm", name), found.get(ranges.get(name), next(iter(found.values()))))
    for entry in composer_lock(files):
        versions.setdefault(("composer", entry["name"]), entry.get("version"))
    return versions


def composer_sources(files):
    """{name: source.url} recorded in composer.lock, used before Packagist."""
    return {entry["name"]: (entry.get("source") or {}).get("url") for entry in composer_lock(files)}


def github_url(value):
    """https://github.com/owner/repo (lower case) for an npm repository field (a string or
    {url, directory}) or a composer source.url, or None when it is not a GitHub repository."""
    if isinstance(value, dict):
        value = value.get("url")
    match = GITHUB.fullmatch(value.strip()) if isinstance(value, str) else None
    return f"https://github.com/{match[1]}/{match[2]}".lower() if match else None
