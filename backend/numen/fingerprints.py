"""Release fingerprints that a remote check can actually observe.

A site publishes its front-end assets byte for byte but executes server code, and it
normally does not deploy (or refuses) manifests, lock files and configuration. Requesting
those also reads as sensitive-file probing, so only published assets are fingerprinted.
The plan lists the assets whose bytes differ between captured releases: fetching a few
of them narrows the deployed release.
"""
from collections import defaultdict
from pathlib import Path, PurePosixPath

ASSET_SUFFIXES = (".js", ".mjs", ".css", ".svg", ".html", ".htm")
# Documentation some platforms serve on purpose, e.g. a WordPress plugin's readme.txt.
DOCUMENT_NAMES = frozenset({"readme.txt", "readme.md", "changelog.txt", "changelog.md", "changes.txt", "version"})
PROBE_LIMIT = 200
MATCHER = Path(__file__).with_name("fingerprint_probe.py")


def published(path):
    parts = PurePosixPath(path).parts
    if any(part.startswith(".") for part in parts):
        return False
    return path.endswith(ASSET_SUFFIXES) or parts[-1].lower() in DOCUMENT_NAMES


def strip_root(files):
    """Release packages wrap their files in one versioned folder (app-1.2.3/...); drop it so
    paths are comparable between releases and match the URLs a site serves."""
    roots = {path.split("/", 1)[0] for path in files}
    if len(roots) != 1 or any("/" not in path for path in files):
        return files
    return {path.split("/", 1)[1]: content for path, content in files.items()}


def plan(corpus):
    """Distinguishing files (most release groups first) and the releases they cannot separate."""
    releases = [release["version"] for release in corpus.get("releases", [])]
    probes = [
        {
            "path": path,
            "size": max(entry.get("size", 0) for entry in digests.values()),
            "digests": {digest: entry["versions"] for digest, entry in digests.items()},
        }
        for path, digests in corpus.get("fingerprints", {}).items()
        if len(digests) > 1 and published(path)
    ]
    probes.sort(key=lambda p: (-len(p["digests"]), p["size"], p["path"]))
    probes = probes[:PROBE_LIMIT]
    groups = defaultdict(list)
    for version in releases:
        signature = tuple(
            next((d for d, versions in p["digests"].items() if version in versions), None)
            for p in probes
        )
        groups[signature].append(version)
    return {"probes": probes, "resolution": list(groups.values())}


def coverage(corpus):
    """The corpus summary kept with a recipe and shown to the operator and the agent."""
    return {
        "releases": corpus["releases"],
        "limitations": corpus["limitations"],
        "complete": corpus["complete"],
        "fingerprinted_paths": len(corpus.get("fingerprints", {})),
        "distinguishing_paths": len(corpus.get("probes", [])),
        "resolution": corpus.get("resolution", []),
    }
