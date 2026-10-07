"""Numen's release fingerprint check, staged as recipe.py beside release-corpus.json.

It fetches the static files that best split the releases still possible and keeps the
releases whose exact bytes the target serves. It uses only the standard library and the
gateway's fetch, so it runs in the same sandbox as a generated recipe.
"""
import json
import os
import sys
from pathlib import Path
from urllib.parse import urljoin


def next_probe(probes, candidates):
    """The unused file whose bytes split the remaining candidates into the most groups."""
    best, best_key = None, None
    for probe in probes:
        groups = sum(1 for versions in probe["digests"].values() if candidates.intersection(versions))
        if groups < 2:
            continue
        covered = len(candidates.intersection(v for vs in probe["digests"].values() for v in vs))
        key = (groups, covered, -probe.get("size", 0))
        if best_key is None or key > best_key:
            best, best_key = probe, key
    return best


def match(fetch, base_url, corpus, budget):
    order = [release["version"] for release in corpus.get("releases", [])]
    candidates = set(order)
    probes = list(corpus.get("probes", []))
    evidence, unmatched, requests = [], [], 0
    while requests < budget:
        probe = next_probe(probes, candidates)
        if probe is None:
            break
        probes.remove(probe)
        url = urljoin(base_url, probe["path"])
        requests += 1
        record = {"url": url, "path": probe["path"]}
        try:
            response = fetch(url, method="GET")
        except Exception as exc:  # A denied, unreachable or exhausted request ends nothing else.
            evidence.append({**record, "error": type(exc).__name__})
            continue
        if response.get("status") != 200:
            evidence.append({**record, "status": response.get("status")})
            continue
        versions = probe["digests"].get(response.get("sha256"), [])
        evidence.append({**record, "status": 200, "sha256": response.get("sha256"), "versions": versions})
        if not versions:
            unmatched.append(probe["path"])
            continue
        candidates &= set(versions)
    matched = sum(1 for item in evidence if item.get("versions"))
    return {
        "candidates": [v for v in order if v in candidates] if matched else [],
        "matched": matched,
        "unmatched": unmatched,
        "requests": requests,
        "evidence": evidence,
    }


def main():
    target = json.loads(Path(os.environ["NUMEN_TARGET_INPUT"]).read_text())
    corpus = json.loads((Path(__file__).parent / "release-corpus.json").read_text())
    from numen_runner.fetch import fetch

    print(json.dumps(match(fetch, target["base_url"], corpus, int(target.get("budget", 10)))))


if __name__ == "__main__":
    sys.exit(main())
