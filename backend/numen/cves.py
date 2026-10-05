import os
import subprocess
from decimal import Decimal, InvalidOperation
from urllib.parse import urlparse

import semver
from .security import fingerprint


def parse_cve(raw):
    scores = []
    for version, key in (
        ("2.0", "cvssMetricV2"),
        ("3.0", "cvssMetricV30"),
        ("3.1", "cvssMetricV31"),
        ("4.0", "cvssMetricV40"),
    ):
        for entry in raw.get("metrics", {}).get(key, []):
            data = entry.get("cvssData", {})
            try:
                score = Decimal(str(data.get("baseScore")))
                if (
                    not score.is_finite()
                    or not 0 <= score <= 10
                    or data.get("version", version) != version
                ):
                    continue
            except InvalidOperation:
                continue
            scores.append(
                {
                    "version": version,
                    "base_score": float(score),
                    "vector": data.get("vectorString"),
                    "source": entry.get("source"),
                    "kind": "Base",
                }
            )
    description = next(
        (d["value"] for d in raw.get("descriptions", []) if d.get("lang") == "en"), ""
    )
    return {
        "title": description[:180] or raw["id"],
        "description": description,
        "published_at": raw.get("published"),
        "modified_at": raw.get("lastModified"),
        "scores": scores,
        "references": [
            reference
            for reference in raw.get("references", [])
            if safe_reference(reference.get("url", ""))
        ],
        "affected_versions": [],
        "fixed_versions": [],
        "rejected": raw.get("vulnStatus") == "Rejected",
        "configurations": raw.get("configurations", []),
    }


def cpe_identity(value):
    pieces = value.split(":")
    return ":".join(pieces[:5]) if len(pieces) >= 5 else ""


def cpe_matches(record, selector):
    # Exact part/vendor/product; versions are evaluated separately.
    return bool(cpe_identity(record) and cpe_identity(record) == cpe_identity(selector))


def product_match(program, cve, link):
    if link.confirmed is False:
        return "rejected"
    if link.confirmed is True:
        return "confirmed"
    selectors = program.config.get("cve_selectors", [])
    for config in cve.raw.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable") and any(
                    s.get("type") == "cpe" and cpe_matches(match.get("criteria", ""), s["value"])
                    for s in selectors
                ):
                    return "confirmed"
    return "potential"


def gate(program, cve, link):
    config = program.config
    matched = product_match(program, cve, link)
    reason, witness = None, None
    if matched != "confirmed":
        reason = "Product identity requires confirmation"
    elif cve.data.get("rejected"):
        reason = "CVE record is rejected"
    elif config.get("cve_min_score") is None or not config.get("cve_versions"):
        reason = "Save scoring versions and a minimum Base score"
    else:
        qualifying = [
            s
            for s in cve.data.get("scores", [])
            if s["version"] in config["cve_versions"]
            and Decimal(str(s["base_score"])) >= Decimal(str(config["cve_min_score"]))
        ]
        if qualifying:
            witness = max(qualifying, key=lambda s: s["base_score"])
        else:
            reason = "No selected scoring version meets the minimum Base score"
    return {
        "match_status": matched,
        "eligible": reason is None,
        "eligibility_reason": reason,
        "qualifying_score": witness,
    }


def gate_hash(program, cve, link):
    return fingerprint(
        {
            "record": {
                k: v for k, v in cve.data.items() if k not in ("published_at", "modified_at")
            },
            "match": product_match(program, cve, link),
            "selectors": program.config.get("cve_selectors"),
            "min": program.config.get("cve_min_score"),
            "versions": program.config.get("cve_versions"),
        }
    )


def compare_versions(a, b, scheme):
    if scheme == "semver":
        try:
            return semver.Version.parse(a.lstrip("v")).compare(b.lstrip("v"))
        except ValueError:
            return None
    if scheme == "php":
        try:
            proc = subprocess.run(
                [
                    os.getenv("NUMEN_PHP", "php"),
                    "-r",
                    "echo version_compare($argv[1], $argv[2]);",
                    "--",
                    a,
                    b,
                ],
                capture_output=True,
                timeout=5,
                check=True,
            )
            return int(proc.stdout)
        except (FileNotFoundError, subprocess.SubprocessError, ValueError):
            return None
    return None


def version_scheme(program):
    return (
        "php"
        if program.source_kind == "wordpress"
        else program.config.get("version_scheme", "unknown")
    )


def vulnerable_bound(program, cve):
    """Highest version a record still reports as affected, for pinning vulnerable source."""
    scheme, candidates = version_scheme(program), []
    for entry in cve.raw.get("affected", []):
        for data in entry.get("affectedData", []):
            collection = data.get("repo") or data.get("collectionURL")
            if collection and collection.rstrip("/") != (program.source_url or "").rstrip("/"):
                continue
            for version in data.get("versions", []):
                if version.get("status") != "affected":
                    continue
                if version.get("lessThanOrEqual"):
                    candidates.append((version["lessThanOrEqual"], True))
                elif version.get("lessThan"):
                    candidates.append((version["lessThan"], False))
                elif version.get("version") not in (None, "", "*", "-"):
                    candidates.append((version["version"], True))
    selectors = program.config.get("cve_selectors", [])
    for config in cve.raw.get("configurations", []):
        if config.get("negate"):
            continue
        for node in config.get("nodes", []):
            if node.get("negate"):
                continue
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable") or not any(
                    s.get("type") == "cpe" and cpe_matches(match.get("criteria", ""), s["value"])
                    for s in selectors
                ):
                    continue
                if match.get("versionEndIncluding"):
                    candidates.append((match["versionEndIncluding"], True))
                elif match.get("versionEndExcluding"):
                    candidates.append((match["versionEndExcluding"], False))
    best = None
    for version, inclusive in candidates:
        # An unorderable bound cannot rank releases, so it is not a usable pin.
        if compare_versions(version, version, scheme) is None:
            continue
        compared = compare_versions(version, best[0], scheme) if best else 1
        if compared is not None and (compared > 0 or (compared == 0 and inclusive)):
            best = (version, inclusive)
    return {"version": best[0], "inclusive": best[1]} if best else None


def range_match(version, match, scheme):
    pieces = match.get("criteria", "").split(":")
    if len(pieces) < 6:
        return None
    exact = pieces[5]
    if exact not in ("*", "-"):
        compared = compare_versions(version, exact, scheme)
        if compared is None:
            return None
        if compared != 0:
            return False
    for key, test in (
        ("versionStartIncluding", lambda c: c >= 0),
        ("versionStartExcluding", lambda c: c > 0),
        ("versionEndIncluding", lambda c: c <= 0),
        ("versionEndExcluding", lambda c: c < 0),
    ):
        if match.get(key):
            compared = compare_versions(version, match[key], scheme)
            if compared is None:
                return None
            if not test(compared):
                return False
    if exact == "-":
        return None
    return True


def applicability(program, cve, observation):
    if (
        not observation
        or observation.data.get("status") != "detected"
        or not observation.data.get("version")
    ):
        return "unknown"
    scheme = version_scheme(program)
    values = []
    selectors = program.config.get("cve_selectors", [])
    for config in cve.raw.get("configurations", []):
        # Environmental AND/negation requires evidence about other products.
        if config.get("operator", "OR") != "OR" or config.get("negate"):
            return "unknown"
        for node in config.get("nodes", []):
            if node.get("operator", "OR") != "OR" or node.get("negate") or node.get("children"):
                return "unknown"
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    return "unknown"
                if any(
                    s.get("type") == "cpe" and cpe_matches(match.get("criteria", ""), s["value"])
                    for s in selectors
                ):
                    values.append(range_match(observation.data["version"], match, scheme))
    if not values or None in values:
        return "unknown"
    return "affected" if any(values) else "not affected"


def safe_reference(value):
    parsed = urlparse(value)
    return parsed.scheme in ("http", "https") and bool(parsed.hostname)


def analysis_superseded(program, cve, link, saved_hash):
    return bool(saved_hash and gate_hash(program, cve, link) != saved_hash)
