"""The Advisory check (A09). Its pins: the runtime versions an Application pins in its Dockerfiles,
.nvmrc, package.json engines and composer.json platform, and its package versions and Locked
versions. A version that cannot be read is None with a reason, which reads as unknown, never as not
exposed. `files` maps a snapshot path to its bytes or text. Its matches: the OSV, GHSA and NVD
records of those pins, with records that share an alias as one vulnerability, and Exposure from each
record's affected ranges. Feed records are untrusted, so every field is checked before it is used.

A pin's identity is ("runtime", None, name) or ("package", ecosystem, name). Ranges are a list of
comparator lists, such as [[">=", "20.0.0"], ["<", "20.19.5"]]: a version is inside when every
comparator of one list holds, and [] holds for every version."""

import operator
import re
from functools import cmp_to_key
from pathlib import PurePosixPath

from . import cves, dependencies
from .prefilter import MANIFESTS
from .security import DomainError

# The runtimes whose pins are collected, by the name their images and settings use, with their OSV
# (ecosystem, name) and NVD CPE. Runtime versions compare as plain semver; GHSA has no runtime.
RUNTIMES = {
    "node": {"osv": ("Bitnami", "node"), "cpe": "cpe:2.3:a:nodejs:node.js"},
    "php": {"osv": ("Bitnami", "php"), "cpe": "cpe:2.3:a:php:php"},
}
ECOSYSTEMS = {
    "npm": {"osv": "npm", "ghsa": "npm", "scheme": "semver"},
    "composer": {"osv": "Packagist", "ghsa": "composer", "scheme": "composer"},
}
OSV_PACKAGES = {spec["osv"]: name for name, spec in ECOSYSTEMS.items()}
OSV_RUNTIMES = {spec["osv"]: name for name, spec in RUNTIMES.items()}
GHSA_PACKAGES = {spec["ghsa"]: name for name, spec in ECOSYSTEMS.items()}
CPE_RUNTIMES = {spec["cpe"]: name for name, spec in RUNTIMES.items()}
FEEDS = ("ghsa", "osv", "nvd")  # the order in which a feed's summary wins
# Only ids of this shape are kept as aliases.
ALIAS = re.compile(r"[A-Z][A-Z0-9]*-[A-Za-z0-9._-]{1,80}")
COMPARATOR = re.compile(r"(<=|>=|<|>|=)?\s*(\S+)")
OPERATORS = {"<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge, "=": operator.eq}
SEVERITIES = ("critical", "high", "moderate", "medium", "low")
# The order in which dependencies.locked_versions lets a lockfile's version win.
LOCKFILES = ("npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "composer.lock")
MANIFEST = {"npm": "package.json", "composer": "composer.json"}
# [registry/][library/]name[:tag][@digest]; a registry host has a dot or a port, or is localhost.
IMAGE = re.compile(r"(?:(?:[^/]*[.:][^/]*|localhost)/)?(?:library/)?(?P<name>[^/:@]+)(?::(?P<tag>[^/@]+))?(?:@\S+)?")
TAG = re.compile(r"v?(\d+\.\d+\.\d+)(?:-[\w.-]+)?")
EXACT = re.compile(r"=?v?(\d+\.\d+\.\d+)")
# What a bump may write, as feed data is untrusted: a fixed version, and an image tag.
FIXED = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?")
IMAGE_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")


def dockerfile(path):
    name = PurePosixPath(path).name
    return name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile")


def pin_file(path):
    """Whether a change to `path` can change a pin: a manifest, a lockfile, .nvmrc or a Dockerfile."""
    name = PurePosixPath(path).name
    return name in MANIFESTS or name == ".nvmrc" or dockerfile(path)


def dockerfile_pins(path, text):
    """A pin for each FROM whose image is a runtime's: node:20.11.1-alpine is node 20.11.1. Options
    such as --platform, and earlier stages' names, are skipped."""
    pins, stages = [], set()
    for line in text.replace("\\\n", " ").splitlines():
        words = line.split()
        args = [word for word in words[1:] if not word.startswith("--")]
        if not words or words[0].upper() != "FROM" or not args:
            continue
        image = args[0]
        stage = image.lower() in stages
        if len(args) > 2 and args[1].upper() == "AS":
            stages.add(args[2].lower())
        match = IMAGE.fullmatch(image)
        if stage or not match or match["name"] not in RUNTIMES:
            continue
        tag = match["tag"]
        exact = tag and "$" not in image and TAG.fullmatch(tag)
        reason = None if exact else "a variable" if "$" in image else "no tag" if tag is None else "a moving tag"
        pins.append({"name": match["name"], "version": exact[1] if exact else None, "field": "dockerfile",
                     "source": path, "image": image[:match.end("name")], "tag": tag, "reason": reason})
    return pins


def exact_pin(name, field, source, value, inexact):
    exact = EXACT.fullmatch(value.strip())
    reason = None if exact else "a variable" if "$" in value else inexact
    return {"name": name, "version": exact[1] if exact else None, "field": field, "source": source, "reason": reason}


def nvmrc_pin(path, text):
    value = next((line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")), "")
    return exact_pin("node", "nvmrc", path, value, "a moving tag")


def engines_pin(path, package):
    node = (package.get("engines") or {}).get("node")
    return exact_pin("node", "engines", path, node, "a range") if node is not None else None


def platform_pin(path, composer):
    php = (((composer.get("config") or {}).get("platform")) or {}).get("php")
    return exact_pin("php", "platform", path, php, "a range") if php is not None else None


def package_pins(manifests, root, overrides):
    locked = dependencies.locked_versions(manifests)
    found = {}  # (ecosystem, name): the lockfile its version came from
    for lockfile in LOCKFILES:
        if lockfile in manifests:
            alone = {name: text for name, text in manifests.items() if name not in LOCKFILES or name == lockfile}
            for key in dependencies.locked_versions(alone):
                found.setdefault(key, lockfile)
    direct = {(ecosystem, name) for ecosystem, name, _ in dependencies.direct_dependencies(manifests)}
    pins = []
    for key in sorted({*locked, *direct}):
        version, source = locked.get(key), root + found.get(key, MANIFEST[key[0]])
        if key in overrides:
            version, how = overrides[key]
            source = f"Locked version ({how})"
        pins.append({"ecosystem": key[0], "name": key[1], "version": version, "source": source,
                     "direct": key in direct, "reason": None if version else "no lockfile entry"})
    return pins


def collect(files, prefix, overrides):
    """{runtimes, packages} of a snapshot: the manifests, lockfiles and .nvmrc at `prefix` (the
    repository's source_path), and Dockerfiles at any depth. `overrides` maps (ecosystem, name) to
    (version, how) for a Locked version the Operator entered or the Deployed version gave."""
    root = prefix.rstrip("/") + "/" if prefix else ""  # as Sources reads source_path

    def read(path):
        value = files[path]
        return value.decode("utf-8", "replace") if isinstance(value, bytes) else value

    manifests = {name: read(root + name) for name in MANIFESTS if root + name in files}
    try:
        runtimes = [pin for path in sorted(files) if dockerfile(path) for pin in dockerfile_pins(path, read(path))]
        if root + ".nvmrc" in files:
            runtimes.append(nvmrc_pin(root + ".nvmrc", read(root + ".nvmrc")))
        for pin in (engines_pin(root + "package.json", dependencies.load(manifests, "package.json")),
                    platform_pin(root + "composer.json", dependencies.load(manifests, "composer.json"))):
            if pin:
                runtimes.append(pin)
        packages = package_pins(manifests, root, overrides)
    except dependencies.UNREADABLE as exc:
        raise DomainError("invalid_manifest", f"A manifest or lockfile could not be read: {exc}", 422) from exc
    return {"runtimes": runtimes, "packages": packages}


def listed(value):
    return value if isinstance(value, list) else []


def dicts(value):
    return [item for item in listed(value) if isinstance(item, dict)]


def text(value, limit=500):
    return value.strip()[:limit] if isinstance(value, str) and value.strip() else None


def composer_version(value):
    # ponytail: stability suffixes (-beta, -RC1, dev-main) read as unknown; add composer's
    # stability order if Locked versions use them
    match = re.fullmatch(r"v?(\d+(?:\.\d+)*)", value.strip())
    return tuple(int(part) for part in match[1].split(".")) if match else None


def compare(a, b, scheme):
    """-1, 0 or 1, or None when either version cannot be read: semver for npm and the runtimes
    (ponytail: npm's prerelease range rules are not modelled), composer as a numeric tuple."""
    if scheme == "semver":
        return cves.compare_versions(a, b, "semver")
    if scheme == "composer":
        x, y = composer_version(a), composer_version(b)
        if x is None or y is None:
            return None
        width = max(len(x), len(y))
        x, y = x + (0,) * (width - len(x)), y + (0,) * (width - len(y))
        return (x > y) - (x < y)
    return None


def readable(version, scheme):
    return isinstance(version, str) and compare(version, version, scheme) is not None


def scheme_of(key):
    return ECOSYSTEMS[key[1]]["scheme"] if key[0] == "package" else "semver"


def affected(version, ranges, scheme):
    """Whether `version` is inside `ranges`: True, False, or None when a version or bound cannot be
    read and no list holds. A comparator that fails rules its list out even beside an unreadable one."""
    unknown = False
    for comparators in ranges:
        held = []
        for op, bound in comparators:
            compared = compare(version, bound, scheme) if op in OPERATORS and isinstance(version, str) else None
            held.append(None if compared is None else OPERATORS[op](compared, 0))
        if False in held:
            continue
        if None in held:
            unknown = True
        else:
            return True
    return None if unknown else False


def pin_state(version, ranges, scheme):
    """exposed when any feed's ranges hold the version, else unknown when one cannot tell (which
    counts as exposed), else not_exposed. `ranges` is {feed: ranges}."""
    found = [affected(version, feed_ranges, scheme) for feed_ranges in ranges.values()]
    return "exposed" if True in found else "unknown" if None in found else "not_exposed"


def worst(states):
    return next((state for state in ("exposed", "unknown") if state in states), "not_exposed")


def osv_ranges(record):
    """{pin identity: ranges} of an OSV record: its SEMVER and ECOSYSTEM events, each introduced up
    to the next fixed (exclusive) or last_affected (inclusive), with introduced 0 no lower bound."""
    found = {}
    for entry in dicts(record.get("affected")):
        package = entry.get("package") if isinstance(entry.get("package"), dict) else {}
        ecosystem, name = package.get("ecosystem"), package.get("name")
        if not isinstance(ecosystem, str) or not isinstance(name, str):
            continue
        if (ecosystem, name) in OSV_RUNTIMES:
            key = ("runtime", None, OSV_RUNTIMES[(ecosystem, name)])
        elif ecosystem in OSV_PACKAGES:
            key = ("package", OSV_PACKAGES[ecosystem], name)
        else:
            continue
        ranges, events = found.setdefault(key, []), False
        for item in dicts(entry.get("ranges")):
            if item.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            events, lower = True, None
            for event in dicts(item.get("events")):
                kind = next((k for k in ("introduced", "fixed", "last_affected") if isinstance(event.get(k), str)), None)
                if kind == "introduced" and lower is None:
                    lower = [] if event[kind] == "0" else [[">=", event[kind]]]
                elif kind in ("fixed", "last_affected") and lower is not None:
                    ranges.append(lower + [["<" if kind == "fixed" else "<=", event[kind]]])
                    lower = None
            if lower is not None:
                ranges.append(lower)
        # ponytail: listed versions count only without a range, since OSV lists a range's versions
        # there too; take their union if a record lists versions beyond its ranges
        if not events:
            ranges += [[["=", version]] for version in listed(entry.get("versions")) if isinstance(version, str)]
    return {key: ranges for key, ranges in found.items() if ranges}


def ghsa_ranges(advisory):
    """{pin identity: ranges} of a GitHub advisory: each vulnerable_version_range split on commas,
    bounded by first_patched_version (which a bump moves to, lowest_fixed) unless it has a '<'
    bound or a '<=' bound the patched version is not above, which it would narrow."""
    found = {}
    for item in dicts(advisory.get("vulnerabilities")):
        package = item.get("package") if isinstance(item.get("package"), dict) else {}
        ecosystem, name = package.get("ecosystem"), package.get("name")
        if not isinstance(ecosystem, str) or ecosystem not in GHSA_PACKAGES or not isinstance(name, str):
            continue
        spec, patched = item.get("vulnerable_version_range"), item.get("first_patched_version")
        comparators = [list(match.groups("=")) if (match := COMPARATOR.fullmatch(piece.strip())) else ["?", piece]
                       for piece in spec.split(",")] if text(spec) else []
        scheme = ECOSYSTEMS[GHSA_PACKAGES[ecosystem]]["scheme"]
        if isinstance(patched, str) and not any(op == "<" or op == "<=" and compare(patched, bound, scheme) != 1
                                                for op, bound in comparators):
            comparators.append(["<", patched])
        if comparators:
            found.setdefault(("package", GHSA_PACKAGES[ecosystem], name), []).append(comparators)
    return found


def nvd_ranges(raw):
    """{pin identity: ranges} of an NVD record: each vulnerable cpeMatch of a runtime's CPE, by its
    versionStart and versionEnd fields and the version in its criteria ("-" reads as unknown)."""
    found = {}
    for config in dicts(raw.get("configurations")):
        for node in dicts(config.get("nodes")):
            if config.get("negate") or node.get("negate"):
                continue
            for match in dicts(node.get("cpeMatch")):
                criteria = match.get("criteria")
                runtime = isinstance(criteria, str) and CPE_RUNTIMES.get(cves.cpe_identity(criteria))
                if not match.get("vulnerable") or not runtime:
                    continue
                exact = (criteria.split(":") + ["*"])[5]
                comparators = [] if exact == "*" else [["=", exact]]
                comparators += [[op, match[key]] for key, op in (
                    ("versionStartIncluding", ">="), ("versionStartExcluding", ">"),
                    ("versionEndIncluding", "<="), ("versionEndExcluding", "<")) if isinstance(match.get(key), str)]
                found.setdefault(("runtime", None, runtime), []).append(comparators)
    return found


RANGES = {"osv": osv_ranges, "ghsa": ghsa_ranges, "nvd": nvd_ranges}


def aliases(feed, raw):
    """The ids a feed's record goes by: OSV's id and aliases; GitHub's ghsa_id, cve_id and
    identifiers; NVD's id."""
    if feed == "osv":
        ids = [raw.get("id"), *listed(raw.get("aliases"))]
    elif feed == "ghsa":
        ids = [raw.get("ghsa_id"), raw.get("cve_id"), *(item.get("value") for item in dicts(raw.get("identifiers")))]
    else:
        ids = [raw.get("id")]
    return sorted({ident for ident in ids if isinstance(ident, str) and ALIAS.fullmatch(ident)})


def canonical(names):
    """The key of an alias set: its CVE id, else its GHSA id, else its first id."""
    return min(names, key=lambda name: (not name.startswith("CVE-"), not name.startswith("GHSA-"), name))


def runtime_cves(records):
    """The CVE ids of the OSV and NVD records of a runtime, which GitHub is asked for by cve_id
    (it has no runtime ecosystem, so it only adds aliases)."""
    return sorted({name for feed, raw in records if feed != "ghsa"
                   and any(key[0] == "runtime" for key in RANGES[feed](raw))
                   for name in aliases(feed, raw) if name.startswith("CVE-")})


def queries(collected):
    """What a check asks each feed for the pins whose version can be read (no other pin is ever
    sent): OSV querybatch queries, GitHub advisory params by ecosystem (100 packages a request) and
    NVD cpeNames."""
    osv, ghsa, nvd = {}, {}, {}
    for pin in collected["runtimes"]:
        spec = RUNTIMES.get(pin["name"])
        if spec and readable(pin["version"], "semver"):
            osv[(*spec["osv"], pin["version"])] = None
            nvd[f"{spec['cpe']}:{pin['version']}" + ":*" * 7] = None
    for pin in collected["packages"]:
        spec = ECOSYSTEMS.get(pin["ecosystem"])
        if spec and readable(pin["version"], spec["scheme"]):
            version = pin["version"].removeprefix("v") if pin["ecosystem"] == "composer" else pin["version"]
            osv[(spec["osv"], pin["name"], version)] = None
            ghsa.setdefault(spec["ghsa"], {})[f"{pin['name']}@{version}"] = None
    return {
        "osv": [{"package": {"ecosystem": ecosystem, "name": name}, "version": version}
                for ecosystem, name, version in osv],
        "ghsa": [{"ecosystem": ecosystem, "affects": ",".join(list(names)[start:start + 100])}
                 for ecosystem, names in ghsa.items() for start in range(0, len(names), 100)],
        "nvd": list(nvd),
    }


def index(collected):
    """{pin identity: pins} of the collected pins whose version can be read. An unreadable one takes
    no part in a match, or every advisory of its product would match it; its pin reads unknown."""
    pins = {}
    for kind, items in (("runtime", collected.get("runtimes", [])), ("package", collected.get("packages", []))):
        for pin in items:
            key = (kind, pin.get("ecosystem"), pin["name"])
            if (kind == "runtime" or pin["ecosystem"] in ECOSYSTEMS) and readable(pin["version"], scheme_of(key)):
                pins.setdefault(key, []).append(pin)
    return pins


def pin_entries(key, ranges, pins):
    """One entry for each version the pins of `key` hold, with where it came from and its state."""
    versions = {}
    for pin in pins:
        versions.setdefault(pin["version"], {})[pin["source"]] = None
    return [{"kind": key[0], "ecosystem": key[1], "name": key[2], "version": version, "sources": list(sources),
             "ranges": ranges, "state": pin_state(version, ranges, scheme_of(key))}
            for version, sources in versions.items()]


def references(feed, raw):
    if feed == "ghsa":
        urls = [raw.get("html_url"), *listed(raw.get("references"))]
    else:
        urls = [item.get("url") for item in dicts(raw.get("references"))]
    return [url for url in urls if isinstance(url, str) and len(url) <= 500 and cves.safe_reference(url)]


def summary(feed, raw):
    if feed == "nvd":
        return text(next((d.get("value") for d in dicts(raw.get("descriptions")) if d.get("lang") == "en"), None))
    return text(raw.get("summary")) or (text(raw.get("details")) if feed == "osv" else None)


def severity(members):
    """GitHub's severity, else NVD's highest CVSS base score."""
    for feed, raw in members:
        if feed == "ghsa" and raw.get("severity") in SEVERITIES:
            return raw["severity"]
    scores = [metric["cvssData"]["baseScore"] for feed, raw in members if feed == "nvd"
              and isinstance(raw.get("metrics"), dict) for entries in raw["metrics"].values()
              for metric in dicts(entries) if isinstance(metric.get("cvssData"), dict)
              and isinstance(metric["cvssData"].get("baseScore"), (int, float))
              and 0 <= metric["cvssData"]["baseScore"] <= 10]
    return f"CVSS {max(scores)}" if scores else None


def record(feed, raw):
    ident, modified = (raw.get(field) for field in {
        "osv": ("id", "modified"), "ghsa": ("ghsa_id", "updated_at"), "nvd": ("id", "lastModified")}[feed])
    return {"feed": feed, "id": ident if isinstance(ident, str) and ALIAS.fullmatch(ident) else None,
            "modified": text(modified, 64)}


def match(collected, records, known=()):
    """The vulnerabilities that `records` ([(feed, record)]) give the `collected` pins. Records whose
    alias sets overlap are one vulnerability, and so is each alias set in `known` (the stored
    matches) with every record it overlaps. Each is {vulnerability, aliases, state, pins, summary,
    severity, references, feeds, records}; one that concerns no collected pin is left out."""
    groups = [(set(names), []) for names in known]
    for feed, raw in records:
        names = set(aliases(feed, raw))
        if not names:
            continue
        joined = [group for group in groups if group[0] & names]
        groups = [group for group in groups if not group[0] & names]
        groups.append((names.union(*(other for other, _ in joined)),
                       [member for _, members in joined for member in members] + [(feed, raw)]))
    pins, found = index(collected), []
    for names, members in groups:
        ranges = {}
        for feed, raw in members:
            for key, value in RANGES[feed](raw).items():
                if key in pins:
                    known_ranges = ranges.setdefault(key, {}).setdefault(feed, [])
                    known_ranges += [item for item in value if item not in known_ranges]
        entries = [entry for key in sorted(ranges, key=str) for entry in pin_entries(key, ranges[key], pins[key])]
        if not entries:
            continue
        members.sort(key=lambda member: (FEEDS.index(member[0]), str(record(*member)["id"])))
        found.append({
            "vulnerability": canonical(names), "aliases": sorted(names),
            "state": worst({entry["state"] for entry in entries}), "pins": entries,
            "summary": next((line for member in members if (line := summary(*member))), None),
            "severity": severity(members),
            "references": list(dict.fromkeys(url for member in members for url in references(*member)))[:20],
            "feeds": sorted({feed for feed, _ in members}),
            "records": [record(*member) for member in members],
        })
    return found


def refresh(old, group, collected):
    """(data, state) of a stored match after a check. `group` is what the check's feeds gave, or
    None when no feed returned the vulnerability, as after a bump to a fixed version. Per pin, each
    feed's latest ranges win and a feed that did not return it keeps its stored ranges, so a feed
    that fails or falls silent never makes a pin read as not exposed; every pin is read again from
    `collected`."""
    ranges = {}
    for entry in old.get("pins", []) + (group or {}).get("pins", []):
        ranges.setdefault((entry["kind"], entry["ecosystem"], entry["name"]), {}).update(entry["ranges"])
    pins, entries = index(collected), []
    for key, feed_ranges in ranges.items():
        if key in pins:
            entries += pin_entries(key, feed_ranges, pins[key])
        else:
            # ponytail: a pin no longer collected, or whose version can no longer be read, keeps its
            # last entries, so a removed pin never remediates; drop them if removal should count
            entries += [entry for entry in old.get("pins", []) if (entry["kind"], entry["ecosystem"], entry["name"]) == key]
    fields = {name: value for name, value in (group or {}).items() if name not in ("vulnerability", "aliases", "state")}
    return {**old, **fields, "pins": entries}, worst({entry["state"] for entry in entries})


def lowest_fixed(version, ranges, scheme):
    """The lowest version above `version` that every feed's ranges ({feed: ranges}) leave out,
    taken from their '<' bounds (where GitHub's first_patched_version lands), or None. Only a
    plain version is a candidate, since a bump writes it into the repository."""
    candidates = [bound for feed_ranges in ranges.values() for comparators in feed_ranges
                  for op, bound in comparators if op == "<" and FIXED.fullmatch(bound)]
    fixed = [bound for bound in candidates if compare(bound, version, scheme) == 1
             and all(affected(bound, feed_ranges, scheme) is False for feed_ranges in ranges.values())]
    return min(fixed, key=cmp_to_key(lambda a, b: compare(a, b, scheme)), default=None)


def target(data, collected):
    """(dependency, reason) of the bump Remediation PR of an Advisory check match (A06), from the
    match's exposed or unknown pins in `data` and the `collected` pins they came from. A runtime
    gives {ecosystem: runtime, name, version, edits: [{source, field, from, to}]}: each Dockerfile
    FROM tag, .nvmrc, engines and platform pin of it moved to the lowest fixed version. Direct
    packages give {ecosystem, names, version, versions: {name: version}}. It is (None,
    no_fixed_version) when no fixed version can be written, (None, not_direct) for packages that
    only a lockfile names, and (None, None) when nothing is exposed.
    ponytail: a match with runtime and package pins bumps only the runtime, and moves every pin of
    it past the highest exposed version; split them if a vulnerability spans both."""
    exposed = [entry for entry in data.get("pins", []) if entry["state"] != "not_exposed"]
    runtimes = [entry for entry in exposed if entry["kind"] == "runtime"]
    if runtimes:
        name = runtimes[0]["name"]
        entries = [entry for entry in runtimes if entry["name"] == name]
        highest = max(entries, key=cmp_to_key(lambda a, b: compare(a["version"], b["version"], "semver")))
        fixed = lowest_fixed(highest["version"], highest["ranges"], "semver")
        versions, edits = {entry["version"] for entry in entries}, {}
        for pin in collected.get("runtimes", []):
            if not fixed or pin["name"] != name or pin["version"] not in versions:
                continue
            old, new = pin["version"], fixed
            if pin["field"] == "dockerfile":
                tag = pin["tag"].replace(pin["version"], fixed, 1)
                if not IMAGE_TAG.fullmatch(tag):
                    return None, "no_fixed_version"
                old, new = f"{pin['image']}:{pin['tag']}", f"{pin['image']}:{tag}"
            edits[(pin["source"], pin["field"], old)] = new
        if not edits:
            return None, "no_fixed_version"
        return {"ecosystem": "runtime", "name": name, "version": fixed, "edits": [
            {"source": source, "field": field, "from": old, "to": new}
            for (source, field, old), new in edits.items()]}, None
    if not exposed:
        return None, None
    direct = {(pin["ecosystem"], pin["name"], pin["version"]) for pin in collected.get("packages", []) if pin["direct"]}
    packages = [entry for entry in exposed if (entry["ecosystem"], entry["name"], entry["version"]) in direct]
    if not packages:
        return None, "not_direct"
    ecosystem = packages[0]["ecosystem"]
    versions = {entry["name"]: fixed for entry in packages if entry["ecosystem"] == ecosystem and (
        fixed := lowest_fixed(entry["version"], entry["ranges"], ECOSYSTEMS[ecosystem]["scheme"]))}
    if not versions:
        return None, "no_fixed_version"
    names = sorted(versions)
    return {"ecosystem": ecosystem, "names": names, "version": versions[names[0]], "versions": versions}, None


def report(advisory):
    """The plain-text report of an Advisory check match (A06), from its stored feed data: the
    vulnerability and its aliases, the severity and feeds, the summary (at most 500 characters, as
    stored), each pin with its state, sources and each feed's affected ranges, and the references.
    It is shown only as escaped text and never reaches an Alert."""
    others = [name for name in advisory["aliases"] if name != advisory["vulnerability"]]
    lines = [advisory["vulnerability"] + (f" (also {', '.join(others)})" if others else "")]
    if advisory.get("severity"):
        lines.append(f"Severity: {advisory['severity']}")
    lines.append(f"Feeds: {', '.join(advisory.get('feeds', []))}")
    if advisory.get("summary"):
        lines += ["", advisory["summary"]]
    lines += ["", "Pins:"]
    for pin in advisory.get("pins", []):
        lines.append(f"- {pin['name']} {pin['version']} ({pin['ecosystem'] or 'runtime'}, {pin['state']}), "
                     f"from {', '.join(pin['sources'])}")
        lines += [f"  {feed}: " + " || ".join(" ".join(op + bound for op, bound in comparators) or "all versions"
                                             for comparators in pin["ranges"][feed])
                  for feed in FEEDS if feed in pin["ranges"]]
    if advisory.get("references"):
        lines += ["", "References:", *(f"- {url}" for url in advisory["references"])]
    return "\n".join(lines)
