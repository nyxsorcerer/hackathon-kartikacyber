"""The Advisory check (A09): collecting each Application's runtime pins (Dockerfile FROM, .nvmrc,
package.json engines, composer.json platform) and package versions from the head of its Own
repository, else its source repository, daily, after a pin-file change on the Own default branch
and on the Operator's request, and matching them against OSV, GHSA and NVD. A version that cannot
be read is unknown, never not exposed."""

import hashlib
import json
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select, update

from conftest import FakeGitHub, FixtureBroker, application, github_account, repository_of
from numen import advisories, domain, remediation
from numen.cves import cpe_identity
from numen.models import AdvisoryCache, AdvisoryMatch, ApplicationRepository, Commit, Job, Notification, now
from numen.security import DomainError
from numen.sources import Sources
from numen.worker import run_once
from test_analysis import analyze
from test_artifacts import APPROVAL, without_package
from test_commit_review import assessment, pinned_bundle
from test_dependencies import BODY, REACT, check, npm_files, own_application, serve
from test_exposure import PACKAGE, REACT as NUMEN_REACT
from test_findings import react_fix, transition
from test_remediation_prs import SHOP, approve, drain, poll, tree, write_token

HEAD = "c" * 40
NODE = {"name": "node", "version": "20.11.1", "reason": None}
HOSTS = {"osv.fixture", "nvd.fixture", "github.fixture", "npm.fixture"}
CVE = "CVE-2026-111497"
GHSA = "GHSA-9c4w-m7v2-x5qh"
# The fixture vulnerability in Node 20.0.0 to 20.19.4 and 22.0.0 to 22.11.x, in each feed's form.
OSV_NODE = {
    "id": "BIT-node-2026-111497", "modified": "2026-11-01T00:00:00Z", "aliases": [CVE, GHSA],
    "summary": "Node.js HTTP request smuggling (fixture)",
    "affected": [{"package": {"ecosystem": "Bitnami", "name": "node"}, "ranges": [{"type": "SEMVER", "events": [
        {"introduced": "20.0.0"}, {"fixed": "20.19.5"}, {"introduced": "22.0.0"}, {"fixed": "22.12.0"}]}]}],
    "references": [{"type": "ADVISORY", "url": "https://nodejs.org/en/blog/vulnerability/fixture"}],
}
GHSA_NODE = {
    "ghsa_id": GHSA, "cve_id": CVE, "summary": "Node.js request smuggling in the HTTP parser (fixture)",
    "severity": "high", "identifiers": [{"type": "GHSA", "value": GHSA}, {"type": "CVE", "value": CVE}],
    "references": [f"https://github.com/advisories/{GHSA}"], "updated_at": "2026-11-01T00:00:00Z",
    "vulnerabilities": [],
}
NVD_NODE = {
    "id": CVE, "lastModified": "2026-11-01T00:00:00.000",
    "descriptions": [{"lang": "en", "value": "Node.js 20 before 20.19.5 allows request smuggling (fixture)."}],
    "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "cvssData": {"version": "3.1", "baseScore": 7.5}}]},
    "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [{
        "vulnerable": True, "criteria": "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*",
        "versionStartIncluding": "20.0.0", "versionEndExcluding": "20.19.5"}]}]}],
    "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-111497"}],
}
OSV_RANGES = [[[">=", "20.0.0"], ["<", "20.19.5"]], [[">=", "22.0.0"], ["<", "22.12.0"]]]
NVD_RANGES = [[[">=", "20.0.0"], ["<", "20.19.5"]]]
# The React2Shell package advisory, in GitHub's form, for the react-server-dom-webpack the
# Phase 7 fixtures lock at 19.0.0.
R2S_CVE, R2S_GHSA = "CVE-2025-55182", "GHSA-fv66-9v8q-g76r"
GHSA_REACT = {
    "ghsa_id": R2S_GHSA, "cve_id": R2S_CVE, "summary": "React Server Components remote code execution (fixture)",
    "severity": "critical", "identifiers": [{"type": "GHSA", "value": R2S_GHSA}, {"type": "CVE", "value": R2S_CVE}],
    "references": [f"https://github.com/advisories/{R2S_GHSA}"], "updated_at": "2026-11-01T00:00:00Z",
    "vulnerabilities": [{"package": {"ecosystem": "npm", "name": PACKAGE},
                         "vulnerable_version_range": ">= 19.0.0, < 19.0.1", "first_patched_version": "19.0.1"}],
}
# A GitHub advisory for react whose range cannot be read.
GHSA_UNREADABLE = {"ghsa_id": "GHSA-r2sh-fixt-ure1", "cve_id": None, "summary": "React (fixture)",
                   "severity": "critical", "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "react"},
                                                                "vulnerable_version_range": "~> 19.0"}]}


def ghsa_package(ident, name, patched):
    """A GitHub advisory for npm `name` before `patched`."""
    return {"ghsa_id": ident, "cve_id": None, "summary": f"{name} (fixture)", "severity": "low",
            "vulnerabilities": [{"package": {"ecosystem": "npm", "name": name},
                                 "vulnerable_version_range": f"< {patched}", "first_patched_version": patched}]}


class Feeds:
    """OSV at osv.fixture, NVD at nvd.fixture and GitHub's advisory database at
    github.fixture/advisories, holding the CVE-2026-111497 fixture, and the npm registry metadata
    in `npm` ({path: body}) at npm.fixture; every other request goes to `fallback`. Like a loose feed, OSV and NVD answer a record for its package whatever the version,
    so Exposure is the check's own range comparison. GitHub answers with an ETag and a 304 for it.
    It logs each request and its status."""

    def __init__(self, fallback=None):
        self.osv, self.nvd, self.ghsa, self.npm = {OSV_NODE["id"]: OSV_NODE}, [NVD_NODE], [GHSA_NODE], {}
        self.fallback, self.requests = fallback, []

    def __call__(self, request):
        response = self.answer(request)
        self.requests.append((request, response.status_code))
        return response

    def answer(self, request):
        url = request.url
        if url.host == "osv.fixture" and url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{"vulns": [
                {"id": ident, "modified": record["modified"]} for ident, record in self.osv.items()
                if query["package"] in [entry["package"] for entry in record["affected"]]]}
                for query in json.loads(request.content)["queries"]]})
        if url.host == "osv.fixture" and url.path.startswith("/v1/vulns/"):
            record = self.osv.get(url.path.removeprefix("/v1/vulns/"))
            return httpx.Response(200, json=record) if record else httpx.Response(404, json={"message": "Not Found"})
        if url.host == "nvd.fixture":
            product = cpe_identity(url.params["cpeName"])
            found = [raw for raw in self.nvd if any(
                cpe_identity(match["criteria"]) == product for config in raw["configurations"]
                for node in config["nodes"] for match in node["cpeMatch"])]
            return httpx.Response(200, json={"totalResults": len(found), "vulnerabilities": [
                {"cve": raw} for raw in found] if url.params.get("startIndex", "0") == "0" else []})
        if url.host == "github.fixture" and url.path == "/advisories":
            assert request.headers["Authorization"] == "Bearer fixture-github-token"
            if "cve_id" in url.params:
                found = [item for item in self.ghsa if item["cve_id"] == url.params["cve_id"]]
            else:
                names = {name.rsplit("@", 1)[0] for name in url.params["affects"].split(",")}
                found = [item for item in self.ghsa if any(
                    v["package"]["ecosystem"] == url.params["ecosystem"] and v["package"]["name"] in names
                    for v in item["vulnerabilities"])]
            etag = f'"{hashlib.sha1(json.dumps(found).encode()).hexdigest()}"'
            if request.headers.get("if-none-match") == etag:
                return httpx.Response(304, headers={"etag": etag})
            return httpx.Response(200, headers={"etag": etag}, json=found)
        if url.host == "npm.fixture" and url.path in self.npm:
            return httpx.Response(200, json=self.npm[url.path])
        return self.fallback(request) if self.fallback else httpx.Response(404, json={"message": "Not Found"})

    def hosts(self):
        return {request.url.host for request, _ in self.requests}

    def sent(self, host, path=None):
        """The requests to `host` (and `path`) with their status."""
        return [(request, status) for request, status in self.requests
                if request.url.host == host and path in (None, request.url.path)]


def feeds(monkeypatch, fallback=None):
    """Points OSV, NVD, GitHub and npm at one Feeds stub behind every Sources client."""
    monkeypatch.setenv("NUMEN_OSV_URL", "http://osv.fixture")
    monkeypatch.setenv("NUMEN_NPM_REGISTRY_URL", "http://npm.fixture")
    monkeypatch.setenv("NUMEN_NVD_API_URL", "http://nvd.fixture")
    monkeypatch.setenv("NUMEN_GITHUB_API_URL", "http://github.fixture")
    stub = Feeds(fallback)
    original = Sources.__init__

    def setup(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self.client = httpx.Client(transport=httpx.MockTransport(stub))

    monkeypatch.setattr(Sources, "__init__", setup)
    return stub


def matches(app, ident):
    with app.state.factory() as db:
        return db.scalars(select(AdvisoryMatch).where(AdvisoryMatch.application_id == ident)).all()


def age_cache(app, days=1):
    with app.state.factory.begin() as db:
        db.execute(update(AdvisoryCache).values(fetched_at=now() - timedelta(days=days)))


def alerts(app):
    with app.state.factory() as db:
        return [row.data for row in db.scalars(select(Notification))]


def findings(client):
    return client.get("/api/findings").json()["items"]


def advisory_jobs(app):
    with app.state.factory() as db:
        return db.scalars(select(Job).where(Job.kind == "advisory_check").order_by(Job.created_at)).all()


def run_check(app, client, config, ident, broker=None):
    """The Operator's Advisory check, run to its end with every job it queues: the job."""
    response = client.post(f"/api/applications/{ident}/advisory-checks")
    assert response.status_code == 202, response.text
    while run_once(config, app.state.factory, broker or FixtureBroker()):
        pass
    return client.get(response.json()["status_url"]).json()


def seeded(app, client, files, **repository):
    """An Application whose source repository's head holds `files`: one with no Own repository,
    or, with role="own" and source_url=SHOP, the Own repository acme/shop."""
    p = application(client, **repository)
    with app.state.factory() as db:
        repository_id = repository_of(db, p["id"]).id
    tree(app, repository_id, HEAD, {path: text.encode() for path, text in files.items()}, head=True)
    return p["id"], repository_id


@pytest.mark.parametrize("files,expected", [
    ({"Dockerfile": "FROM node:20.11.1-alpine\n"},
     [{**NODE, "field": "dockerfile", "source": "Dockerfile", "image": "node", "tag": "20.11.1-alpine"}]),
    ({"deploy/Dockerfile.prod": "# syntax=docker/dockerfile:1\nFROM docker.io/library/node:20.11.1@sha256:"
      + "a" * 64 + "\n"},
     [{**NODE, "field": "dockerfile", "source": "deploy/Dockerfile.prod", "image": "docker.io/library/node",
       "tag": "20.11.1"}]),
    # --platform is skipped, `build` is an earlier stage's name, and nginx and bitnami/node are not
    # a runtime's official image.
    ({"web.Dockerfile": "FROM --platform=$BUILDPLATFORM node:20.11.1 AS build\nRUN npm ci\n"
      "FROM build AS test\nFROM bitnami/node:20.11.1\nfrom nginx:1.27.0\n"},
     [{**NODE, "field": "dockerfile", "source": "web.Dockerfile", "image": "node", "tag": "20.11.1"}]),
    ({"Dockerfile": "FROM php:8.3.1-fpm\n"},
     [{"name": "php", "version": "8.3.1", "reason": None, "field": "dockerfile", "source": "Dockerfile",
       "image": "php", "tag": "8.3.1-fpm"}]),
    ({".nvmrc": "v20.11.1\n"}, [{**NODE, "field": "nvmrc", "source": ".nvmrc"}]),
    ({"package.json": json.dumps({"engines": {"node": "20.11.1"}})},
     [{**NODE, "field": "engines", "source": "package.json"}]),
    ({"composer.json": json.dumps({"config": {"platform": {"php": "8.3.1"}}})},
     [{"name": "php", "version": "8.3.1", "reason": None, "field": "platform", "source": "composer.json"}]),
])
def test_runtime_pins_are_read_from_dockerfile_nvmrc_engines_and_composer_platform(files, expected):
    assert advisories.collect(files, None, {})["runtimes"] == expected


@pytest.mark.parametrize("files,reason", [
    ({"Dockerfile": "FROM node:lts\n"}, "a moving tag"),
    ({"Dockerfile": "FROM node:20\n"}, "a moving tag"),
    ({"Dockerfile": "ARG NODE_VERSION=20.11.1\nFROM node:${NODE_VERSION}\n"}, "a variable"),
    ({"Dockerfile": "FROM node\n"}, "no tag"),
    ({".nvmrc": "lts/*\n"}, "a moving tag"),
    ({"package.json": json.dumps({"engines": {"node": ">=20"}})}, "a range"),
])
def test_an_unreadable_runtime_version_is_unknown_not_not_exposed(system, monkeypatch, files, reason):
    app, client, config = system
    stub = feeds(monkeypatch)
    ident, _ = seeded(app, client, files)
    assert run_check(app, client, config, ident)["status"] == "succeeded"
    (pin,) = client.get(f"/api/applications/{ident}/advisories").json()["runtimes"]
    assert (pin["name"], pin["version"], pin["reason"], pin["exposure"]) == ("node", None, reason, "unknown")
    assert stub.requests == []  # an unreadable version is never sent to a feed


def test_package_versions_come_from_lockfiles_and_locked_versions():
    files = {
        **{f"app/{name}": text for name, text in npm_files(
            {"react": "^19.0.0", "left-pad": "^1.3.0"}, {"react": "19.0.0", "scheduler": "0.25.0"}).items()},
        "app/composer.json": json.dumps({"require": {"php": ">=8.1", "symfony/console": "^6.4"}}),
        "app/composer.lock": json.dumps({"packages": [{"name": "symfony/console", "version": "v6.4.1"}]}),
        "package-lock.json": "not read: outside the source path",
    }
    pins = advisories.collect(files, "app", {("npm", "react"): ("19.0.1", "operator")})
    assert pins == {"runtimes": [], "packages": [
        {"ecosystem": "composer", "name": "symfony/console", "version": "v6.4.1", "source": "app/composer.lock",
         "direct": True, "reason": None},
        {"ecosystem": "npm", "name": "left-pad", "version": None, "source": "app/package.json", "direct": True,
         "reason": "no lockfile entry"},
        {"ecosystem": "npm", "name": "react", "version": "19.0.1", "source": "Locked version (operator)",
         "direct": True, "reason": None},
        {"ecosystem": "npm", "name": "scheduler", "version": "0.25.0", "source": "app/package-lock.json",
         "direct": False, "reason": None},
    ]}
    with pytest.raises(DomainError) as refused:
        advisories.collect({"package.json": "{"}, None, {})
    assert refused.value.code == "invalid_manifest"


def test_a_pin_file_change_on_the_own_default_branch_queues_an_advisory_check(system, monkeypatch):
    app, client, config = system
    github_account(app)
    fixtures = serve(monkeypatch)
    feeds(monkeypatch, fixtures)
    monkeypatch.setattr(Sources, "snapshot_github", lambda self, repository, revision: {
        path: text.encode() for path, text in dict(
            fixtures.history(repository.source_url.removeprefix("https://github.com/")))[revision].items()})
    fixtures.push("acme/shop", {"README.md": "Shop"})
    ident = own_application(client, "acme/shop")
    check(app, client, config, ident)  # the Baseline
    fixtures.push("acme/shop", {"README.md": "Shop, again"})
    check(app, client, config, ident)
    assert advisory_jobs(app) == []

    docker = fixtures.push("acme/shop", {"Dockerfile": "FROM node:20.11.1-alpine\n"})
    check(app, client, config, ident)
    lock = fixtures.push("acme/shop", npm_files({"react": "^19.0.0"}, {"react": "19.0.0"}))
    check(app, client, config, ident)
    assert [(job.idempotency_key, job.status) for job in advisory_jobs(app)] == [
        (f"advisory:{ident}:{docker}", "succeeded"), (f"advisory:{ident}:{lock}", "succeeded")]
    pins = client.get(f"/api/applications/{ident}/advisories").json()
    own = next(r for r in client.get(f"/api/applications/{ident}").json()["repositories"] if r["role"] == "own")
    assert (pins["repository_id"], pins["revision"]) == (own["repository_id"], lock)
    assert [(p["name"], p["version"], p["source"], p["exposure"]) for p in pins["runtimes"]] == [
        ("node", "20.11.1", "Dockerfile", "exposed")]
    assert [(p["name"], p["version"], p["source"]) for p in pins["packages"]] == [
        ("react", "19.0.0", "package-lock.json")]

    # With no Own repository, a pin-file change on the source repository queues it.
    fixtures.push("acme/blog", {"README.md": "Blog"})
    blog = application(client, asset_name="Blog", source_url="https://github.com/acme/blog")["id"]
    check(app, client, config, blog)  # the Baseline
    nvmrc = fixtures.push("acme/blog", {".nvmrc": "v20.11.1\n"})
    check(app, client, config, blog)
    assert [(job.idempotency_key, job.status) for job in advisory_jobs(app)][2:] == [
        (f"advisory:{blog}:{nvmrc}", "succeeded")]
    assert [(p["version"], p["source"]) for p in client.get(f"/api/applications/{blog}/advisories").json()[
        "runtimes"]] == [("20.11.1", ".nvmrc")]


def test_the_advisory_check_runs_once_per_utc_day(system, monkeypatch):
    app, client, config = system
    checked = application(client)
    paused = application(client, source_url="https://github.com/demo/paused", monitor_enabled=False)
    application(client, source_url="https://github.com/demo/unchecked")  # no head to read yet
    for p in (checked, paused):
        with app.state.factory.begin() as db:
            repository_of(db, p["id"]).cursor = HEAD
    today = now()
    for _ in range(2):
        with app.state.factory.begin() as db:
            domain.schedule_advisory_checks(db)
    tomorrow = today + timedelta(days=1)
    monkeypatch.setattr(domain, "now", lambda: tomorrow)
    with app.state.factory.begin() as db:
        domain.schedule_advisory_checks(db)
    assert [job.idempotency_key for job in advisory_jobs(app)] == [
        f"advisory:{checked['id']}:{today:%Y-%m-%d}", f"advisory:{checked['id']}:{tomorrow:%Y-%m-%d}"]


def test_run_advisory_check_endpoint(system, monkeypatch):
    app, client, config = system
    feeds(monkeypatch)
    bare = client.post("/api/applications", json=BODY).json()
    refused = client.post(f"/api/applications/{bare['id']}/advisory-checks")
    assert refused.status_code == 422 and refused.json()["code"] == "repository_required"
    p = application(client)
    refused = client.post(f"/api/applications/{p['id']}/advisory-checks")
    assert refused.status_code == 422 and refused.json()["code"] == "source_not_checked"
    assert client.get(f"/api/applications/{p['id']}/advisories").json()["runtimes"] == []

    # With no Own repository, the check reads the source repository's head. An Operator's Locked
    # version on a derived Upstream link replaces the lockfile's version.
    ident, repository_id = seeded(app, client, {
        "Dockerfile": "FROM node:20.11.1\n", **npm_files({"react": "^19.0.0"}, {"react": "19.0.0"})})
    linked = client.post(f"/api/applications/{ident}/repositories",
                         json={"source_kind": "github", "source_url": REACT, "locked_version": "19.0.1"})
    assert linked.status_code == 201, linked.text
    with app.state.factory.begin() as db:
        db.scalar(select(ApplicationRepository).where(
            ApplicationRepository.repository_id == linked.json()["repository_id"])).packages = ["npm:react"]
    job = run_check(app, client, config, ident)
    assert (job["status"], job["result"]) == ("succeeded", {
        "source_ref": HEAD, "runtimes": 1, "packages": 1, "unknown": 0, "matches": 1, "opened": 1, "attached": 0,
        "finding_ids": [finding["id"] for finding in findings(client)]})
    pins = client.get(f"/api/applications/{ident}/advisories").json()
    assert (pins["repository_id"], pins["revision"]) == (repository_id, HEAD)
    assert [(p["name"], p["version"], p["source"]) for p in pins["runtimes"] + pins["packages"]] == [
        ("node", "20.11.1", "Dockerfile"), ("react", "19.0.1", "Locked version (operator)")]

    # A check queued before an Own repository was linked no longer reads the right repository.
    queued = client.post(f"/api/applications/{ident}/advisory-checks").json()
    own = client.post(f"/api/applications/{ident}/repositories",
                      json={"role": "own", "source_kind": "github", "source_url": "https://github.com/acme/shop"})
    assert own.status_code == 201, own.text
    while run_once(config, app.state.factory, FixtureBroker()):
        pass
    failed = client.get(queued["status_url"]).json()
    assert (failed["status"], failed["error"]["code"]) == ("failed", "input_changed")


def test_ranges_use_each_ecosystems_version_semantics():
    react, node = ("package", "npm", "react"), ("runtime", None, "node")
    # GHSA: the range split on commas; first_patched_version bounds a range with no upper bound.
    ghsa = advisories.ghsa_ranges({"vulnerabilities": [{"package": {"ecosystem": "npm", "name": "react"},
                                                        "vulnerable_version_range": ">= 19.0.0, < 19.0.1"}]})
    assert ghsa == {react: [[[">=", "19.0.0"], ["<", "19.0.1"]]]}
    assert advisories.ghsa_ranges({"vulnerabilities": [{"package": {"ecosystem": "npm", "name": "react"},
                                                        "vulnerable_version_range": ">= 19.0.0",
                                                        "first_patched_version": "19.0.1"}]}) == ghsa
    assert [advisories.affected(v, ghsa[react], "semver") for v in ("18.3.1", "19.0.0", "19.0.1")] == [
        False, True, False]
    # A '<=' bound below first_patched_version keeps it, as the version a bump moves to; one at or
    # above it would be narrowed, so the patched version is left out.
    inclusive = {"package": {"ecosystem": "npm", "name": "react"}, "vulnerable_version_range": "<= 19.0.0",
                 "first_patched_version": "19.0.1"}
    assert advisories.ghsa_ranges({"vulnerabilities": [inclusive]}) == {react: [[["<=", "19.0.0"], ["<", "19.0.1"]]]}
    assert advisories.lowest_fixed("19.0.0", {"ghsa": [[["<=", "19.0.0"], ["<", "19.0.1"]]]}, "semver") == "19.0.1"
    assert advisories.ghsa_ranges({"vulnerabilities": [{**inclusive, "first_patched_version": "18.0.0"}]}) == {
        react: [[["<=", "19.0.0"]]]}
    # OSV: introduced/fixed pairs; introduced 0 is no lower bound, last_affected is inclusive, and
    # listed versions count when there is no range.
    assert advisories.osv_ranges(OSV_NODE) == {node: OSV_RANGES}
    assert [advisories.affected(v, OSV_RANGES, "semver") for v in (
        "18.20.0", "20.11.1", "20.19.5", "22.11.0", "22.12.0")] == [False, True, False, True, False]
    assert advisories.osv_ranges({"affected": [
        {"package": {"ecosystem": "npm", "name": "left-pad"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "1.3.0"}]},
                    {"type": "GIT", "events": [{"introduced": "0"}]}]},
        {"package": {"ecosystem": "Packagist", "name": "acme/tool"}, "versions": ["1.2.9"]},
        {"package": {"ecosystem": "PyPI", "name": "left-pad"}, "versions": ["1.0.0"]}]}) == {
        ("package", "npm", "left-pad"): [[["<=", "1.3.0"]]], ("package", "composer", "acme/tool"): [[["=", "1.2.9"]]]}
    # NVD: the runtime's cpeMatch by its versionStart and versionEnd fields, or its exact version.
    assert advisories.nvd_ranges(NVD_NODE) == {node: NVD_RANGES}
    assert [advisories.affected(v, NVD_RANGES, "semver") for v in ("20.19.4", "20.19.5")] == [True, False]
    exact = {**NVD_NODE, "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:php:php:8.3.1:*:*:*:*:*:*:*"},
        {"vulnerable": False, "criteria": "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"}]}]}]}
    assert advisories.nvd_ranges(exact) == {("runtime", None, "php"): [[["=", "8.3.1"]]]}
    # composer is numeric, so v1.2.10 is after 1.2.9, where a string comparison puts it before.
    assert advisories.compare("v1.2.10", "1.2.9", "composer") == 1
    assert [advisories.affected(v, [[["<", "1.2.9"]]], "composer") for v in ("v1.2.10", "1.2.8")] == [False, True]
    # A version or bound that cannot be read gives None, unless another comparator rules it out.
    assert advisories.compare("1.2.10-beta", "1.2.9", "composer") is None
    assert advisories.affected("20.11.1", [[["<", "twenty"]]], "semver") is None
    assert advisories.affected("20.11.1", [[[">=", "21.0.0"], ["<", "twenty"]]], "semver") is False
    assert advisories.affected("20.11.1", [[["~>", "20.0"]]], "semver") is None


def test_osv_ghsa_and_nvd_aliases_key_one_match(system, monkeypatch):
    app, client, config = system
    github_account(app)
    stub = feeds(monkeypatch)
    ident, _ = seeded(app, client, {"Dockerfile": "FROM node:20.11.1-alpine\n"})
    job = run_check(app, client, config, ident)
    assert (job["status"], job["result"]["matches"]) == ("succeeded", 1)
    body = client.get(f"/api/applications/{ident}/advisories").json()
    assert body["feeds"] == {"osv": {"records": 1}, "nvd": {"records": 1}, "ghsa": {"records": 1}}
    (match,) = body["matches"]
    assert (match["vulnerability"], match["aliases"], match["state"], match["feeds"]) == (
        CVE, sorted(["BIT-node-2026-111497", CVE, GHSA]), "exposed", ["ghsa", "nvd", "osv"])
    # GHSA has no runtime ecosystem: it was asked for the CVE and adds its alias, summary and severity.
    assert (match["summary"], match["severity"]) == (GHSA_NODE["summary"], "high")
    assert match["pins"] == [{"kind": "runtime", "ecosystem": None, "name": "node", "version": "20.11.1",
                              "sources": ["Dockerfile"], "ranges": {"osv": OSV_RANGES, "nvd": NVD_RANGES},
                              "state": "exposed"}]
    assert [p["exposure"] for p in body["runtimes"]] == ["exposed"]
    assert len(matches(app, ident)) == 1
    (ghsa,) = stub.sent("github.fixture", "/advisories")
    assert dict(ghsa[0].url.params) == {"cve_id": CVE, "per_page": "100"}
    (nvd,) = stub.sent("nvd.fixture")
    assert nvd[0].url.params["cpeName"] == "cpe:2.3:a:nodejs:node.js:20.11.1:*:*:*:*:*:*:*"
    assert json.loads(stub.sent("osv.fixture", "/v1/querybatch")[0][0].content) == {"queries": [
        {"package": {"ecosystem": "Bitnami", "name": "node"}, "version": "20.11.1"}]}
    assert stub.hosts() <= HOSTS


def test_the_next_days_check_keeps_one_match_and_a_later_alias_merges_into_it(system, monkeypatch):
    app, client, config = system
    github_account(app)
    stub = feeds(monkeypatch)
    ident, repository_id = seeded(app, client, {"Dockerfile": "FROM node:20.11.1-alpine\n"})
    run_check(app, client, config, ident)
    (first,) = matches(app, ident)
    age_cache(app)
    assert run_check(app, client, config, ident)["status"] == "succeeded"
    assert [(row.id, row.vulnerability) for row in matches(app, ident)] == [(first.id, CVE)]

    # A record learned later that shares only the GHSA id with the stored match folds into its key.
    later = {**OSV_NODE, "id": "OSV-2026-111497", "aliases": [GHSA]}
    stub.osv, stub.nvd = {later["id"]: later}, []
    age_cache(app)
    assert run_check(app, client, config, ident)["status"] == "succeeded"
    (row,) = matches(app, ident)
    assert (row.id, row.vulnerability, row.state) == (first.id, CVE, "exposed")
    assert row.aliases == sorted(["BIT-node-2026-111497", CVE, GHSA, "OSV-2026-111497"])
    # NVD no longer lists it, so its stored ranges are kept: a feed's silence never clears a range.
    assert row.data["pins"][0]["ranges"] == {"osv": OSV_RANGES, "nvd": NVD_RANGES}

    # After a bump to a fixed version that no feed lists, the stored ranges read the new version.
    tree(app, repository_id, "d" * 40, {"Dockerfile": b"FROM node:20.19.5-alpine\n"}, head=True)
    stub.osv = {}
    run_check(app, client, config, ident)
    (row,) = matches(app, ident)
    assert (row.id, row.state, [(p["version"], p["state"]) for p in row.data["pins"]]) == (
        first.id, "not_exposed", [("20.19.5", "not_exposed")])
    assert stub.hosts() <= HOSTS


def test_a_version_outside_every_range_is_not_exposed_and_an_unreadable_range_is_unknown(system, monkeypatch):
    app, client, config = system
    github_account(app)
    stub = feeds(monkeypatch)
    stub.ghsa.append(GHSA_UNREADABLE)
    ident, _ = seeded(app, client, {
        "Dockerfile": "FROM node:22.12.0\n", ".nvmrc": "lts/*\n",
        **npm_files({"react": "^19.0.0", "left-pad": "^1.3.0"}, {"react": "19.0.0"})})
    assert run_check(app, client, config, ident)["result"]["matches"] == 1
    body = client.get(f"/api/applications/{ident}/advisories").json()
    assert [(m["vulnerability"], m["state"], [(p["name"], p["version"], p["state"]) for p in m["pins"]])
            for m in body["matches"]] == [
        # The unreadable .nvmrc is listed as unknown below, but takes no part in a match.
        (CVE, "not_exposed", [("node", "22.12.0", "not_exposed")]),
        ("GHSA-r2sh-fixt-ure1", "unknown", [("react", "19.0.0", "unknown")])]
    assert [(p["source"], p["version"], p["exposure"]) for p in body["runtimes"] + body["packages"]] == [
        ("Dockerfile", "22.12.0", "not_exposed"), (".nvmrc", None, "unknown"),
        ("package.json", None, "unknown"), ("package-lock.json", "19.0.0", "unknown")]
    # Pins whose version cannot be read are never sent to a feed.
    assert json.loads(stub.sent("osv.fixture", "/v1/querybatch")[0][0].content)["queries"] == [
        {"package": {"ecosystem": "Bitnami", "name": "node"}, "version": "22.12.0"},
        {"package": {"ecosystem": "npm", "name": "react"}, "version": "19.0.0"}]
    assert [r.url.params["cpeName"] for r, _ in stub.sent("nvd.fixture")] == [
        "cpe:2.3:a:nodejs:node.js:22.12.0:*:*:*:*:*:*:*"]
    assert [dict(r.url.params) for r, _ in stub.sent("github.fixture", "/advisories")] == [
        {"ecosystem": "npm", "affects": "react@19.0.0", "per_page": "100"}, {"cve_id": CVE, "per_page": "100"}]
    assert stub.hosts() <= HOSTS


def test_feed_responses_are_cached(system, monkeypatch):
    app, client, config = system
    github_account(app)
    stub = feeds(monkeypatch)
    ident, _ = seeded(app, client, {"Dockerfile": "FROM node:20.11.1-alpine\n"})
    run_check(app, client, config, ident)
    stub.requests.clear()
    run_check(app, client, config, ident)
    # OSV's querybatch is the freshness check: an unchanged `modified` needs no record fetch.
    assert [r.url.path for r, _ in stub.sent("osv.fixture")] == ["/v1/querybatch"]
    # GitHub revalidates by ETag and answers 304.
    (ghsa,) = stub.sent("github.fixture", "/advisories")
    assert ghsa[0].headers["if-none-match"] and ghsa[1] == 304
    # NVD is reused for 12 hours.
    assert stub.sent("nvd.fixture") == []
    assert len(matches(app, ident)) == 1 and matches(app, ident)[0].state == "exposed"

    stub.requests.clear()
    stub.osv[OSV_NODE["id"]] = {**OSV_NODE, "modified": "2026-11-02T00:00:00Z"}
    run_check(app, client, config, ident)
    assert [r.url.path for r, _ in stub.sent("osv.fixture")] == ["/v1/querybatch", "/v1/vulns/BIT-node-2026-111497"]
    assert stub.hosts() <= HOSTS


def test_a_feed_that_fails_is_recorded_and_the_others_still_match(system, monkeypatch):
    app, client, config = system
    stub = feeds(monkeypatch)  # no GitHub read token
    ident, _ = seeded(app, client, {"Dockerfile": "FROM node:20.11.1-alpine\n"})
    assert run_check(app, client, config, ident)["status"] == "succeeded"
    body = client.get(f"/api/applications/{ident}/advisories").json()
    assert body["feeds"]["ghsa"]["error"]["code"] == "github_token_required"
    assert (body["feeds"]["osv"], body["feeds"]["nvd"]) == ({"records": 1}, {"records": 1})
    (match,) = body["matches"]
    assert (match["vulnerability"], match["state"], match["feeds"]) == (CVE, "exposed", ["nvd", "osv"])
    assert GHSA in match["aliases"]  # from OSV's aliases
    assert stub.hosts() <= HOSTS


# Advisory Findings (A09, A11): an exposed or unknown match attaches to the Application's Open or
# Confirmed commit or cve Finding that goes by one of its aliases, or opens one with source
# advisory, whose Playbook is a report and a bump Remediation PR, never a Lab Proof (A06).
def test_a_dockerfile_pinning_an_exposed_node_version_opens_exactly_one_finding_across_three_feeds(
        system, monkeypatch):
    app, client, config = system
    github_account(app)
    stub = feeds(monkeypatch)
    ident, _ = seeded(app, client, {"Dockerfile": "FROM node:20.11.1-alpine\n"})
    job = run_check(app, client, config, ident)
    (finding,) = findings(client)
    # The exposed match opens and Confirms it (A11).
    assert (finding["source"], finding["source_ref"], finding["status"], finding["target_applicability"]) == (
        "advisory", CVE, "confirmed", "affected")
    assert finding["title"] == f"node 20.11.1: {GHSA_NODE['summary']}"
    assert {k: v for k, v in finding["cause"].items() if k != "at"} == {
        "by": "advisory", "advisory_id": CVE, "aliases": sorted(["BIT-node-2026-111497", CVE, GHSA])}
    assert (job["result"]["opened"], job["result"]["attached"], job["result"]["finding_ids"]) == (1, 0, [finding["id"]])
    assert alerts(app) == [{"application": "Site", "account": None, "source": CVE, "verdict": "Advisory",
                            "link": f"/findings/{finding['id']}"}]
    assert [row.finding_id for row in matches(app, ident)] == [finding["id"]]

    # The next day's check opens no duplicate and sends no second Alert.
    age_cache(app)
    again = run_check(app, client, config, ident)
    assert (again["result"]["matches"], again["result"]["opened"], again["result"]["finding_ids"]) == (1, 0, [])
    assert [f["id"] for f in findings(client)] == [finding["id"]] and len(alerts(app)) == 1
    # A Finding the Operator Remediated stays Remediated.
    assert transition(client, finding["id"], "remediated", "The Asset does not run this image").status_code == 200
    age_cache(app)
    run_check(app, client, config, ident)
    assert [(f["id"], f["status"]) for f in findings(client)] == [(finding["id"], "remediated")]
    assert len(alerts(app)) == 1 and [row.finding_id for row in matches(app, ident)] == [finding["id"]]
    assert stub.hosts() <= HOSTS


@pytest.mark.parametrize("order", ["commit_first", "advisory_first"])
def test_the_react2shell_package_advisory_and_the_exposed_fix_commit_share_one_finding(
        system, monkeypatch, local_sources, order):
    app, client, config = system
    github_account(app)
    stub = feeds(monkeypatch)
    stub.ghsa.append(GHSA_REACT)
    # Shop's Own head locks react-server-dom-webpack@19.0.0, which the fix commit addresses by its GHSA id.
    ident, commit, release = react_fix(system, local_sources, own=True)

    def fix():
        job, _ = analyze(system, commit, {**assessment("Vulnerability fix", release), "addresses": [R2S_GHSA]},
                         without_package(pinned_bundle(release)))
        assert job["status"] == "succeeded", job
        return job

    if order == "commit_first":
        fixed = fix()
        (opened,) = findings(client)
        assert (opened["source"], opened["status"]) == ("commit", "open")
        check = run_check(app, client, config, ident)
        assert (check["result"]["opened"], check["result"]["attached"]) == (0, 1)
    else:
        check = run_check(app, client, config, ident)
        assert (check["result"]["opened"], check["result"]["attached"]) == (1, 0)
        fixed = fix()
    (finding,) = findings(client)
    # In either order, the fix runs its Upstream Playbook on the one Finding.
    assert check["result"]["finding_ids"] == fixed["result"]["finding_ids"] == [finding["id"]]
    (match,) = matches(app, ident)
    assert (match.vulnerability, match.aliases, match.state, match.finding_id) == (
        R2S_CVE, [R2S_CVE, R2S_GHSA], "exposed", finding["id"])
    current = client.get(f"/api/findings/{finding['id']}").json()
    (advisory,) = current["advisories"]
    assert (advisory["vulnerability"], [(p["name"], p["version"]) for p in advisory["pins"]]) == (
        R2S_CVE, [(PACKAGE, "19.0.0")])
    if order == "commit_first":
        # An Advisory check match Confirms the commit Finding (A11).
        assert (current["source"], current["status"]) == ("commit", "confirmed")
        assert {k: v for k, v in current["cause"].items() if k != "at"} == {"by": "advisory", "advisory_id": R2S_CVE}
        (attached,) = [e for e in current["events"] if e["action"] == "advisory_attached"]
        assert (attached["vulnerability"], attached["aliases"]) == (R2S_CVE, [R2S_CVE, R2S_GHSA])
    else:
        assert (current["source"], current["source_ref"], current["status"]) == ("advisory", R2S_CVE, "confirmed")
        assert [e["commit_id"] for e in current["events"] if e["action"] == "linked"] == [commit]
    # Either way it has the exposed Upstream Vulnerability fix's cell: an n-day Proof after
    # Approval, never exported, and a bump (A06, A15, A16).
    assert [s["step"] for s in current["playbook"]] == ["proof", "remediation_pr"]
    assert current["exportable"] is False
    lab = client.post(f"/api/findings/{finding['id']}/lab-runs", json=APPROVAL)
    assert (lab.status_code, lab.json()["code"]) == (422, "incomplete_bundle"), lab.text
    assert len(alerts(app)) == 1  # The one Finding's opening Alert.
    assert stub.hosts() <= HOSTS


def test_an_advisory_finding_runs_only_its_cell(system, monkeypatch):
    app, client, config = system
    github_account(app)
    stub = feeds(monkeypatch)
    # A version outside every range opens nothing and sends no Alert.
    ident, repository_id = seeded(app, client, {"Dockerfile": "FROM node:22.12.0\n"})
    job = run_check(app, client, config, ident)
    assert (job["result"]["matches"], job["result"]["opened"]) == (0, 0)
    assert [(row.state, row.finding_id) for row in matches(app, ident)] == [("not_exposed", None)]
    assert findings(client) == [] and alerts(app) == []

    tree(app, repository_id, "d" * 40, {"Dockerfile": b"FROM node:20.11.1\n"}, head=True)
    assert run_check(app, client, config, ident)["result"]["opened"] == 1
    (finding,) = findings(client)
    assert len(alerts(app)) == 1
    current = client.get(f"/api/findings/{finding['id']}").json()
    assert current["playbook"] == [{"step": "report", "status": "ready"},
                                   {"step": "remediation_pr", "status": "no_own_repository"}]
    (advisory,) = current["advisories"]
    assert (advisory["aliases"], advisory["pins"]) == (
        sorted(["BIT-node-2026-111497", CVE, GHSA]),
        [{"kind": "runtime", "ecosystem": None, "name": "node", "version": "20.11.1", "sources": ["Dockerfile"],
          "ranges": {"osv": OSV_RANGES, "nvd": NVD_RANGES}, "state": "exposed"}])
    assert advisory["report"] == "\n".join([
        f"{CVE} (also BIT-node-2026-111497, {GHSA})",
        "Severity: high",
        "Feeds: ghsa, nvd, osv",
        "",
        GHSA_NODE["summary"],
        "",
        "Pins:",
        "- node 20.11.1 (runtime, exposed), from Dockerfile",
        "  osv: >=20.0.0 <20.19.5 || >=22.0.0 <22.12.0",
        "  nvd: >=20.0.0 <20.19.5",
        "",
        "References:",
        f"- https://github.com/advisories/{GHSA}",
        "- https://nodejs.org/en/blog/vulnerability/fixture",
        "- https://nvd.nist.gov/vuln/detail/CVE-2026-111497",
    ])
    refused = client.post(f"/api/findings/{finding['id']}/lab-runs", json=APPROVAL)
    assert (refused.status_code, refused.json()["code"]) == (409, "lab_not_allowed")
    assert refused.json()["message"] == "An Advisory check match gets a report and a bump Remediation PR, never a Lab Proof"
    assert client.get(f"/api/findings/{finding['id']}").json()["lab_runs"] == []
    assert stub.hosts() <= HOSTS


def test_deleting_an_advisory_finding_frees_its_match(system, monkeypatch):
    app, client, config = system
    github_account(app)
    stub = feeds(monkeypatch)
    stub.ghsa.append(GHSA_UNREADABLE)
    ident, _ = seeded(app, client, npm_files({"react": "^19.0.0"}, {"react": "19.0.0"}))
    run_check(app, client, config, ident)
    # A range that cannot be read is unknown, which counts as exposed: it opens a Finding.
    (finding,) = findings(client)
    assert (finding["source_ref"], finding["target_applicability"], finding["title"]) == (
        "GHSA-r2sh-fixt-ure1", "unknown", "react 19.0.0: React (fixture)")
    assert [(row.state, row.finding_id) for row in matches(app, ident)] == [("unknown", finding["id"])]
    assert client.delete(f"/api/findings/{finding['id']}").status_code == 204
    assert [(row.state, row.finding_id) for row in matches(app, ident)] == [("unknown", None)]
    assert stub.hosts() <= HOSTS


# The advisory bump (A06, A08): after a match opens a Finding, application code drafts a bump
# Remediation PR to the lowest fixed version, which opens only after Approval; and a bump seen on
# the Own repository's default branch remediates the Finding (A09, A11).
def steps(finding):
    return {row["step"]: row["status"] for row in finding["playbook"]}


def test_lowest_fixed_versions_and_runtime_edits():
    ranges = {"osv": OSV_RANGES, "nvd": NVD_RANGES}
    assert [advisories.lowest_fixed(v, ranges, "semver") for v in ("20.11.1", "22.1.0")] == ["20.19.5", "22.12.0"]
    # A bound inside another feed's range is not fixed, and one that is not a plain version is never written.
    assert advisories.lowest_fixed("1.0.0", {"osv": [[["<", "1.0.1"]]], "ghsa": [[["<", "1.0.2"]]]}, "semver") == "1.0.2"
    assert advisories.lowest_fixed("1.0.0", {"ghsa": [[["<", "1.0.1;rm -rf"]]]}, "semver") is None
    # Only the FROM token is replaced, and a digest after it is dropped: it names the old image.
    files = {"Dockerfile": b"FROM --platform=linux/amd64 docker.io/library/node:20.11.1@sha256:" + b"a" * 64
             + b" AS app\n# docker.io/library/node:20.11.1 is the base\n",
             "composer.json": json.dumps({"config": {"platform": {"php": "8.3.1"}}}).encode()}
    assert remediation.runtime_files(files, [
        {"source": "Dockerfile", "field": "dockerfile", "from": "docker.io/library/node:20.11.1",
         "to": "docker.io/library/node:20.19.5"},
        {"source": "composer.json", "field": "platform", "from": "8.3.1", "to": "8.3.15"}]) == {
        "Dockerfile": b"FROM --platform=linux/amd64 docker.io/library/node:20.19.5 AS app\n"
                      b"# docker.io/library/node:20.11.1 is the base\n",
        "composer.json": (json.dumps({"config": {"platform": {"php": "8.3.15"}}}, indent=4) + "\n").encode()}
    with pytest.raises(DomainError) as changed:
        remediation.runtime_files({".nvmrc": b"v20.12.0\n"}, [
            {"source": ".nvmrc", "field": "nvmrc", "from": "20.11.1", "to": "20.19.5"}])
    assert changed.value.code == "pin_changed"
    assert [remediation.branch_name(ref, action) for ref, action in ((CVE, "bump"), ("a" * 40, "patch"))] == [
        "asset-monitor/cve-2026-111497-bump", "asset-monitor/aaaaaaa-patch"]


def test_an_exposed_node_pin_drafts_a_dockerfile_bump_to_the_lowest_fixed_tag(system, monkeypatch):
    app, client, config = system
    github_account(app)
    stub = feeds(monkeypatch)
    files = {"Dockerfile": "FROM node:20.11.1-alpine AS build\nRUN npm ci\nFROM node:20.11.1-alpine\n",
             ".nvmrc": "v20.11.1\n", "package.json": json.dumps({"name": "shop", "engines": {"node": "20.11.1"}},
                                                                indent=2) + "\n"}
    ident, _ = seeded(app, client, files, role="own", source_url=SHOP)
    broker = FixtureBroker()
    run_check(app, client, config, ident, broker)
    (finding,) = findings(client)
    current = client.get(f"/api/findings/{finding['id']}").json()
    (draft,) = current["remediation_prs"]
    assert (draft["subject"], draft["action"], draft["status"], draft["base_ref"], draft["error"]) == (
        CVE, "bump", "ready", HEAD, None)
    # The lowest fixed version above the pin (20.19.5, not 22.12.0), put into the current tag.
    assert draft["dependency"] == {"ecosystem": "runtime", "name": "node", "version": "20.19.5", "edits": [
        {"source": "Dockerfile", "field": "dockerfile", "from": "node:20.11.1-alpine", "to": "node:20.19.5-alpine"},
        {"source": ".nvmrc", "field": "nvmrc", "from": "20.11.1", "to": "20.19.5"},
        {"source": "package.json", "field": "engines", "from": "20.11.1", "to": "20.19.5"}]}
    assert draft["summary"] == "Bumps node to 20.19.5 (Dockerfile, .nvmrc, package.json)"
    before = {path: text.encode() for path, text in files.items()}
    after = {path: text.replace("20.11.1", "20.19.5").encode() for path, text in files.items()}
    assert draft["diff"] == remediation.tree_diff(before, after)
    assert remediation.apply_diff(draft["diff"], before)["changed"] == after
    assert sorted(draft["paths"]) == sorted(files)
    assert (steps(current), current["remediation_actions"]) == ({"report": "ready", "remediation_pr": "ready"}, ["bump"])
    # Application code drafted it: no agent ran and no registry was asked; nothing opens before Approval.
    assert broker.calls == []
    with app.state.factory() as db:
        assert sorted(job.kind for job in db.scalars(select(Job))) == ["advisory_check", "notification",
                                                                      "remediation_draft"]
    assert stub.sent("npm.fixture") == [] and stub.hosts() <= HOSTS


def test_an_exposed_package_drafts_a_bump_to_its_lowest_fixed_version(system, monkeypatch):
    app, client, config = system
    github_account(app)
    stub = feeds(monkeypatch)
    scheduler = ghsa_package("GHSA-sche-dule-r000", "scheduler", "0.25.1")
    stub.ghsa += [GHSA_REACT, GHSA_UNREADABLE, scheduler]
    dist = {"tarball": f"http://npm.fixture/{PACKAGE}/-/{PACKAGE}-19.0.1.tgz", "integrity": "sha512-fixture"}
    stub.npm[f"/{PACKAGE}/19.0.1"] = {"name": PACKAGE, "version": "19.0.1", "dist": dist}
    # An advisory-only React2Shell: no fix commit, the package advisory alone.
    files = {path: text.encode() for path, text in npm_files(
        {PACKAGE: "19.0.0", "react": "^19.0.0"}, {PACKAGE: "19.0.0", "react": "19.0.0", "scheduler": "0.25.0"}).items()}
    ident, _ = seeded(app, client, {path: data.decode() for path, data in files.items()}, role="own", source_url=SHOP)
    assert run_check(app, client, config, ident)["result"]["opened"] == 3
    found = {f["source_ref"]: client.get(f"/api/findings/{f['id']}").json() for f in findings(client)}
    (draft,) = found[R2S_CVE]["remediation_prs"]
    assert (draft["subject"], draft["action"], draft["status"], draft["summary"]) == (
        R2S_CVE, "bump", "ready", f"Bumps {PACKAGE} to 19.0.1")
    assert draft["dependency"] == {"ecosystem": "npm", "names": [PACKAGE], "version": "19.0.1",
                                   "versions": {PACKAGE: "19.0.1"}}
    # Phase 6's dependency_files: package.json and the lock entry, with the registry's dist.
    applied = remediation.apply_diff(draft["diff"], files)
    assert applied["changed"] == remediation.dependency_files(files, "npm", PACKAGE, "19.0.1", "bump", dist)
    assert json.loads(applied["changed"]["package.json"])["dependencies"][PACKAGE] == "19.0.1"
    assert json.loads(applied["changed"]["package-lock.json"])["packages"][f"node_modules/{PACKAGE}"] == {
        "version": "19.0.1", "resolved": dist["tarball"], "integrity": dist["integrity"]}
    # A package only the lockfile names is matched but not bumped, and an unreadable range has no
    # fixed version to bump to.
    for ref, reason in ((scheduler["ghsa_id"], "not_direct"), (GHSA_UNREADABLE["ghsa_id"], "no_fixed_version")):
        assert (steps(found[ref])["remediation_pr"], found[ref]["remediation_actions"],
                found[ref]["remediation_prs"]) == (reason, [], [])
        refused = client.post(f"/api/findings/{found[ref]['id']}/remediation-prs", json={"action": "bump"})
        assert (refused.status_code, refused.json()["code"]) == (422, "remediation_unavailable")
    assert [request.url.path for request, _ in stub.sent("npm.fixture")] == [f"/{PACKAGE}/19.0.1"]
    assert stub.hosts() <= HOSTS


def test_approving_the_advisory_bump_opens_one_draft_pull_request(system, monkeypatch):
    app, client, config = system
    github_account(app)
    write_token(app)
    github = FakeGitHub()
    stub = feeds(monkeypatch, github)
    github.commit(HEAD, {"Dockerfile": b"FROM node:20.11.1-alpine\n"})
    github.push(HEAD)
    ident, _ = seeded(app, client, {"Dockerfile": "FROM node:20.11.1-alpine\n"}, role="own", source_url=SHOP)
    run_check(app, client, config, ident)
    (finding,) = findings(client)
    (draft,) = client.get(f"/api/findings/{finding['id']}").json()["remediation_prs"]
    assert draft["status"] == "ready" and github.pulls == []
    first, second = approve(client, draft), approve(client, draft)
    assert first.status_code == second.status_code == 202 and first.json()["job_id"] == second.json()["job_id"]
    drain((app, client, config), FixtureBroker())
    assert approve(client, draft).json()["job_id"] == first.json()["job_id"]
    drain((app, client, config), FixtureBroker())
    (opened,) = client.get(f"/api/findings/{finding['id']}").json()["remediation_prs"]
    (pull,) = github.pulls
    branch = "asset-monitor/cve-2026-111497-bump"
    assert (opened["status"], opened["branch"], pull["head"]["ref"], pull["draft"]) == ("open", branch, branch, True)
    assert pull["title"] == f"Asset Monitor bump for {CVE}"
    assert github.files(github.refs[f"heads/{branch}"]) == {"Dockerfile": ("100644", b"FROM node:20.19.5-alpine\n")}
    assert github.writes().count(("POST", "/repos/acme/shop/pulls")) == 1
    # The Operator merges; the next poll sees the merge commit on the default branch.
    merged = "1" * 40
    pull.update(state="closed", merged=True, merge_commit_sha=merged)
    github.push(merged)
    poll((app, client, config), ident)
    after = client.get(f"/api/findings/{finding['id']}").json()
    assert (after["status"], after["cause"]["by"], after["remediation_prs"][0]["status"]) == (
        "remediated", "remediation_pr", "merged")
    assert stub.hosts() <= HOSTS


def test_without_an_own_repository_the_advisory_bump_is_skipped(system, monkeypatch):
    app, client, config = system
    github_account(app)
    stub = feeds(monkeypatch)
    ident, _ = seeded(app, client, {"Dockerfile": "FROM node:20.11.1-alpine\n"})
    run_check(app, client, config, ident)
    (finding,) = findings(client)
    current = client.get(f"/api/findings/{finding['id']}").json()
    assert (steps(current)["remediation_pr"], current["own_repository"], current["remediation_actions"],
            current["remediation_prs"]) == ("no_own_repository", False, [], [])
    refused = client.post(f"/api/findings/{finding['id']}/remediation-prs", json={"action": "bump"})
    assert (refused.status_code, refused.json()["code"]) == (422, "remediation_unavailable")
    assert refused.json()["message"] == "No Own repository: Remediation PR steps are skipped"
    with app.state.factory() as db:
        assert db.scalars(select(Job).where(Job.kind == "remediation_draft")).all() == []
    assert stub.hosts() <= HOSTS


def test_a_bump_to_a_fixed_version_seen_on_the_default_branch_remediates_the_finding(
        system, monkeypatch, local_sources):
    app, client, config = system
    github_account(app)
    fixtures = serve(monkeypatch, npm={PACKAGE: NUMEN_REACT, "left-pad": None})
    stub = feeds(monkeypatch, fixtures)
    left_pad = ghsa_package("GHSA-left-padf-ix00", "left-pad", "1.3.1")
    stub.ghsa += [GHSA_REACT, left_pad]
    monkeypatch.setattr(Sources, "snapshot_github", lambda self, repository, revision: {
        path: text.encode() for path, text in dict(fixtures.history("acme/shop"))[revision].items()})
    # Shop: its Own repository acme/shop, and the React2Shell fix commit's Finding, which the
    # package advisory attaches to. Its React link is derived, so the lockfile's version is used.
    ident, commit, release = react_fix(system, local_sources, own=True)
    with app.state.factory.begin() as db:
        fixtures.trees["numen/react"] = [(db.get(Commit, commit).revision, {})]  # nothing new upstream
        db.scalar(select(ApplicationRepository).where(ApplicationRepository.application_id == ident,
                                                      ApplicationRepository.role == "upstream")
                  ).locked_version_source = "manifest"
    job, _ = analyze(system, commit, {**assessment("Vulnerability fix", release), "addresses": [R2S_GHSA]},
                     without_package(pinned_bundle(release)))
    (attached,) = job["result"]["finding_ids"]
    vulnerable = fixtures.push("acme/shop", {"Dockerfile": "FROM node:20.11.1-alpine\n", **npm_files(
        {PACKAGE: "19.0.0", "left-pad": "^1.3.0"}, {PACKAGE: "19.0.0", "left-pad": "1.3.0"})})
    check(app, client, config, ident)
    found = {f["source_ref"]: f["id"] for f in findings(client)}
    node = found[CVE]
    assert client.get(f"/api/findings/{attached}").json()["status"] == "confirmed"
    assert transition(client, found[left_pad["ghsa_id"]], "remediated", "left-pad is never loaded").status_code == 200
    before = {ref: client.get(f"/api/findings/{fid}").json() for ref, fid in found.items() if fid != node}

    fixed = fixtures.push("acme/shop", {"Dockerfile": "FROM node:20.19.5-alpine\n", **npm_files(
        {PACKAGE: "19.0.1", "left-pad": "^1.3.1"}, {PACKAGE: "19.0.1", "left-pad": "1.3.1"})})
    check(app, client, config, ident)
    # The pin-file change on the default branch queued the check that saw the bump.
    assert [(job.idempotency_key, job.status) for job in advisory_jobs(app)] == [
        (f"advisory:{ident}:{vulnerable}", "succeeded"), (f"advisory:{ident}:{fixed}", "succeeded")]
    remediated = client.get(f"/api/findings/{node}").json()
    assert remediated["status"] == "remediated"
    assert {k: v for k, v in remediated["cause"].items() if k != "at"} == {
        "by": "version_bump", "advisory_id": CVE, "revision": fixed, "versions": {"node": ["20.19.5"]}}
    assert {row.vulnerability: row.state for row in matches(app, ident)}[CVE] == "not_exposed"
    # The commit Finding the React2Shell match attached to is Remediated by the same bump (A11),
    # and the advisory Finding the Operator Remediated keeps its cause.
    shared = client.get(f"/api/findings/{attached}").json()
    assert {k: v for k, v in shared["cause"].items() if k != "at"} == {
        "by": "version_bump", "advisory_id": R2S_CVE, "revision": fixed, "versions": {PACKAGE: ["19.0.1"]}}
    assert (shared["source"], shared["status"]) == ("commit", "remediated")
    before.pop(next(ref for ref, f in before.items() if f["id"] == attached))
    assert [(f["source"], f["status"], f["cause"]["by"]) for f in before.values()] == [
        ("advisory", "remediated", "operator")]
    for ref, earlier in before.items():
        current = client.get(f"/api/findings/{found[ref]}").json()
        assert (current["status"], current["cause"]) == (earlier["status"], earlier["cause"]), ref
    assert stub.hosts() <= HOSTS


def test_a_bump_short_of_a_widened_range_leaves_the_finding_as_it_is(system, monkeypatch):
    app, client, config = system
    github_account(app)
    stub = feeds(monkeypatch)
    ident, repository_id = seeded(app, client, {"Dockerfile": "FROM node:20.11.1-alpine\n"}, role="own",
                                  source_url=SHOP)
    run_check(app, client, config, ident)
    (finding,) = findings(client)
    # The fix was incomplete: the feeds now say 20.19.6, while the Own default branch moves to 20.19.5.
    widened = json.loads(json.dumps(OSV_NODE).replace("20.19.5", "20.19.6"))
    stub.osv = {widened["id"]: {**widened, "modified": "2026-11-02T00:00:00Z"}}
    stub.nvd = [json.loads(json.dumps(NVD_NODE).replace("20.19.5", "20.19.6"))]
    age_cache(app)
    tree(app, repository_id, "d" * 40, {"Dockerfile": b"FROM node:20.19.5-alpine\n"}, head=True)
    run_check(app, client, config, ident)
    (row,) = matches(app, ident)
    assert (row.state, [(p["version"], p["state"]) for p in row.data["pins"]]) == ("exposed", [("20.19.5", "exposed")])
    assert client.get(f"/api/findings/{finding['id']}").json()["status"] == "confirmed"
    assert stub.hosts() <= HOSTS


def test_a_later_alias_that_joins_two_keys_keeps_the_finding_of_one(system, monkeypatch):
    app, client, config = system
    github_account(app)
    stub = feeds(monkeypatch)
    # OSV first lists only a record for 22.x without aliases, which Node 20.11.1 is not exposed to.
    other = {**OSV_NODE, "id": "OSV-2026-0022", "aliases": [], "affected": [{
        "package": {"ecosystem": "Bitnami", "name": "node"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "22.0.0"}, {"fixed": "22.12.0"}]}]}]}
    stub.osv, stub.nvd = {other["id"]: other}, []
    ident, _ = seeded(app, client, {"Dockerfile": "FROM node:20.11.1-alpine\n"})
    run_check(app, client, config, ident)
    assert [(row.vulnerability, row.state, row.finding_id) for row in matches(app, ident)] == [
        ("OSV-2026-0022", "not_exposed", None)]
    # NVD then lists CVE-2026-111497, which opens its Finding under a second key.
    stub.nvd = [NVD_NODE]
    age_cache(app)
    run_check(app, client, config, ident)
    (finding,) = findings(client)
    # OSV learns that its record is that vulnerability: the keys fold into the one with the Finding.
    stub.osv = {other["id"]: {**other, "aliases": [CVE], "modified": "2026-11-02T00:00:00Z"}}
    age_cache(app)
    job = run_check(app, client, config, ident)
    (row,) = matches(app, ident)
    assert (row.vulnerability, row.finding_id, row.state, row.aliases) == (
        CVE, finding["id"], "exposed", sorted([CVE, GHSA, "OSV-2026-0022"]))
    assert (job["result"]["opened"], [f["id"] for f in findings(client)], len(alerts(app))) == (0, [finding["id"]], 1)
    assert stub.hosts() <= HOSTS
