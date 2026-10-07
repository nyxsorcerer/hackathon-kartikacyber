import io
import json
import zipfile

import httpx

from conftest import FixtureBroker, program, source_snapshot
from numen import fingerprint_probe, fingerprints
from numen.artifacts import publish
from numen.models import Program, VersionRecipe
from numen.sources import Sources
from numen.worker import run_once
from numen.workflows import merge_fingerprints


def package(folder, files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path, content in files.items():
            archive.writestr(f"{folder}/{path}", content)
    return buffer.getvalue()


def release_files(version):
    return {
        "js/app.js": f"app {version}".encode(),  # differs per release
        "css/site.css": b"same in every release",
        "index.php": f"<?php // {version}".encode(),  # executed by the server, never served
        "composer.json": f'{{"version": "{version}"}}'.encode(),  # not deployed
        "vendor/composer/installed.json": version.encode(),
        ".htaccess": version.encode(),
        "VERSION": version.encode(),
    }


def test_release_corpus_fingerprints_served_files_of_one_installer_package(system, monkeypatch):
    app, client, config = system
    p = program(client)
    base = "https://api.github.com/repos/demo/plugin/releases/assets/"
    releases = [
        {
            "tag_name": version,
            "assets": [
                {"name": f"app-{version}-remote-updater.zip", "size": 9, "url": base + version + "-updater"},
                {"name": f"app-{version}.zip", "size": 9, "url": base + version},
            ],
        }
        for version in ("2.0.0", "1.0.0")
    ]
    requested = []

    def get(url, params=None, headers=None):
        requested.append(url)
        if url.endswith("/releases"):
            return httpx.Response(200, json=releases)
        version = url.rsplit("/", 1)[1]
        return httpx.Response(200, content=package(f"app-{version}", release_files(version)))

    source = Sources(config)
    monkeypatch.setattr(source, "get", get)
    with app.state.factory() as db:
        corpus = source.release_corpus(db.get(Program, p["id"]))
    assert not any(url.endswith("-updater") for url in requested)
    # Paths drop the versioned package folder and keep only assets a site publishes;
    # manifests, dependency metadata and server config are never fingerprinted or requested.
    assert sorted(corpus["fingerprints"]) == ["VERSION", "css/site.css", "js/app.js"]
    assert [probe["path"] for probe in corpus["probes"]] == ["VERSION", "js/app.js"]
    assert corpus["resolution"] == [["2.0.0"], ["1.0.0"]]
    assert all(release["distributed"] for release in corpus["releases"])


CORPUS = {
    "releases": [{"version": v} for v in ("3.0", "2.1", "2.0", "1.0")],
    "probes": [
        # A bundle that splits every release, but which this deployment does not serve.
        {"path": "js/legacy.js", "size": 10, "digests": {"l3": ["3.0"], "l21": ["2.1"], "l20": ["2.0"], "l1": ["1.0"]}},
        {"path": "js/app.js", "size": 50, "digests": {"a3": ["3.0"], "a2": ["2.1", "2.0"], "a1": ["1.0"]}},
        {"path": "css/site.css", "size": 20, "digests": {"s3": ["3.0", "2.1"], "s2": ["2.0", "1.0"]}},
    ],
}


def site(served):
    requests = []

    def fetch(url, method="GET"):
        requests.append(url)
        path = url.removeprefix("https://site.test/")
        return {"status": 200, "sha256": served[path]} if path in served else {"status": 404}

    return fetch, requests


def test_fingerprint_probe_fetches_what_splits_the_remaining_releases():
    fetch, requests = site({"js/app.js": "a2", "css/site.css": "s3", "js/legacy.js": "l21"})
    result = fingerprint_probe.match(fetch, "https://site.test/", CORPUS, 10)
    # One served four-way split settles it; nothing further is requested.
    assert result["candidates"] == ["2.1"] and requests == ["https://site.test/js/legacy.js"]
    # The four-way split comes first; when it is not served, the others still narrow to one.
    fetch, requests = site({"js/app.js": "a2", "css/site.css": "s3"})
    result = fingerprint_probe.match(fetch, "https://site.test/", CORPUS, 10)
    assert requests == ["https://site.test/js/legacy.js", "https://site.test/js/app.js", "https://site.test/css/site.css"]
    assert result["candidates"] == ["2.1"]
    # Bytes from no captured release narrow nothing and are reported.
    fetch, _ = site({"js/app.js": "rebuilt"})
    result = fingerprint_probe.match(fetch, "https://site.test/", CORPUS, 10)
    assert result["candidates"] == [] and result["unmatched"] == ["js/app.js"]
    fetch, requests = site({})
    assert fingerprint_probe.match(fetch, "https://site.test/", CORPUS, 2)["requests"] == 2


def observation(**overrides):
    return {"status": "ambiguous", "version": None, "candidates": [], "method": "html_markers", "evidence": ["page"], "limitations": [], **overrides}


def fingerprint_match(candidates, unmatched=()):
    return {"candidates": candidates, "matched": 1, "unmatched": list(unmatched), "evidence": [{"path": "js/app.js", "sha256": "a2"}]}


def test_release_fingerprints_narrow_but_never_overrule_a_disclosure():
    exact = merge_fingerprints(observation(), fingerprint_match(["2.1"]), CORPUS)
    assert exact["status"] == "detected" and exact["version"] == "2.1"
    assert exact["method"] == "html_markers+release_fingerprints"
    assert exact["confidence"]["level"] == "medium" and "1.0 to 3.0" in exact["limitations"][-1]
    assert exact["evidence"] == ["page", {"path": "js/app.js", "sha256": "a2"}]
    shared = merge_fingerprints(observation(), fingerprint_match(["2.1", "2.0"]), CORPUS)
    assert shared["status"] == "ambiguous" and shared["candidates"] == ["2.1", "2.0"]
    # A stray unmatched file keeps a single candidate from becoming an exact claim.
    assert merge_fingerprints(observation(), fingerprint_match(["2.1"], ["css/x.css"]), CORPUS)["status"] == "ambiguous"
    consistent = merge_fingerprints(observation(status="detected", version="2.0"), fingerprint_match(["2.1", "2.0"]), CORPUS)
    assert consistent["status"] == "detected" and consistent["version"] == "2.0"
    contradicted = merge_fingerprints(observation(status="detected", version="3.0"), fingerprint_match(["2.1"]), CORPUS)
    assert contradicted["status"] == "unknown" and contradicted["candidates"] == ["2.1"]
    nothing = merge_fingerprints(observation(), {"candidates": [], "matched": 0, "unmatched": [], "evidence": [{"status": 404}]}, CORPUS)
    assert nothing["status"] == "ambiguous" and "No distinguishing release file could be fetched (1 tried)" in nothing["limitations"]


def test_version_check_runs_numen_fingerprint_stage_after_the_recipe(system):
    app, client, config = system
    p = program(client, source_kind="wordpress", source_url="https://plugins.svn.wordpress.org/demo", plugin_slug="demo", source_ref=None)
    source_snapshot(app, p["id"])
    corpus = {**CORPUS, "fingerprints": {}, "limitations": []}
    with app.state.factory.begin() as db:
        recipe = VersionRecipe(program_id=p["id"], source_generation=1, source_ref="a" * 40, status="active", data={})
        db.add(recipe)
        db.flush()
        publish(db, config.artifact_root, "recipe", recipe.id, {
            "determine_version.py": b"print('script')",
            "recipe.json": b"{}",
            "release-corpus.json": json.dumps(corpus).encode(),
        })
        row = db.get(Program, p["id"])
        row.config = {**row.config, "active_recipe_id": recipe.id}
    stages = []

    def handler(call):
        target = json.loads(call["files"]["target.json"])
        if call["files"]["recipe.py"] == fingerprints.MATCHER.read_bytes():
            stages.append(("fingerprints", target, call["policy"]["request_budget"]))
            return fingerprint_match(["2.1"]), {}
        stages.append(("recipe", target["mode"], call["policy"]["request_budget"]))
        return observation(), {}

    client.post(f"/api/programs/{p['id']}/version-checks")
    run_once(config, app.state.factory, FixtureBroker(handler=handler))
    assert stages == [
        ("recipe", "observe", 25),
        ("fingerprints", {"base_url": "https://example.com/wp-content/plugins/demo/", "budget": 10}, 10),
    ]
    version = client.get(f"/api/programs/{p['id']}").json()["version"]
    assert version["status"] == "detected" and version["version"] == "2.1"
    assert version["method"] == "html_markers+release_fingerprints"


def test_fingerprint_base_follows_the_recipe_only_onto_allowed_origins():
    from types import SimpleNamespace

    from numen.workflows import fingerprint_base

    site_program = SimpleNamespace(asset_url="https://site.test/cms", source_kind="github", plugin_slug=None)
    policy = {"origins": ["https://site.test", "https://cdn.site.test"]}
    assert fingerprint_base(site_program, {}, policy) == "https://site.test/cms/"
    assert fingerprint_base(site_program, {"asset_base": "static"}, policy) == "https://site.test/cms/static/"
    assert fingerprint_base(site_program, {"asset_base": "https://cdn.site.test/v"}, policy) == "https://cdn.site.test/v/"
    assert fingerprint_base(site_program, {"asset_base": "https://evil.test/"}, policy) == "https://site.test/cms/"
    assert fingerprints.strip_root({"a-1/x.js": b"", "a-1/y/z.css": b""}) == {"x.js": b"", "y/z.css": b""}
    assert fingerprints.strip_root({"x.js": b"", "y/z.css": b""}) == {"x.js": b"", "y/z.css": b""}
