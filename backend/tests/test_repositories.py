"""Applications link one Own and any number of Upstream repositories, each stored once per URL."""

import json
from datetime import timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from conftest import FixtureBroker, application, connection, github_account, source_snapshot
from test_workflows import source_record
from numen import domain
from numen.models import (
    Application, ApplicationRepository, Commit, Job, Repository, VersionRecipe, now,
)
from numen.sources import Sources
from numen.worker import run_once

BODY = {
    "asset_name": "Portal",
    "asset_url": "https://portal.example.com",
    "product_kind": "CMS",
    "product_name": "Portal",
    "monitor_interval_seconds": 172800,
}
REACT = "https://github.com/facebook/react"
TRIAGE = {"reply": json.dumps({
    "decision": "security_candidate",
    "title": "Potential input trust boundary vulnerability",
    "reason": "Input trust boundary changed",
})}


def bare(client, **overrides):
    created = client.post("/api/applications", json={**BODY, **overrides})
    assert created.status_code == 201, created.text
    return created.json()["id"], f"/api/applications/{created.json()['id']}/repositories"


def test_saved_application_reopens_with_its_repositories_and_states(system):
    _, client, _ = system
    ident, base = bare(client)
    own = client.post(base, json={
        "role": "own", "source_kind": "github", "source_url": "https://github.com/Acme/Portal.git/"})
    assert own.status_code == 201, own.text
    react = client.post(base, json={"source_kind": "github", "source_url": REACT, "locked_version": "19.0.0"})
    plugin = client.post(base, json={"source_kind": "wordpress", "plugin_slug": "akismet", "locked_version": "5.3"})
    assert react.status_code == plugin.status_code == 201
    react, plugin = react.json(), plugin.json()
    assert client.patch(f"{base}/{react['repository_id']}", json={"enabled": False}).status_code == 200
    assert client.delete(f"{base}/{plugin['repository_id']}").status_code == 200
    reopened = client.get(f"/api/applications/{ident}").json()["repositories"]
    assert [
        (r["role"], r["source_url"], r["enabled"], r["removed_at"] is not None,
         r["locked_version"], r["locked_version_source"])
        for r in reopened
    ] == [
        ("own", "https://github.com/acme/portal", True, False, None, None),
        ("upstream", REACT, False, False, "19.0.0", "operator"),
        ("upstream", "https://plugins.svn.wordpress.org/akismet", True, True, "5.3", "operator"),
    ]
    assert reopened[2]["plugin_slug"] == "akismet" and reopened[2]["source_ref"] == "trunk"
    assert [a["id"] for a in client.get("/api/applications?q=facebook/react").json()["items"]] == [ident]
    # An explicit null clears the Locked version and where it came from; omitted fields stay.
    cleared = client.patch(f"{base}/{react['repository_id']}", json={"locked_version": None}).json()
    assert (cleared["locked_version"], cleared["locked_version_source"], cleared["enabled"]) == (
        None, None, False)
    assert client.patch(f"{base}/missing", json={"enabled": True}).status_code == 404
    # Turning a link on brings the next check forward, so the repository gets its Baseline.
    assert client.post(f"/api/applications/{ident}/checks").status_code == 202
    later = client.get(f"/api/applications/{ident}").json()["next_check_at"]
    client.patch(f"{base}/{react['repository_id']}", json={"enabled": True})
    assert client.get(f"/api/applications/{ident}").json()["next_check_at"] < later


def test_application_has_at_most_one_own_repository(system):
    app, client, _ = system
    ident, base = bare(client)
    first = client.post(base, json={"role": "own", "source_kind": "github", "source_url": "https://github.com/acme/one"})
    assert first.status_code == 201
    second = client.post(base, json={"role": "own", "source_kind": "github", "source_url": "https://github.com/acme/two"})
    assert second.status_code == 409 and second.json()["code"] == "own_repository_exists"
    wordpress = client.post(base, json={"role": "own", "source_kind": "wordpress", "plugin_slug": "akismet"})
    assert wordpress.status_code == 422
    again = client.post(base, json={"source_kind": "github", "source_url": "https://github.com/ACME/one"})
    assert again.status_code == 409 and again.json()["code"] == "repository_linked"
    assert client.delete(f"{base}/{first.json()['repository_id']}").status_code == 200
    replaced = client.post(base, json={"role": "own", "source_kind": "github", "source_url": "https://github.com/acme/two"})
    assert replaced.status_code == 201, replaced.text
    active = [r["source_url"] for r in client.get(f"/api/applications/{ident}").json()["repositories"]
              if r["role"] == "own" and r["removed_at"] is None]
    assert active == ["https://github.com/acme/two"]
    # The database refuses a second active Own repository even past the API.
    with pytest.raises(IntegrityError):
        with app.state.factory.begin() as db:
            extra = Repository(source_kind="github", source_url="https://github.com/acme/three")
            db.add(extra)
            db.flush()
            db.add(ApplicationRepository(application_id=ident, repository_id=extra.id, role="own"))


def test_shared_upstream_repository_is_polled_and_triaged_once(system, monkeypatch):
    app, client, config = system
    profile = connection(app)
    github_account(app)
    own_profile = {**profile, "agent": "pi", "reasoning_effort": "low"}
    shop = application(client, asset_name="Shop", source_url=REACT, source_ref=None)
    blog = application(client, asset_name="Blog", source_url=REACT, source_ref=None,
                       config={"triage_mode": "pi", "profiles": {"commit_triage": own_profile}})
    with app.state.factory() as db:
        assert db.scalar(select(func.count()).select_from(Repository)) == 1
    polls = []
    head = {"sha": "a" * 40}

    def commits(_, repository):
        polls.append(repository.source_url)
        # The first check only sets the Baseline.
        return head["sha"], [source_record(head["sha"])] if repository.cursor else [], None

    monkeypatch.setattr(Sources, "github_commits", commits)

    def tick():
        with app.state.factory.begin() as db:
            for row in db.scalars(select(Application)):
                row.next_check_at = now() - timedelta(seconds=1)
            assert domain.schedule(db) == 2
            checks = db.scalars(select(Job).where(Job.kind == "source_check", Job.status == "queued")).all()
            assert len(checks) == 1
        # The automatic Analysis a flag queues is not run: no snapshot of the head is stored.
        while run_once(config, app.state.factory, FixtureBroker(TRIAGE), exclude=("commit_analysis",)):
            pass

    def triage_jobs():
        with app.state.factory() as db:
            return db.scalars(select(Job).where(Job.kind == "commit_triage")).all()

    tick()  # The Baseline imports and triages nothing.
    head["sha"] = "b" * 40
    tick()
    assert polls == [REACT, REACT]
    jobs = triage_jobs()
    assert len(jobs) == 1 and jobs[0].application_id == blog["id"]
    assert jobs[0].profile["reasoning_effort"] == "low" and jobs[0].status == "succeeded"
    with app.state.factory() as db:
        (analysis,) = db.scalars(select(Job).where(Job.kind == "commit_analysis")).all()
    # A shared Upstream commit is analysed once, in the context of the first Application using it.
    assert (analysis.application_id, analysis.input["automatic"], analysis.input["shared"]) == (shop["id"], True, True)
    client.patch(f"/api/applications/{blog['id']}", json={"config": {"triage_mode": "disabled"}})
    head["sha"] = "c" * 40
    tick()
    assert len(triage_jobs()) == 1
    with app.state.factory() as db:
        rows = {c.revision: c for c in db.scalars(select(Commit))}
    assert sorted(rows) == ["b" * 40, "c" * 40]
    assert rows["c" * 40].triage_status == "disabled" and rows["b" * 40].triage_status == "completed"
    for monitored in (shop, blog):
        listed = client.get(f"/api/applications/{monitored['id']}/commits").json()["items"]
        assert sorted(c["revision"] for c in listed) == sorted(rows)


def test_application_commit_list_shows_commits_of_linked_repositories(system):
    app, client, _ = system
    p = application(client)
    other = application(client, asset_name="Other", source_url="https://github.com/demo/other")
    upstream = source_snapshot(app, p["id"], "a" * 40)
    unrelated = source_snapshot(app, other["id"], "c" * 40)
    base = f"/api/applications/{p['id']}/repositories"
    linked = client.post(base, json={"role": "own", "source_kind": "github",
                                     "source_url": "https://github.com/demo/own"})
    assert linked.status_code == 201
    own = source_snapshot(app, p["id"], "b" * 40, linked.json()["repository_id"])

    def listed(path):
        return {c["id"] for c in client.get(path).json()["items"]}

    assert listed(f"/api/applications/{p['id']}/commits") == {upstream, own}
    assert listed(f"/api/commits?application_id={p['id']}") == {upstream, own}
    assert listed(f"/api/applications/{other['id']}/commits") == {unrelated}
    plugin = next(r for r in client.get(f"/api/applications/{p['id']}").json()["repositories"]
                  if r["source_url"] == "https://github.com/demo/plugin")
    assert client.delete(f"{base}/{plugin['repository_id']}").status_code == 200
    # A removed repository keeps its history in the Application's commit list.
    assert listed(f"/api/applications/{p['id']}/commits") == {upstream, own}
    commit = client.get(f"/api/commits/{upstream}").json()
    assert (commit["repository_id"], commit["application_id"]) == (plugin["repository_id"], p["id"])


def test_migrated_application_keeps_its_source_when_it_gets_an_own_repository(system):
    app, client, _ = system
    selectors = [{"type": "cpe", "value": "cpe:2.3:a:automattic:akismet:*:*:*:*:*:wordpress:*:*"}]
    p = application(client, source_kind="wordpress", plugin_slug="akismet", config={"cve_selectors": selectors})
    plugin = p["repositories"][0]["repository_id"]
    source_snapshot(app, p["id"], "7")
    with app.state.factory.begin() as db:
        row = db.get(Application, p["id"])
        recipe = VersionRecipe(application_id=row.id, source_generation=row.source_generation,
                               source_ref="7", status="active", data={})
        db.add(recipe)
        db.flush()
        recipe_id, generation = recipe.id, row.source_generation
        row.config = {**row.config, "active_recipe_id": recipe_id}
        row.cve_cursor = {"completed_at": "2026-11-01T00:00:00Z"}
    base = f"/api/applications/{p['id']}/repositories"
    own = client.post(base, json={"role": "own", "source_kind": "github", "source_url": "https://github.com/acme/site"})
    assert own.status_code == 201, own.text
    assert client.patch(f"{base}/{plugin}", json={"enabled": False}).status_code == 200
    with app.state.factory() as db:
        row = db.get(Application, p["id"])
        assert (row.source_generation, row.config["active_recipe_id"], row.cve_cursor) == (
            generation, recipe_id, {"completed_at": "2026-11-01T00:00:00Z"})
        assert row.config["cve_selectors"] == selectors
        # CVE analysis, version checks and audit contexts still read the plugin.
        assert domain.source_repository(db, row).id == plugin
        assert domain.job_input(db, row) == {"source_generation": generation, "source_ref": "7"}
    # The recipe can still be chosen again, since it belongs to the current source.
    patched = client.patch(f"/api/applications/{p['id']}", json={"config": {"active_recipe_id": recipe_id}})
    assert patched.status_code == 200, patched.text
    # Removing the plugin replaces the source: a new generation without the recipe.
    assert client.delete(f"{base}/{plugin}").status_code == 200
    with app.state.factory() as db:
        row = db.get(Application, p["id"])
        assert row.source_generation == generation + 1 and row.config["active_recipe_id"] is None
        assert domain.source_repository(db, row).id == own.json()["repository_id"]


def test_commit_belongs_to_an_application_that_still_uses_its_repository(system):
    app, client, _ = system
    connection(app)
    first = application(client, asset_name="First", source_url=REACT, source_ref=None)
    second = application(client, asset_name="Second", source_url=REACT, source_ref=None)
    react = first["repositories"][0]["repository_id"]
    assert client.delete(f"/api/applications/{first['id']}/repositories/{react}").status_code == 200
    commit_id = source_snapshot(app, second["id"])
    assert client.get(f"/api/commits/{commit_id}").json()["application_id"] == second["id"]
    single = client.post(f"/api/commits/{commit_id}/analyses", json={})
    assert single.status_code == 202, single.text
    assert client.get(f"/api/jobs/{single.json()['job_id']}").json()["application_id"] == second["id"]


def test_check_now_queues_one_source_check_per_linked_repository(system):
    _, client, _ = system
    p = application(client)
    base = f"/api/applications/{p['id']}/repositories"

    def link(url):
        response = client.post(base, json={"source_kind": "github", "source_url": url})
        assert response.status_code == 201, response.text
        return response.json()["repository_id"]

    second = link("https://github.com/demo/second")
    client.patch(f"{base}/{link('https://github.com/demo/off')}", json={"enabled": False})
    client.delete(f"{base}/{link('https://github.com/demo/gone')}")
    endpoint = f"/api/applications/{p['id']}/checks"
    response = client.post(endpoint, headers={"Idempotency-Key": "check-1"})
    assert response.status_code == 202, response.text
    items = response.json()["items"]
    plugin = p["repositories"][0]["repository_id"]
    assert [i["repository_id"] for i in items] == [plugin, second]
    assert all(i["status_url"] == f"/api/jobs/{i['job_id']}" for i in items)
    jobs = [client.get(i["status_url"]).json() for i in items]
    assert {j["kind"] for j in jobs} == {"source_check"} and len({j["id"] for j in jobs}) == 2
    assert client.post(endpoint, headers={"Idempotency-Key": "check-1"}).json()["items"] == items
    # An active check of a repository is reused, also from another Application that shares it.
    assert client.post(endpoint).json()["items"] == items
    other = application(client, asset_name="Other", source_url="https://github.com/demo/second")
    shared = client.post(f"/api/applications/{other['id']}/checks").json()["items"]
    assert shared == [items[1]]
    empty, _ = bare(client)
    refused = client.post(f"/api/applications/{empty}/checks")
    assert refused.status_code == 422 and refused.json()["code"] == "repository_required"
