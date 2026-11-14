"""Served-content checks (A10): each Asset's Watched pages (the homepage always one, the others on
the Asset URL's origin), checked on the Application's interval and on the Asset's Check now. The
fixed probe fetches each page and its scripts as browser and as Googlebot through the gateway,
the bytes are stored by content hash, and each user agent's Content fingerprint is compared with
the Baseline, which the Operator accepts first.

served_broker stands in for the runner: each 'probe' call runs served_probe.collect over an
in-memory site, as the probe does through the gateway. Its pages are the inert ones of
test_served_fingerprints: judol links point at .test hosts and the ClickFix prompt's clipboard
command is a harmless placeholder. No test reaches a real host."""

import base64
import hashlib
import json
from datetime import timedelta

from sqlalchemy import func, select, update

from conftest import FixtureBroker
from numen import domain, served, served_probe
from numen.models import Action, Artifact, Job, ServedChange, ServedFetch, now
from numen.worker import run_once
from numen.workflows import SERVED_POLICY, Workflows
from test_served_fingerprints import CLICKFIX_BODY, CLICKFIX_HEAD, JUDOL, rendered, scripts

SHOP = "https://shop.test"
BODY = {"asset_name": "Toko Batik Sari", "asset_url": SHOP, "product_kind": "app", "product_name": "Shop",
        "monitor_interval_seconds": 172800}


def page(body, content_type="text/html"):
    return 200, {"content-type": content_type}, body


def shop_site(browser, googlebot=None, build="3f9a1c2b"):
    """The fixture shop's homepage as each user agent is served it, and its scripts."""
    return {("browser", SHOP): page(browser), ("googlebot", SHOP): page(googlebot or browser),
            **{(None, url): page(body, "text/javascript") for url, body in scripts(build).items()}}


def served_broker(site, handler=None):
    """A FixtureBroker that answers each 'probe' call as the runner runs the fixed probe:
    served_probe.collect over `site`, {(user agent, or None for both, url): (status, headers,
    body)}, 404 for any other URL. broker.requested records every (url, user agent) fetched, and
    every other call goes to `handler`. The site may change between checks."""
    requested = []

    def fetch(url, method="GET", user_agent=None):
        requested.append((url, user_agent))
        status, headers, body = site.get((user_agent, url)) or site.get((None, url)) or (404, {}, "not found")
        data = body.encode() if isinstance(body, str) else body
        return {"url": url, "status": status, "headers": headers, "sha256": hashlib.sha256(data).hexdigest(),
                "content_base64": base64.b64encode(data).decode()}

    def answer(call):
        if call["kind"] != "probe":
            return handler(call) if handler else ({}, {})
        assert call["files"]["recipe.py"] == served.PROBE.read_bytes()
        return served_probe.collect(fetch, json.loads(call["files"]["target.json"]))

    broker = FixtureBroker(handler=answer)
    broker.requested = requested
    return broker


def asset(client, **overrides):
    response = client.post("/api/applications", json={**BODY, **overrides})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def pages(client, ident):
    return client.get(f"/api/applications/{ident}/watched-pages").json()["items"]


def check(system, broker, ident):
    """Check now for the Asset, run to its end: the served_check job."""
    app, client, config = system
    response = client.post(f"/api/applications/{ident}/served-content-checks")
    assert response.status_code == 202, response.text
    while run_once(config, app.state.factory, broker):
        pass
    return client.get(f"/api/jobs/{response.json()['job_id']}").json()


def accept(client, ident, page_id, fetch_id):
    response = client.post(f"/api/applications/{ident}/watched-pages/{page_id}/baselines", json={"fetch_id": fetch_id})
    assert response.status_code == 200, response.text
    return response.json()


def baselined(system, site):
    """An Asset whose homepage was checked once on `site`, with both fetches accepted as its Baseline."""
    _, client, _ = system
    ident, broker = asset(client), served_broker(site)
    check(system, broker, ident)
    (home,) = pages(client, ident)
    for agent in home["user_agents"]:
        accept(client, ident, home["id"], agent["latest"]["id"])
    return ident, broker


def changes(app):
    with app.state.factory() as db:
        return list(db.scalars(select(ServedChange).order_by(ServedChange.created_at)))


def test_the_homepage_is_always_watched_and_cannot_be_removed(system):
    app, client, _ = system
    ident = asset(client)
    (home,) = pages(client, ident)
    assert (home["url"], home["homepage"], home["removed_at"]) == (SHOP, True, None)
    assert [(a["user_agent"], a["state"], a["latest"], a["baseline"], a["accept_allowed"]) for a in home["user_agents"]] == [
        ("browser", "awaiting_baseline", None, None, False), ("googlebot", "awaiting_baseline", None, None, False)]
    refused = client.delete(f"/api/applications/{ident}/watched-pages/{home['id']}")
    assert refused.status_code == 409 and refused.json()["code"] == "homepage_required"

    # A Baseline belongs to its URL: a new Asset URL moves the homepage to a page with none, and only
    # the new URL is checked.
    broker = served_broker(shop_site(rendered(1)))
    check(system, broker, ident)
    accept(client, ident, home["id"], pages(client, ident)[0]["user_agents"][0]["latest"]["id"])
    moved = client.patch(f"/api/applications/{ident}", json={"asset_url": SHOP + "/id"})
    assert moved.status_code == 200, moved.text
    (home,) = pages(client, ident)
    assert (home["url"], home["homepage"]) == (SHOP + "/id", True)
    assert [(a["state"], a["baseline"]) for a in home["user_agents"]] == [("awaiting_baseline", None)] * 2
    broker.requested.clear()
    job = check(system, broker, ident)
    assert {url for url, _ in broker.requested} == {SHOP + "/id"}
    assert job["result"] == {"pages": 1, "fetches": 2, "changed": 0, "matches": 0, "awaiting_baseline": 0, "failed": 2}
    (home,) = pages(client, ident)
    assert [(a["state"], a["latest"]["error"], a["accept_allowed"]) for a in home["user_agents"]] == [
        ("failed", {"status": 404, "error": None}, False)] * 2


def test_watched_pages_must_share_the_asset_origin(system):
    _, client, _ = system
    ident = asset(client)
    url = f"/api/applications/{ident}/watched-pages"
    for other in ("https://other.test/produk", "http://shop.test/produk", "https://shop.test:8443/produk"):
        refused = client.post(url, json={"url": other})
        assert refused.status_code == 422 and "url" in refused.json()["fields"], other
    added = client.post(url, json={"url": SHOP + "/produk"})
    assert added.status_code == 201, added.text
    assert (added.json()["url"], added.json()["homepage"]) == (SHOP + "/produk", False)
    for again in (SHOP + "/produk", SHOP + "/"):  # the homepage is one already
        refused = client.post(url, json={"url": again})
        assert refused.status_code == 409 and refused.json()["code"] == "page_watched", again

    removed = client.delete(f"{url}/{added.json()['id']}")
    assert removed.status_code == 200 and removed.json()["removed_at"]
    assert [p["url"] for p in pages(client, ident)] == [SHOP]
    assert client.delete(f"{url}/{added.json()['id']}").status_code == 404
    restored = client.post(url, json={"url": SHOP + "/produk"})
    assert restored.status_code == 201 and restored.json()["id"] == added.json()["id"]

    for n in range(18):
        assert client.post(url, json={"url": f"{SHOP}/p{n}"}).status_code == 201
    refused = client.post(url, json={"url": SHOP + "/p18"})
    assert refused.status_code == 422 and refused.json()["code"] == "too_many_watched_pages"
    assert len(pages(client, ident)) == domain.MAX_WATCHED_PAGES == 20


def test_a_new_asset_origin_stops_watching_the_old_origins_pages(system):
    _, client, _ = system
    ident = asset(client)
    url = f"/api/applications/{ident}/watched-pages"
    for path in ("/produk", "/kontak"):
        assert client.post(url, json={"url": SHOP + path}).status_code == 201
    assert client.patch(f"/api/applications/{ident}", json={"asset_url": SHOP + "/id"}).status_code == 200
    assert [p["url"] for p in pages(client, ident)] == [SHOP + "/id", SHOP + "/produk", SHOP + "/kontak"]
    moved = client.patch(f"/api/applications/{ident}", json={"asset_url": "https://toko.test"})
    assert moved.status_code == 200, moved.text
    assert [p["url"] for p in pages(client, ident)] == ["https://toko.test"]


def served_jobs(app):
    with app.state.factory() as db:
        return list(db.scalars(select(Job).where(Job.kind == "served_check").order_by(Job.created_at)))


def test_served_content_checks_run_on_the_interval_and_on_check_now(system, monkeypatch):
    app, client, _ = system
    monitored = asset(client)
    asset(client, monitor_enabled=False)
    asset(client, archived=True)
    assert served_jobs(app) == []  # creating an Application queues none
    with app.state.factory.begin() as db:
        domain.schedule(db)  # the repository poll queues none either
    assert served_jobs(app) == []

    window = int(now().timestamp()) // 172800
    for _ in range(2):
        with app.state.factory.begin() as db:
            domain.schedule_served_checks(db)
    assert [(job.application_id, job.idempotency_key) for job in served_jobs(app)] == [
        (monitored, f"served:{monitored}:{window}")]

    # Check now reuses the check that is active, else queues one.
    url = f"/api/applications/{monitored}/served-content-checks"
    reused = client.post(url, headers={"Idempotency-Key": "check-1"})
    assert reused.status_code == 202 and reused.json()["job_id"] == served_jobs(app)[0].id
    with app.state.factory.begin() as db:
        db.execute(update(Job).values(status="succeeded"))
    queued = client.post(url, headers={"Idempotency-Key": "check-2"})
    assert queued.status_code == 202 and queued.json()["job_id"] != reused.json()["job_id"]
    assert client.post(url).json()["job_id"] == queued.json()["job_id"]
    with app.state.factory.begin() as db:
        db.execute(update(Job).values(status="succeeded"))

    later = now() + timedelta(seconds=172800)
    monkeypatch.setattr(domain, "now", lambda: later)
    with app.state.factory.begin() as db:
        domain.schedule_served_checks(db)
    assert [job.idempotency_key for job in served_jobs(app)] == [
        f"served:{monitored}:{window}", "check-2", f"served:{monitored}:{window + 1}"]


def test_each_page_is_fetched_as_browser_and_googlebot_through_the_gateway(system):
    app, client, _ = system
    ident = asset(client)
    assert client.post(f"/api/applications/{ident}/watched-pages", json={"url": SHOP + "/produk"}).status_code == 201
    site = {**shop_site(rendered(1)), (None, SHOP + "/produk"): page(rendered(2))}
    broker = served_broker(site)
    job = check(system, broker, ident)
    assert (job["status"], job["subject"]["type"], job["subject"]["label"]) == ("succeeded", "served", SHOP)
    assert job["result"] == {"pages": 2, "fetches": 4, "changed": 0, "matches": 0, "awaiting_baseline": 4, "failed": 0}
    assert [call["kind"] for call in broker.calls] == ["probe", "probe"]
    targets = [json.loads(call["files"]["target.json"]) for call in broker.calls]
    assert [target["url"] for target in targets] == [SHOP, SHOP + "/produk"]
    for call, target in zip(broker.calls, targets):
        assert call["profile"] is None and set(call["files"]) == {"recipe.py", "target.json"}
        assert call["policy"] == SERVED_POLICY and call["policy"]["served_content"] is True
        assert "origins" not in call["policy"] and call["policy"]["methods"] == ["GET"]
        assert (target["user_agents"], target["max_scripts"]) == (["browser", "googlebot"], 20)
    # Every request names one user agent of the fixed pair: each page and its scripts, as each.
    assert {ua for _, ua in broker.requested} == {"browser", "googlebot"}
    for url in (SHOP, SHOP + "/produk", SHOP + "/static/app.3f9a1c2b.js", "https://cdn.shop.test/vendor.js"):
        assert [ua for requested, ua in broker.requested if requested == url] == ["browser", "googlebot"] * (
            2 if "static" in url or "cdn" in url else 1), url
    for watched in pages(client, ident):
        for agent in watched["user_agents"]:
            latest = agent["latest"]
            assert (latest["status"], len(latest["fingerprint"]), latest["error"]) == ("fetched", 64, None)
            assert [(r["kind"], r["url"], r["status"]) for r in latest["resources"]] == [
                ("page", watched["url"], 200), ("script", SHOP + "/static/app.3f9a1c2b.js", 200),
                ("script", "https://cdn.shop.test/vendor.js", 200)]


def test_fetched_bytes_are_stored_once_by_content_hash(system):
    app, client, config = system
    ident = asset(client)
    broker = served_broker(shop_site(rendered(1)))
    check(system, broker, ident)
    served_bytes = [rendered(1).encode(), *(body.encode() for body in list(scripts().values())[:2])]

    def stored():
        with app.state.factory() as db:
            return list(db.scalars(select(Artifact).where(Artifact.resource_type == "served_content")))

    rows = [row for row in stored() if row.path == "content"]
    assert sorted(row.resource_id for row in rows) == sorted(hashlib.sha256(data).hexdigest() for data in served_bytes)
    assert all(row.sha256 == row.resource_id for row in rows)
    with app.state.factory() as db:
        fetch = db.scalar(select(ServedFetch).where(ServedFetch.user_agent == "googlebot"))
        assert Workflows(config, None, None, None).served_files(db, fetch, "changed/") == {
            "changed/page.html": served_bytes[0], "changed/scripts/00.js": served_bytes[1],
            "changed/scripts/01.js": served_bytes[2]}
    # An unchanged page's bytes are stored once, whatever the number of checks and user agents.
    count = len(stored())
    check(system, broker, ident)
    assert len(stored()) == count
    with app.state.factory() as db:
        assert db.scalar(select(func.count()).select_from(ServedFetch)) == 4


def test_the_first_fingerprint_becomes_the_baseline_only_when_accepted(system):
    app, client, _ = system
    ident = asset(client)
    missing = client.post(f"/api/applications/{ident}/watched-pages", json={"url": SHOP + "/hilang"}).json()
    site = shop_site(rendered(1))
    broker = served_broker(site)
    check(system, broker, ident)
    home = pages(client, ident)[0]
    first = home["user_agents"][1]["latest"]
    assert [(a["state"], a["accept_allowed"]) for a in home["user_agents"]] == [("awaiting_baseline", True)] * 2
    # Until the Operator accepts one, no fingerprint is a change.
    site.update(shop_site(rendered(2, extra_body=JUDOL)))
    check(system, broker, ident)
    assert changes(app) == []
    judol = pages(client, ident)[0]["user_agents"][1]["latest"]
    assert judol["fingerprint"] != first["fingerprint"]

    url = f"/api/applications/{ident}/watched-pages/{home['id']}/baselines"
    refused = client.post(url, json={"fetch_id": first["id"]}, headers={"X-CSRF-Token": "not-the-session-token"})
    assert refused.status_code == 403 and refused.json()["code"] == "csrf_required"
    failed = pages(client, ident)[1]["user_agents"][1]["latest"]
    for page_id, fetch_id in ((missing["id"], failed["id"]), (missing["id"], first["id"])):
        refused = client.post(f"/api/applications/{ident}/watched-pages/{page_id}/baselines", json={"fetch_id": fetch_id})
        assert refused.status_code == 422 and refused.json()["code"] == "invalid_baseline"
    # Accepting is not an Approval: the body carries no password.
    googlebot = accept(client, ident, home["id"], first["id"])["user_agents"][1]
    assert googlebot["baseline"]["fetch_id"] == first["id"] and googlebot["baseline"]["fingerprint"] == first["fingerprint"]
    assert (googlebot["state"], googlebot["accept_allowed"], googlebot["change"]) == ("changed", False, None)
    with app.state.factory() as db:
        (action,) = db.scalars(select(Action).where(Action.resource_type == "watched_page", Action.resource_id == home["id"]))
        assert action.data == {"action": "baseline_accepted", "user_agent": "googlebot", "fetch_id": first["id"],
                               "fingerprint": first["fingerprint"], "previous": None}
    accept(client, ident, home["id"], first["id"])  # its own fingerprint again: nothing changes
    refused = client.post(url, json={"fetch_id": judol["id"]})
    assert refused.status_code == 409 and refused.json()["code"] == "baseline_not_allowed"
    with app.state.factory() as db:
        assert db.scalar(select(func.count()).select_from(Action).where(Action.resource_id == home["id"])) == 1

    # From the Baseline on, the judol fingerprint is a change; the browser, with none, still waits.
    check(system, broker, ident)
    (change,) = changes(app)
    assert (change.user_agent, change.fingerprint, change.baseline_fetch_id) == ("googlebot", judol["fingerprint"], first["id"])
    assert [a["state"] for a in pages(client, ident)[0]["user_agents"]] == ["awaiting_baseline", "changed"]


def test_googlebot_only_gambling_links_change_the_googlebot_fingerprint_only(system):
    """AC-A10: a page that serves gambling links only to the Googlebot fetch produces a changed
    fingerprint, with the difference attributed to that user agent."""
    app, client, _ = system
    site = shop_site(rendered(1))
    ident, broker = baselined(system, site)
    site.update(shop_site(rendered(2), rendered(3, extra_body=JUDOL)))
    job = check(system, broker, ident)
    assert job["result"] == {"pages": 1, "fetches": 2, "changed": 1, "matches": 1, "awaiting_baseline": 0, "failed": 0}
    browser, googlebot = pages(client, ident)[0]["user_agents"]
    assert (browser["state"], browser["diff"], browser["change"]) == ("matches", {}, None)
    assert googlebot["state"] == "changed"
    assert googlebot["diff"]["link_hosts"] == {"added": ["slot-gacor.test"], "removed": []}
    assert googlebot["diff"]["links"]["added"] == ["https://slot-gacor.test/daftar", "https://slot-gacor.test/maxwin"]
    change = googlebot["change"]
    assert (change["fetch_id"], change["previous_fetch_id"], change["baseline_fetch_id"]) == (
        googlebot["latest"]["id"], googlebot["baseline"]["fetch_id"], googlebot["baseline"]["fetch_id"])
    assert (change["diff"], change["triage_status"], change["verdict"], change["review_decision"]) == (
        googlebot["diff"], "disabled", None, "pending")
    # The same fingerprint again, its tokens rotated, is the same change: recorded once.
    site.update(shop_site(rendered(4), rendered(5, extra_body=JUDOL)))
    check(system, broker, ident)
    (recorded,) = changes(app)
    assert (recorded.id, recorded.user_agent, recorded.fetch_id) == (change["id"], "googlebot", change["fetch_id"])


def test_an_added_external_script_host_is_a_changed_fingerprint(system):
    """AC-A10: an added external script host produces a changed fingerprint."""
    app, client, _ = system
    site = shop_site(rendered(1))
    ident, broker = baselined(system, site)
    site.update(shop_site(rendered(2, extra_head=CLICKFIX_HEAD, extra_body=CLICKFIX_BODY)))
    assert check(system, broker, ident)["result"]["changed"] == 2
    for agent in pages(client, ident)[0]["user_agents"]:
        assert agent["state"] == "changed"
        assert agent["diff"]["script_hosts"] == {"added": ["cdn.clickfix-fixture.test"], "removed": []}
        assert agent["change"]["diff"] == agent["diff"]
    assert sorted(change.user_agent for change in changes(app)) == ["browser", "googlebot"]


def test_rotating_tokens_and_bundler_hashes_keep_matching_the_baseline(system):
    """AC-A10: rotating nonces, CSRF tokens and bundler hash tokens do not change the fingerprint."""
    app, client, _ = system
    site = shop_site(rendered(1))
    ident, broker = baselined(system, site)
    for n in range(2, 5):
        site.update(shop_site(rendered(n, build="9e8d7c6b"), rendered(n + 10, build="9e8d7c6b"), build="9e8d7c6b"))
        assert check(system, broker, ident)["result"]["matches"] == 2
    assert [a["state"] for a in pages(client, ident)[0]["user_agents"]] == ["matches", "matches"]
    assert changes(app) == []


def test_a_check_runs_no_javascript(system):
    """AC-A10: no JavaScript from a fetched page is ever executed. The page's scripts would
    request /served/executed if run; the check makes probe calls only, and only the page and its
    script src are ever requested."""
    _, client, _ = system
    ident = asset(client)
    beacon = """<html><head><script src="/static/beacon.js"></script>
<script>new Image().src = "/served/executed?inline=1"; fetch("https://shop.test/served/executed")</script>
</head><body><a href="/served/executed?link=1">a link is never followed</a><img src="/served/executed?img=1"></body></html>"""
    broker = served_broker({(None, SHOP): page(beacon), (None, SHOP + "/static/beacon.js"): page(
        'fetch("/served/executed?script=1"); import("https://shop.test/served/executed")', "text/javascript")})
    assert check(system, broker, ident)["status"] == "succeeded"
    assert [call["kind"] for call in broker.calls] == ["probe"]
    assert broker.requested == [(SHOP, "browser"), (SHOP + "/static/beacon.js", "browser"),
                                (SHOP, "googlebot"), (SHOP + "/static/beacon.js", "googlebot")]
    assert not any("/served/executed" in url for url, _ in broker.requested)


def test_a_page_with_more_than_20_scripts_is_checked(system):
    """The probe fetches 20 of a page's scripts and lists the others past the limit, so their hosts still count."""
    _, client, _ = system
    ident = asset(client)
    srcs = [f"https://cdn{n}.test/x.js" for n in range(24)]
    broker = served_broker({(None, SHOP): page("".join(f'<script src="{src}"></script>' for src in srcs)),
                            **{(None, src): page(f"/* {src} */", "text/javascript") for src in srcs}})
    assert check(system, broker, ident)["status"] == "succeeded"
    for agent in pages(client, ident)[0]["user_agents"]:
        assert agent["latest"]["status"] == "fetched"
        assert [r["status"] for r in agent["latest"]["resources"][1:]] == [200] * 20 + ["skipped"] * 4


def test_a_probe_result_unlike_the_fixed_probes_fails_the_check(system):
    app, client, _ = system
    ident = asset(client)
    for tamper in (lambda result, files: ({"fetches": {"browser": result["fetches"]["browser"]}}, files),
                   lambda result, files: (result, {name[::-1]: data for name, data in files.items()})):
        broker = served_broker(shop_site(rendered(1)))
        honest = broker.handler
        broker.handler = lambda call, honest=honest, tamper=tamper: tamper(*honest(call))
        job = check(system, broker, ident)
        assert (job["status"], job["error"]["code"]) == ("failed", "invalid_probe_result")
    with app.state.factory() as db:
        assert db.scalar(select(func.count()).select_from(ServedFetch)) == 0
        assert db.scalar(select(func.count()).select_from(Artifact).where(Artifact.resource_type == "served_content")) == 0
