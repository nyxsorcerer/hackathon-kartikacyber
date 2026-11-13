"""Alerts (A12): one fixed template of application-generated fields, sent when a Finding opens and
when a cap is reached, and at no other time; delivery failures behave as in Numen's AC-16."""

import json
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select

from conftest import FixtureBroker, application, source_snapshot
from numen import cves, domain
from numen.models import CVE, Action, Application, ApplicationCVE, Commit, Job, Notification, now
from numen.worker import run_once
from test_analysis import CAPS, analyze, flag, started, triaged
from test_artifacts import bundle, queue_cve_analysis
from test_commit_review import assessment, prepared
from test_findings import analyzed, by_application, parented, shared
from test_workflows import cve_raw, seed_cve

MENTION = "@everyone see https://evil.example/x"


def webhook(client):
    settings = {"webhook_enabled": True, "webhook_url": "http://fixture.local/api/webhooks/1/secret",
                "dashboard_url": "http://localhost:8080"}
    assert client.patch("/api/settings", json=settings).status_code == 200


def alerts(app):
    """Every Alert queued so far, by event key, with the fields it stores."""
    with app.state.factory() as db:
        return {n.event_key: n.data for n in db.scalars(select(Notification))}


def deliver(system, monkeypatch, status=200):
    """Runs the queued notification jobs, Discord answering `status`; the payloads it was sent."""
    app, _, config = system
    sent = []

    def post(url, **kwargs):
        sent.append(kwargs["json"])
        return httpx.Response(status, json={"id": "discord-fixture-id"})

    monkeypatch.setattr(httpx, "post", post)
    with app.state.factory() as db:
        others = tuple(set(db.scalars(select(Job.kind).where(Job.kind != "notification"))))
    while run_once(config, app.state.factory, FixtureBroker(), exclude=others):
        pass
    return sent


def test_an_alert_carries_only_application_generated_fields(system, monkeypatch):
    app, client, _ = system
    webhook(client)
    _, ident, _ = prepared(system)
    with app.state.factory.begin() as db:
        commit = db.get(Commit, ident)
        commit.data = {**commit.data, "message": MENTION, "author": "@here Mallory"}
    title, summary = "@everyone template inclusion https://evil.example/x", "Read " + MENTION
    job = analyzed(system, ident, "Vulnerability introduced", title=title, summary=summary)
    finding_id = job["result"]["finding_id"]
    (queued,) = [j for j in client.get("/api/jobs").json()["items"] if j["kind"] == "notification"]
    assert queued["subject"]["label"] == "Vulnerability introduced · high confidence"
    (payload,) = deliver(system, monkeypatch)
    assert payload == {
        "content": "Asset Monitor: Vulnerability introduced · high confidence\nApplication: Site\n"
                   f"Source: aaaaaaa\nhttp://localhost:8080/findings/{finding_id}",
        "allowed_mentions": {"parse": []},
    }
    text = json.dumps(payload, ensure_ascii=False)
    for forbidden in ("@everyone", "@here", "Mallory", "evil.example", title, summary):
        assert forbidden not in text


def test_each_opened_finding_sends_one_alert_per_application(system):
    app, client, _ = system
    (shop, blog), x = shared(system, "Shop", "Blog")
    analyzed(system, x, "Vulnerability introduced")
    found = by_application(client)
    expected = {
        f"finding:{found[a['id']]['id']}:opened": {
            "application": a["asset_name"], "account": None, "source": "aaaaaaa",
            "verdict": "Vulnerability introduced · high confidence", "link": f"/findings/{found[a['id']]['id']}",
        }
        for a in (shop, blog)
    }
    assert alerts(app) == expected
    analyzed(system, x, "Vulnerability introduced")  # A repeat Analysis opens nothing.
    y = parented(app, shop["id"], "b" * 40, "a" * 40)
    analyzed(system, y, "Vulnerability fix", "a" * 40, addresses=["a" * 7])  # Linked in both.
    assert alerts(app) == expected
    # Served-content and advisory Findings alert through the same opening function.
    with app.state.factory.begin() as db:
        shop_row = db.get(Application, shop["id"])
        page, _ = domain.open_finding(db, shop_row, "served_content", "change-1", "Injected loader", "https://shop.example/",
                                      {"by": "verdict", "verdict": "Malicious change", "confidence": "medium"})
        advisory, _ = domain.open_finding(db, shop_row, "advisory", "GHSA-fv66-9v8q-g76r", "Template inclusion",
                                          "GHSA-fv66-9v8q-g76r", {"by": "advisory", "advisory_id": "GHSA-fv66-9v8q-g76r"})
        domain.open_finding(db, shop_row, "advisory", "GHSA-fv66-9v8q-g76r", "Again", "GHSA-fv66-9v8q-g76r",
                            {"by": "advisory", "advisory_id": "GHSA-fv66-9v8q-g76r"})
        page_id, advisory_id = page.id, advisory.id
    assert alerts(app) == {
        **expected,
        f"finding:{page_id}:opened": {"application": "Shop", "account": None, "source": "https://shop.example/",
                                      "verdict": "Malicious change · medium confidence", "link": f"/findings/{page_id}"},
        f"finding:{advisory_id}:opened": {"application": "Shop", "account": None, "source": "GHSA-fv66-9v8q-g76r",
                                          "verdict": "Advisory", "link": f"/findings/{advisory_id}"},
    }


def test_a_cve_analysis_that_opens_a_finding_alerts_as_advisory(system):
    app, client, config = system
    p, queued, result = queue_cve_analysis(system)
    run_once(config, app.state.factory, FixtureBroker(result, bundle()))
    client.post(f"/api/applications/{p['id']}/cves/{result['cve_id']}/analyses", json={})
    # The repeat reuses the Finding and sends nothing.
    run_once(config, app.state.factory, FixtureBroker(result, bundle()), exclude=("notification",))
    finding_id = client.get(f"/api/jobs/{queued}").json()["result"]["finding_id"]
    assert alerts(app) == {f"finding:{finding_id}:opened": {
        "application": "Site", "account": None, "source": "CVE-2026-12345", "verdict": "Advisory",
        "link": f"/findings/{finding_id}",
    }}


def test_a_reached_cap_sends_one_alert_per_cap_per_day(system, monkeypatch):
    app, client, _ = system
    monitored, _, profile = prepared(system)
    other = application(client, asset_name="Other", source_url="https://github.com/demo/other")
    started(app, monitored["id"], CAPS["application"])
    flag(app, monitored["id"], "b" * 40, "c" * 40)  # Both wait for the Application cap.
    with app.state.factory.begin() as db:
        domain.schedule(db)  # Waiting changes are checked again: still no second Alert.

    def expected(day):
        return {
            f"cap:application:{monitored['id']}:{day}": {
                "application": "Site", "account": None, "source": None, "verdict": "Cap reached",
                "link": f"/reviews?application={monitored['id']}",
            },
            f"cap:account:{profile['connection_id']}:{day}": {
                "application": None, "account": "Test access", "source": None, "verdict": "Cap reached",
                "link": "/settings?tab=accounts",
            },
        }

    today = now().date().isoformat()
    application_cap = {k: v for k, v in expected(today).items() if k.startswith("cap:application")}
    assert alerts(app) == application_cap
    started(app, monitored["id"], CAPS["account"] - CAPS["application"], shared=True)
    flag(app, other["id"], "d" * 40, "e" * 40)  # Other's own cap is untouched; the account's is full.
    assert alerts(app) == expected(today)
    # On the next UTC day each cap that is reached again sends again.
    tomorrow = now() + timedelta(days=1)
    monkeypatch.setattr(domain, "now", lambda: tomorrow)
    with app.state.factory.begin() as db:
        for job in db.scalars(select(Job)):
            job.created_at += timedelta(days=1)  # The same Analyses, run on the next day.
    flag(app, monitored["id"], "1" * 40)
    flag(app, other["id"], "2" * 40)
    assert alerts(app) == {**expected(today), **expected(tomorrow.date().isoformat())}


def test_nothing_else_sends_an_alert(system):
    app, client, _ = system
    monitored, ident, _ = prepared(system)
    for verdict in ("Security hardening", "Unrelated", "Insufficient context"):  # The last is a Review queue entry.
        job, _ = analyze(system, ident, assessment(verdict), {"report.md": b"# Assessment"})
        assert job["status"] == "succeeded", job
    triaged(system, source_snapshot(app, monitored["id"], "b" * 40), monitored["id"])  # A security_candidate
    marked = [source_snapshot(app, monitored["id"], r * 40) for r in "cde"]
    assert client.post(f"/api/commits/{marked[0]}/review", json={"decision": "candidate"}).status_code == 200
    assert client.post("/api/commits/review", json={"ids": marked[1:], "decision": "candidate"}).status_code == 200
    watched = application(client, asset_name="CVE watch", config={
        "cve_selectors": [{"type": "cpe", "value": "cpe:2.3:a:demo:plugin:*:*:*:*:*:*:*:*"}],
        "cve_min_score": 7, "cve_versions": ["3.1"],
    })
    seed_cve(app, watched["id"], cve_raw())
    with app.state.factory.begin() as db:
        row = db.get(Application, watched["id"])
        link = db.scalar(select(ApplicationCVE).where(ApplicationCVE.application_id == row.id))
        cve = db.get(CVE, link.cve_id)
        assert cves.gate(row, cve, link)["eligible"]
        domain.refresh_cve_policy(db, row, cve, link)
    assert alerts(app) == {}


def test_a_failed_alert_retries_with_its_identity_and_changes_no_finding(system, monkeypatch):
    app, client, _ = system
    webhook(client)
    _, ident, _ = prepared(system)
    job = analyzed(system, ident, "Vulnerability introduced")
    finding = client.get(f"/api/findings/{job['result']['finding_id']}").json()
    commit = client.get(f"/api/commits/{ident}").json()
    assert len(deliver(system, monkeypatch, 500)) == 1
    (note,) = client.get("/api/notifications").json()["items"]
    assert (note["status"], note["error"]["code"], note["attempts"]) == ("failed", "webhook_http_error", 1)
    assert note["next_attempt_at"]
    assert client.get(f"/api/findings/{finding['id']}").json() == finding
    assert client.get(f"/api/commits/{ident}").json() == commit
    assert client.get(f"/api/jobs/{job['id']}").json()["status"] == "succeeded"
    with app.state.factory.begin() as db:
        (retry,) = db.scalars(select(Job).where(Job.kind == "notification", Job.status == "queued"))
        retry.not_before = now() - timedelta(seconds=1)  # Its back-off has passed.
    assert len(deliver(system, monkeypatch)) == 1
    (delivered,) = client.get("/api/notifications").json()["items"]
    assert (delivered["id"], delivered["event_key"]) == (note["id"], note["event_key"])
    assert (delivered["status"], delivered["attempts"]) == ("delivered", 2)
    assert client.get(f"/api/findings/{finding['id']}").json() == finding


def test_a_legacy_numen_notification_is_sent_without_its_text(system, monkeypatch):
    app, client, _ = system
    webhook(client)
    with app.state.factory.begin() as db:
        row = Notification(event_key="commit:1:candidate", status="pending",
                           data={"title": "Security candidate: @everyone", "detail": "x", "link": "/commits/1"})
        db.add(row)
        db.flush()
        domain.enqueue(db, "notification", inputs={"notification_id": row.id})
    assert deliver(system, monkeypatch) == [
        {"content": "Asset Monitor: Alert\nhttp://localhost:8080/commits/1", "allowed_mentions": {"parse": []}}
    ]


@pytest.mark.parametrize("verdict", ["Malicious change", "Vulnerability introduced"])
def test_an_introducing_change_opens_its_own_finding_whatever_it_addresses(system, verdict):
    app, client, _ = system
    monitored, x, _ = prepared(system)
    x_finding = analyzed(system, x, "Vulnerability introduced")["result"]["finding_id"]
    y = parented(app, monitored["id"], "b" * 40, "a" * 40)
    # Its message says "follow-up to aaaaaaa", so the agent lists X: Y still gets its own Finding.
    job = analyzed(system, y, verdict, "b" * 40, addresses=["a" * 7])
    y_finding = job["result"]["finding_id"]
    assert y_finding not in (None, x_finding) and job["result"]["finding_ids"] == [y_finding]
    assert client.get(f"/api/findings/{y_finding}").json()["cause"]["verdict"] == verdict
    assert set(alerts(app)) == {f"finding:{x_finding}:opened", f"finding:{y_finding}:opened"}
    x_row = client.get(f"/api/findings/{x_finding}").json()
    assert [e["commit_id"] for e in x_row["events"] if e["action"] == "linked"] == [y] and x_row["status"] == "open"


def test_a_cap_alert_lost_to_a_concurrent_worker_keeps_the_transaction(system):
    app, _, _ = system
    key, where = "cap:account:connection-1:2026-11-13", {"account": "Test access", "link": "/settings?tab=accounts"}
    with app.state.factory.begin() as db:
        domain.notify(db, key, verdict="Cap reached", **where)
    with app.state.factory.begin() as db:
        db.add(Action(resource_type="account", resource_id="connection-1", data={"action": "kept"}))
        real, checks = db.scalar, []

        def scalar(query, *args, **kwargs):  # The other worker's Alert was not committed at the check.
            checks.append(query)
            return None if len(checks) == 1 else real(query, *args, **kwargs)

        db.scalar = scalar
        domain.notify(db, key, verdict="Cap reached", **where)
    with app.state.factory() as db:
        assert [n.event_key for n in db.scalars(select(Notification))] == [key]
        assert db.scalar(select(Action).where(Action.data["action"].as_string() == "kept"))
