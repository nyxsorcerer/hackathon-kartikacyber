"""Transcripts (A14): each Triage run is kept in the database and each Analysis run's Herdr session
(a rendering of its native JSONL records, then the terminal view) in artifact storage, linked to
its Verdict, with every configured secret removed. A Finding lists the Transcripts of what it is
about.

Every agent reply and session comes from FixtureBroker; no test reaches a real host."""

import base64
import json
from datetime import timedelta
from pathlib import Path

from sqlalchemy import select

from conftest import FixtureBroker, application, github_account
from numen import artifacts, scheduler
from numen.models import Account, Action, ApplicationCVE, Artifact, Finding, Job, JobEvent, Transcript, now, uid
from numen.worker import run_once
from test_artifacts import bundle, queue_cve_analysis
from test_commit_review import assessment, pinned_bundle, prepared
from test_triage import CANDIDATE, reply, triage

API_KEY = "fixture-key-no-real-access"  # connection()'s Analysis key
READ_TOKEN = "fixture-github-token"  # github_account()'s
WRITE_TOKEN = "github_pat_fixture_write_token_0001"
NVD_KEY = "fixture-nvd-key-0123456789"
WEBHOOK = "http://fixture.local/api/webhooks/1/transcript-webhook-secret"
PASSWORD = "test-password-long"  # the Operator's: stored only as a hash, so no agent ever has it
SKIPPED = ("notification", "detection_rule", "patch_drafting", "remediation_draft", "finding_artifacts")
SCREEN = ("=== session-transcripts/pi/run.jsonl ===\n[user]\nAnalyse the change\n\n[assistant]\n"
          "<script>alert(1)</script>\n\n=== Latest terminal view ===\npi> done")


def analysed(system, screen, reason=CANDIDATE["reason"]):
    """A flagged commit of an Upstream repository: its Triage, whose reply gives `reason`, then its
    automatic Analysis, which finds a Vulnerability fix and opens a Finding. The broker answers
    with the Analysis session `screen`. (the commit id, the Analysis job id)"""
    app, client, config = system
    monitored, ident, _ = prepared(system)
    job_id = triage(app, ident, monitored["id"])

    def answer(call):
        if call["profile"]["operation"] == "commit_triage":
            return reply({**CANDIDATE, "reason": reason}), {}
        return assessment("Vulnerability fix"), pinned_bundle()

    broker = FixtureBroker(handler=answer, screen=screen)
    while run_once(config, app.state.factory, broker, exclude=SKIPPED):
        pass
    assert client.get(f"/api/jobs/{job_id}").json()["status"] == "succeeded"
    with app.state.factory() as db:
        (analysis_job,) = db.scalars(select(Job).where(Job.kind == "commit_analysis"))
        return ident, analysis_job.id


def configure_secrets(system):
    """Every kind of configured secret: the GitHub read and write tokens, the NVD key, the Discord
    webhook, and with prepared()'s Analysis API key and the vault key, all their values."""
    app, client, config = system
    github_account(app)
    with app.state.factory.begin() as db:
        for provider, key in (("github_write", WRITE_TOKEN), ("nvd", NVD_KEY)):
            db.add(Account(label=provider, provider=provider, auth_type="api_key",
                           credential=app.state.vault.encrypt({"api_key": key}),
                           data={"status": "unchecked", "models": [], "usage": None}))
    response = client.patch("/api/settings", json={"webhook_enabled": False, "webhook_url": WEBHOOK})
    assert response.status_code == 200, response.text
    return [API_KEY, READ_TOKEN, WRITE_TOKEN, NVD_KEY, WEBHOOK, config.secret_key]


def test_no_stored_transcript_contains_a_configured_secret(system, github):
    """AC-A14: no stored Transcript, Triage or Analysis, contains a configured secret value."""
    app, _, config = system
    secrets = configure_secrets(system)
    leaked = " ".join(secrets)
    encoded = base64.b64encode(WRITE_TOKEN.encode()).decode()
    # The Triage reply holds every secret; the session holds each and one as standard base64 too.
    ident, _ = analysed(system, f"{SCREEN}\n{leaked}\nAuthorization: Basic {encoded}", "Compared with " + leaked)
    with app.state.factory() as db:
        rows = list(db.scalars(select(Transcript).where(Transcript.subject_id == ident).order_by(Transcript.created_at)))
        files = {a.path: Path(config.artifact_root, a.storage_path).read_text()
                 for a in db.scalars(select(Artifact).where(Artifact.resource_type == "transcript"))}
    assert [row.kind for row in rows] == ["triage", "analysis"]
    assert set(files) == {"transcript.txt", "manifest.json"}
    for text in [*(json.dumps(row.data) for row in rows), *files.values()]:
        for secret in [*secrets, encoded, PASSWORD]:
            assert secret not in text
    assert rows[0].data["reply"].count("[redacted]") == len(secrets)
    assert files["transcript.txt"].count("[redacted]") == len(secrets) + 1
    # Retention weighs each one by its stored size.
    assert [row.size for row in rows] == [len(json.dumps(rows[0].data).encode()), len(files["transcript.txt"].encode())]


def test_a_findings_transcripts_are_listed_with_it_and_the_analysis_one_names_its_verdict(system, github):
    """A14: an Analysis Transcript is linked to its Verdict, and a Finding lists its Transcripts.
    An Upstream commit's Analysis Transcript holds its Proof, so it is never downloaded (A15)."""
    app, client, _ = system
    ident, analysis_job = analysed(system, SCREEN)
    (summary,) = client.get("/api/findings").json()["items"]
    finding = client.get(f"/api/findings/{summary['id']}").json()
    triaged, analysis = finding["transcripts"]
    assert (triaged["kind"], analysis["kind"]) == ("triage", "analysis")
    assert triaged["subject_id"] == analysis["subject_id"] == ident
    assert (analysis["job_id"], analysis["status"]) == (analysis_job, "completed")
    assert analysis["analysis_id"] == finding["cause"]["analysis_id"] and triaged["analysis_id"] is None
    shown = client.get(f"/api/transcripts/{analysis['id']}").json()
    assert shown["text"] == SCREEN and shown["analysis_id"] == analysis["analysis_id"]
    data = json.loads(client.get(f"/api/transcripts/{triaged['id']}").json()["text"])
    assert data["status"] == "completed" and CANDIDATE["reason"] in data["reply"]
    assert "Facts:" in data["prompt"]
    assert client.get("/api/transcripts/missing").status_code == 404
    with app.state.factory() as db:
        stored = db.scalar(select(Artifact.id).where(Artifact.resource_id == analysis["id"], Artifact.path == "transcript.txt"))
    refused = client.get(f"/api/artifacts/{stored}/content")
    assert (refused.status_code, refused.json()["code"]) == (403, "upstream_proof_not_exported")


def test_each_applications_cve_finding_lists_only_its_own_analysis_transcript(system):
    """A14: a CVE is analysed per Application, so one Application's cve Finding never lists the
    Transcript of another's Analysis of the same CVE."""
    app, client, config = system
    first, queued, result = queue_cve_analysis(system)
    second = application(client, config={
        "cve_selectors": [{"type": "cpe", "value": "cpe:2.3:a:demo:plugin:*:*:*:*:*:*:*:*"}],
        "cve_min_score": 7, "cve_versions": ["3.1"]})
    with app.state.factory.begin() as db:
        db.add(ApplicationCVE(application_id=second["id"], cve_id=result["cve_id"], confirmed=None, data={}))
    again = client.post(f"/api/applications/{second['id']}/cves/{result['cve_id']}/analyses", json={}).json()
    while run_once(config, app.state.factory, FixtureBroker(result, bundle()), exclude=SKIPPED):
        pass
    for ident, job_id in ((first["id"], queued), (second["id"], again["job_id"])):
        job = client.get(f"/api/jobs/{job_id}").json()
        finding = client.get(f"/api/findings/{job['result']['finding_id']}").json()
        assert finding["application_id"] == ident
        assert [t["analysis_id"] for t in finding["transcripts"]] == [job["result"]["analysis_id"]]


def test_an_analysis_without_a_session_still_records_its_verdict(system, github):
    """A14: a run whose session cannot be read keeps its Verdict; only its Transcript is missing."""
    app, client, _ = system
    ident, analysis_job = analysed(system, None)
    commit = client.get(f"/api/commits/{ident}").json()
    assert commit["verdict"] == "Vulnerability fix" and commit["analysis_state"]["status"] == "completed"
    with app.state.factory() as db:
        kinds = [e.data["kind"] for e in db.scalars(select(JobEvent).where(JobEvent.job_id == analysis_job))]
        assert [t.kind for t in db.scalars(select(Transcript).where(Transcript.subject_id == ident))] == ["triage"]
    assert "transcript_unavailable" in kinds


MIB = 1024 * 1024


def retained(system, transcripts):
    """An Application whose commit Finding is about commit "source" and linked to commit "linked",
    and one Transcript of its job per (kind, subject, size, days old). An Analysis one's session
    is stored in artifact storage. Their ids, in order."""
    app, client, config = system
    ident = application(client)["id"]
    with app.state.factory.begin() as db:
        job = Job(kind="commit_analysis", status="succeeded", input_hash="h", application_id=ident)
        finding = Finding(application_id=ident, source="commit", title="Kept", data={"source_commit_id": "source"})
        db.add_all([job, finding])
        db.flush()
        db.add(Action(resource_type="finding", resource_id=finding.id, data={"action": "linked", "commit_id": "linked"}))
        rows = []
        for kind, subject, size, days in transcripts:
            row = Transcript(id=uid(), kind=kind, job_id=job.id, subject_id=subject, size=size,
                             data={"status": "completed"}, created_at=now() - timedelta(days=days))
            if kind == "analysis":
                text = f"Session of {subject}".encode()
                revision, _ = artifacts.publish(db, config.artifact_root, "transcript", row.id, {"transcript.txt": text})
                row.data, row.size = {**row.data, "revision": revision}, len(text)
            rows.append(row)
        db.add_all(rows)
    return [row.id for row in rows]


def test_retention_prunes_triage_transcripts_after_30_days_or_past_256_mb_oldest_first(system):
    """A14: a Triage Transcript goes after 30 days, and once they pass 256 MB together the oldest
    go first, one of what a Finding is about too."""
    app, _, config = system
    *_, second, third = retained(system, [
        ("triage", "old", 10, 31), ("triage", "source", 10, 40),
        ("triage", "linked", 100 * MIB, 3), ("triage", "c2", 100 * MIB, 2), ("triage", "c3", 100 * MIB, 1)])
    scheduler.prune(config, app.state.factory)
    with app.state.factory() as db:
        assert set(db.scalars(select(Transcript.id))) == {second, third}


def test_retention_deletes_unlinked_analysis_transcripts_after_30_days_and_keeps_a_findings(system):
    """A14: an Analysis Transcript is kept while a Finding is about its change, as its source or
    a linked change, and otherwise 30 days. Its row, Artifact rows and folder go together."""
    app, client, config = system
    old, *kept = retained(system, [
        ("analysis", "old", 0, 31), ("analysis", "source", 0, 31), ("analysis", "linked", 0, 31), ("analysis", "young", 0, 29)])
    with app.state.factory() as db:
        (revision,) = set(db.scalars(select(Artifact.revision).where(Artifact.resource_id == old)))
    assert (config.artifact_root / revision).is_dir()
    scheduler.prune(config, app.state.factory)
    with app.state.factory() as db:
        assert set(db.scalars(select(Transcript.id))) == set(kept)
        assert not db.scalars(select(Artifact).where(Artifact.resource_id == old)).all()
    assert not (config.artifact_root / revision).exists()
    for ident, subject in zip(kept, ["source", "linked", "young"]):
        assert client.get(f"/api/transcripts/{ident}").json()["text"] == f"Session of {subject}"
