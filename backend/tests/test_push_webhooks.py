"""Push webhooks (B02): the Operator sets one up on an Own GitHub repository, sees its path and
Push webhook secret once, regenerates the secret or turns the Push webhook off. The secret is
stored encrypted with NUMEN_INGRESS_KEY and redacted like every configured secret (A14). The
scheduler's nudge turns accepted Push deliveries into source checks by the B02 rule."""

import hashlib
import json
import os
import re
import secrets
import uuid
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from conftest import FixtureBroker, application, check_now, connection, github_account
from test_ingress import deliver
from test_workflows import source_record
from numen import domain, ingress
from numen.models import Action, Application, Commit, Job, PushDelivery, PushWebhook, Repository, VersionRecipe, now, utc
from numen.security import DomainError, Vault
from numen.sources import Sources
from numen.worker import run_once
from numen.workflows import all_secrets

BODY = {
    "asset_name": "Portal",
    "asset_url": "https://portal.example.com",
    "product_kind": "CMS",
    "product_name": "Portal",
    "monitor_interval_seconds": 172800,
}


def linked(client, **source):
    """An Application with one repository link; (application id, the link's push-webhook URL)."""
    ident = client.post("/api/applications", json=BODY).json()["id"]
    link = client.post(f"/api/applications/{ident}/repositories", json=source)
    assert link.status_code == 201, link.text
    return ident, f"/api/applications/{ident}/repositories/{link.json()['repository_id']}/push-webhook"


def own(client, name="acme/portal"):
    return linked(client, role="own", source_kind="github", source_url=f"https://github.com/{name}")


def stored(app):
    with app.state.factory() as db:
        return db.scalars(select(PushWebhook)).all()


def test_a_push_webhook_is_set_up_on_an_own_repository_and_shown_once(system):
    app, client, _ = system
    ident, url = own(client)
    created = client.post(url)
    assert created.status_code == 201, created.text
    shown = created.json()
    assert set(shown) == {"path", "secret"}
    assert re.fullmatch(r"/push/[0-9a-f]{32}", shown["path"])
    assert re.fullmatch(r"[0-9a-f]{64}", shown["secret"])
    (row,) = stored(app)
    ingress = Vault(os.environ["NUMEN_INGRESS_KEY"])
    assert row.push_id == shown["path"].removeprefix("/push/")
    assert shown["secret"] not in row.secret and ingress.decrypt(row.secret) == shown["secret"]
    # GET shows that it is on, never its push id or secret.
    page = client.get(f"/api/applications/{ident}")
    (repository,) = page.json()["repositories"]
    assert set(repository["push_webhook"]) == {"created_at", "last_accepted", "last_refusal"}
    assert repository["push_webhook"]["last_accepted"] is repository["push_webhook"]["last_refusal"] is None
    assert row.push_id not in page.text and shown["secret"] not in page.text
    again = client.post(url)
    assert again.status_code == 409 and again.json()["code"] == "push_webhook_exists"

    # Regenerate replaces the secret at once and keeps the push id.
    regenerated = client.post(f"{url}/secret")
    assert regenerated.status_code == 200, regenerated.text
    assert regenerated.json()["path"] == shown["path"]
    assert regenerated.json()["secret"] != shown["secret"]
    (row,) = stored(app)
    assert ingress.decrypt(row.secret) == regenerated.json()["secret"]

    # Turn off removes the Push webhook and its deliveries.
    with app.state.factory.begin() as db:
        db.add(PushDelivery(push_webhook_id=row.id, delivery_id="d-1", body_sha256="0" * 64))
    off = client.delete(url)
    assert off.status_code == 200, off.text
    assert off.json()["push_webhook"] is None and off.json()["role"] == "own"
    assert stored(app) == []
    with app.state.factory() as db:
        assert db.scalars(select(PushDelivery)).all() == []
        actions = db.scalars(select(Action).where(Action.resource_id == ident)).all()
    for gone in (client.post(f"{url}/secret"), client.delete(url)):
        assert gone.status_code == 404 and gone.json()["code"] == "not_found"
    recorded = [a.data for a in actions if a.data.get("action", "").startswith("push_webhook")]
    assert [a["action"] for a in recorded] == [
        "push_webhook_set_up", "push_webhook_regenerated", "push_webhook_turned_off"]
    assert all(a["repository_id"] == repository["repository_id"] for a in recorded)
    text = json.dumps([a.data for a in actions])
    for secret in (shown["secret"], regenerated.json()["secret"], row.push_id):
        assert secret not in text


def test_a_push_webhook_cannot_be_set_up_on_an_upstream_repository(system):
    """AC-B02: Upstream repositories, GitHub or WordPress, and a removed Own link stay polled."""
    app, client, _ = system
    _, github = linked(client, source_kind="github", source_url="https://github.com/facebook/react")
    _, wordpress = linked(client, source_kind="wordpress", plugin_slug="akismet")
    _, removed = own(client, "acme/old")
    assert client.delete(removed.removesuffix("/push-webhook")).status_code == 200
    for url in (github, wordpress, removed):
        refused = client.post(url)
        assert refused.status_code == 422 and refused.json()["code"] == "push_webhook_own_only"
        assert client.post(f"{url}/secret").json()["code"] == "push_webhook_own_only"
    ident, _ = own(client, "acme/portal")
    assert client.post(f"/api/applications/{ident}/repositories/missing/push-webhook").status_code == 404
    assert stored(app) == []


def test_push_webhook_routes_need_the_session_and_csrf_but_no_password(system):
    app, client, _ = system
    _, url = own(client)
    with TestClient(app) as anonymous:
        assert anonymous.post(url).status_code == 401
    forged = client.post(url, headers={"X-CSRF-Token": ""})
    assert forged.status_code == 403 and forged.json()["code"] == "csrf_required"
    assert stored(app) == []
    assert client.post(url).status_code == 201  # no password: setting one up is not an Approval


def test_all_secrets_holds_each_push_webhook_secret(system, monkeypatch):
    app, client, _ = system
    shown = [client.post(own(client, name)[1]).json()["secret"] for name in ("acme/one", "acme/two")]
    with app.state.factory() as db:
        secrets = all_secrets(db, app.state.vault)
        assert set(shown) <= set(secrets) and os.environ["NUMEN_INGRESS_KEY"] in secrets
        # Without the key, the secrets cannot be redacted, so nothing runs rather than leak one.
        monkeypatch.delenv("NUMEN_INGRESS_KEY")
        with pytest.raises(DomainError) as refused:
            all_secrets(db, app.state.vault)
    assert refused.value.code == "vault_unconfigured"


UNRELATED = {"reply": json.dumps({"decision": "unrelated", "title": "Documentation wording",
                                  "reason": "No security bearing"})}


def set_up(client, name="acme/portal"):
    """An Application whose Own repository has a Push webhook; (application id, repository id,
    push id, secret)."""
    ident, url = own(client, name)
    shown = client.post(url).json()
    return ident, url.split("/")[-2], shown["path"].removeprefix("/push/"), shown["secret"]


def listener(app):
    """The push listener on the app's database, knowing every push id set up so far."""
    served = ingress.push_app(app.state.factory, Vault(os.environ["NUMEN_INGRESS_KEY"]))
    served.refresh()
    return TestClient(served)


def push(pusher, push_id, secret, body=None):
    """One accepted Push delivery, with a body of its own unless `body` is given."""
    body = body or json.dumps({"after": secrets.token_hex(20)}).encode()
    response = deliver(pusher, push_id, secret, body)
    assert response.json() == {"status": "accepted"}, response.text


def nudge(app):
    """One scheduler loop's nudge."""
    with app.state.factory.begin() as db:
        domain.nudge_push_deliveries(db)


def checks(app, repository_id):
    with app.state.factory() as db:
        return db.scalars(select(Job).where(
            Job.kind == "source_check", Job.input["repository_id"].as_string() == repository_id
        ).order_by(Job.created_at)).all()


def unprocessed(app):
    with app.state.factory() as db:
        return db.scalar(select(func.count()).select_from(PushDelivery).where(PushDelivery.processed_at.is_(None)))


def test_a_push_delivery_imports_the_new_commit_through_the_github_api_without_check_now(system, monkeypatch):
    """AC-B02: a delivery only nudges the poller. The new commit comes from the GitHub API, never
    from the payload, through the check schedule() and Check now queue, with the same jobs after
    it. A redelivery and a replayed body queue no further check."""
    app, client, config = system
    connection(app)
    github_account(app)
    ident, repository_id, push_id, secret = set_up(client)
    client.patch(f"/api/applications/{ident}", json={"config": {"triage_mode": "pi"}})
    head, polls = {"sha": "a" * 40}, []

    def commits(_, repository, *args):
        polls.append(repository.id)
        return head["sha"], [source_record(head["sha"])] if repository.cursor else [], None

    monkeypatch.setattr(Sources, "github_commits", commits)
    monkeypatch.setattr(Sources, "github_file", lambda *_: None)  # no manifest to derive from

    def run(queue):
        """The kinds of the jobs `queue` and every job after it created."""
        with app.state.factory() as db:
            before = set(db.scalars(select(Job.id)))
        queue()
        while run_once(config, app.state.factory, FixtureBroker(UNRELATED)):
            pass
        with app.state.factory() as db:
            return sorted(job.kind for job in db.scalars(select(Job)) if job.id not in before)

    def scheduled():
        with app.state.factory.begin() as db:
            domain.schedule(db)

    run(scheduled)  # the Baseline
    head["sha"] = "b" * 40
    payload = json.dumps({"after": "f" * 40, "commits": [{"id": "f" * 40, "message": "From the payload"}]}).encode()
    pusher = listener(app)
    delivery = str(uuid.uuid4())
    # The delivery, its redelivery, and the same body replayed under a new delivery id.
    assert [deliver(pusher, push_id, secret, payload, delivery=repeat).json()["status"]
            for repeat in (delivery, delivery, None)] == ["accepted", "duplicate", "duplicate"]
    assert len(checks(app, repository_id)) == 1  # the Baseline's: the ingress queues nothing
    with app.state.factory() as db:
        expected = domain.repository_input(db.get(Repository, repository_id))
    polls.clear()
    nudged = run(lambda: nudge(app))
    assert nudged == ["commit_triage", "source_check"] and polls == [repository_id]
    assert checks(app, repository_id)[-1].input == expected
    head["sha"] = "c" * 40
    assert run(lambda: check_now(client, ident)) == nudged
    for repeat in (delivery, None):
        assert deliver(pusher, push_id, secret, payload, delivery=repeat).json() == {"status": "duplicate"}
    assert run(lambda: nudge(app)) == []
    with app.state.factory() as db:
        assert sorted(db.scalars(select(Commit.revision))) == ["b" * 40, "c" * 40]


def test_the_nudge_applies_only_to_an_enabled_own_repository_of_an_application_in_use(system):
    """Decision 16: a nudge needs the enabled Own repository of an Application that is not
    archived, but not scheduled monitoring, and keeps A02's GitHub read token rule. A delivery it
    does not act on is still processed, so it never comes back."""
    app, client, _ = system
    cases = {name: set_up(client, f"acme/{name}") for name in ("off", "removed", "archived", "unmonitored")}

    def link(name):
        ident, repository, *_ = cases[name]
        return f"/api/applications/{ident}/repositories/{repository}"

    assert client.patch(link("off"), json={"enabled": False}).status_code == 200
    assert client.delete(link("removed")).status_code == 200
    assert client.patch(f"/api/applications/{cases['archived'][0]}", json={"archived": True}).status_code == 200
    assert client.patch(f"/api/applications/{cases['unmonitored'][0]}", json={"monitor_enabled": False}).status_code == 200
    # A Push webhook on a repository that is only Upstream, which Set up refuses, is ignored too.
    upstream = application(client, source_url="https://github.com/acme/upstream")
    repository, push_id, secret = upstream["repositories"][0]["repository_id"], secrets.token_hex(16), secrets.token_hex(32)
    with app.state.factory.begin() as db:
        db.add(PushWebhook(repository_id=repository, push_id=push_id,
                           secret=Vault(os.environ["NUMEN_INGRESS_KEY"]).encrypt(secret)))
    cases["upstream"] = (upstream["id"], repository, push_id, secret)
    pusher = listener(app)

    def nudged():
        """Delivers one push to each case and nudges: the cases that got a source check."""
        for _, _, push_id, secret in cases.values():
            push(pusher, push_id, secret)
        nudge(app)
        assert unprocessed(app) == 0
        return {name for name, (_, repository, *_) in cases.items() if checks(app, repository)}

    assert nudged() == set()
    with app.state.factory() as db:
        errors = {name: db.get(Repository, repository).last_error for name, (_, repository, *_) in cases.items()}
    assert errors.pop("unmonitored")["code"] == "github_token_required"
    assert set(errors.values()) == {None}
    github_account(app)
    assert nudged() == {"unmonitored"}


def test_ten_deliveries_while_a_check_is_queued_add_none_and_one_while_running_adds_exactly_one(system):
    """AC-B02: deliveries reuse a queued check. While one runs they wait, and the first loop after
    it queues exactly one more."""
    app, client, _ = system
    github_account(app)
    _, repository, push_id, secret = set_up(client)
    pusher = listener(app)

    def finish(status):
        with app.state.factory.begin() as db:
            db.get(Job, checks(app, repository)[-1].id).status = status

    push(pusher, push_id, secret)
    nudge(app)
    (queued,) = checks(app, repository)
    for _ in range(10):
        push(pusher, push_id, secret)
        nudge(app)
    assert [job.id for job in checks(app, repository)] == [queued.id] and unprocessed(app) == 0
    finish("running")
    push(pusher, push_id, secret)
    nudge(app)
    nudge(app)
    assert len(checks(app, repository)) == 1 and unprocessed(app) == 1
    finish("succeeded")
    nudge(app)
    nudge(app)
    assert [job.status for job in checks(app, repository)] == ["succeeded", "queued"]
    assert unprocessed(app) == 0


def test_a_nudge_never_moves_next_check_at_and_scheduled_checks_stay_on_time(system, monkeypatch):
    """AC-B02 and B02's Fallback: with a delivery every minute over two 5-minute intervals, the
    scheduled source check, version check and CVE sync, and the day's Advisory check, are queued
    on time, and no nudge moves next_check_at or last_check_at."""
    app, client, _ = system
    github_account(app)
    ident, repository, push_id, secret = set_up(client)
    start = now().replace(hour=12, minute=0, second=0, microsecond=0)
    with app.state.factory.begin() as db:
        row = db.get(Application, ident)
        recipe = VersionRecipe(application_id=ident, source_generation=row.source_generation,
                               source_ref="a" * 40, status="active", data={})
        db.add(recipe)
        db.flush()
        row.monitor_interval_seconds, row.next_check_at = 300, start
        row.config = {**row.config, "active_recipe_id": recipe.id,
                      "cve_selectors": [{"type": "keyword", "value": "portal"}]}
        db.get(Repository, repository).cursor = "a" * 40
    pusher = listener(app)

    def times():
        with app.state.factory() as db:
            row = db.get(Application, ident)
            return utc(row.next_check_at), utc(row.last_check_at)

    for minute in range(11):
        current = start + timedelta(minutes=minute)
        monkeypatch.setattr(domain, "now", lambda: current)
        push(pusher, push_id, secret)
        with app.state.factory.begin() as db:
            domain.schedule(db)
            domain.schedule_advisory_checks(db)
        due = start + timedelta(minutes=minute // 5 * 5)
        assert times() == (due + timedelta(minutes=5), due)
        nudge(app)
        assert times() == (due + timedelta(minutes=5), due)
        with app.state.factory.begin() as db:
            queued = db.scalars(select(Job).where(Job.status == "queued")).all()
            kinds = sorted(job.kind for job in queued)
            for job in queued:
                job.status = "succeeded"  # the worker ran it
        scheduled = ["cve_sync", "source_check", "version_check"] if minute % 5 == 0 else ["source_check"]
        assert kinds == (["advisory_check"] if minute == 0 else []) + scheduled, minute
    assert unprocessed(app) == 0


def test_push_deliveries_older_than_seven_days_are_pruned(system):
    """Plan, Tables: a body is unique among the last 7 days' deliveries; the nudge prunes older ones."""
    app, client, _ = system
    _, _, push_id, secret = set_up(client)
    pusher = listener(app)
    old, recent = b'{"after": "old"}', b'{"after": "recent"}'
    for body, days in ((old, 8), (recent, 6)):
        push(pusher, push_id, secret, body)
        with app.state.factory.begin() as db:
            db.scalar(select(PushDelivery).where(
                PushDelivery.body_sha256 == hashlib.sha256(body).hexdigest())).received_at = now() - timedelta(days=days)
    assert deliver(pusher, push_id, secret, old).json() == {"status": "duplicate"}
    nudge(app)
    assert [deliver(pusher, push_id, secret, body).json()["status"] for body in (old, recent)] == [
        "accepted", "duplicate"]
