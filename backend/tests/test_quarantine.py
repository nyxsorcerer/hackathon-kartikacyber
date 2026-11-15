"""Quarantine and Restore (B07): each only after an Approval with the password on that request, as a
command signed with the Dashboard key that lists only the files whose SHA-256 the Finding names in
the agent's latest manifest. The agent's verified result is shown per file; a later verified manifest
without the named SHA-256 values Remediates the Finding, and one that shows a named value again
regresses it to Confirmed with an Alert naming the agent and no path."""
import base64
import json
from datetime import timedelta

from sqlalchemy import select, update

from conftest import application
from numen import agent_wire
from numen.models import Action, AgentMessage, Notification, ServerChange, now
from test_artifacts import APPROVAL
from test_server_agents import payload, process, stand  # noqa: F401
from test_server_files import ROOT, SHELL, SHELL_PATH, baselined, drop_shell, server, sha  # noqa: F401

QUARANTINE_ID = "c" * 32


def opened(server):  # noqa: F811
    """A server_files Finding opened by hand on the dropped shell's Server change."""
    baselined(server)
    drop_shell(server)
    with server.stand.factory() as db:
        (change,) = db.scalars(select(ServerChange))
    created = server.stand.client.post("/api/findings", json={
        "application_id": server.stand.application_id, "source": "server_files", "title": "A dropped PHP shell",
        "source_server_change_id": change.id})
    assert created.status_code == 201, created.text
    return created.json()


def shown(server, finding):  # noqa: F811
    return server.stand.client.get(f"/api/findings/{finding['id']}").json()


def quarantine(server, finding, **body):  # noqa: F811
    listed = shown(server, finding)["quarantine"]
    return server.stand.client.post(f"/api/findings/{finding['id']}/quarantines",
                                    json={**APPROVAL, "list_sha256": listed["list_sha256"], **body})


def commands(server, name=None):  # noqa: F811
    with server.stand.factory() as db:
        query = select(AgentMessage).where(AgentMessage.type == "command").order_by(AgentMessage.sequence)
        return list(db.scalars(query.where(AgentMessage.name == name) if name else query))


def answer(server, command, status, **file):  # noqa: F811
    """The agent's verified result for `command`: each file it lists, with `status`."""
    message = next(m for m in commands(server) if m.id == command["id"])
    body = json.loads(base64.b64decode(message.payload))["body"]
    files = ([{**item, "quarantine_id": QUARANTINE_ID, "status": status, **file} for item in body["files"]]
             if body["name"] == "quarantine" else
             [{"root": ROOT, "path": SHELL_PATH, "sha256": sha(SHELL), "quarantine_id": entry, "status": status}
              for entry in body["entries"]])
    result = {"type": "command", "sequence": message.sequence, "command_id": message.id, "name": body["name"],
              "status": "done", "files": files}
    assert server.stand.agent.send("POST", "/agent/v1/result", result)[0] == 202
    process(server.stand)


def test_quarantine_needs_the_password_and_the_reviewed_list_and_sends_one_signed_command(server):  # noqa: F811
    finding = opened(server)
    assert (finding["source_ref"], finding["subject_id"], finding["agent_id"]) == (
        "web-1", finding["source_server_change_id"], server.stand.agent.agent_id)
    listed = shown(server, finding)["quarantine"]
    assert (listed["agent_name"], listed["list"], listed["commands"]) == (
        "web-1", [{"root": ROOT, "path": SHELL_PATH, "sha256": sha(SHELL)}], [])
    client, path = server.stand.client, f"/api/findings/{finding['id']}/quarantines"
    # A missing or wrong password, or a list that changed since it was reviewed, sends nothing.
    for body, code in (({"list_sha256": listed["list_sha256"]}, 403), (
            {"password": "wrong", "list_sha256": listed["list_sha256"]}, 403), ({**APPROVAL, "list_sha256": "0" * 64}, 409)):
        refused = client.post(path, json=body)
        assert refused.status_code == code, refused.text
    assert refused.json()["code"] == "quarantine_list_changed"
    assert commands(server) == []
    sent = quarantine(server, finding)
    assert sent.status_code == 202, sent.text
    assert quarantine(server, finding).json()["id"] == sent.json()["id"]  # a double submit sends one command
    (command,) = commands(server)
    assert command.idempotency_key == (
        f"quarantine:{server.stand.application_id}:{finding['id']}:{listed['list_sha256']}:0")
    # The agent gets it signed with the Dashboard key, listing only the files the Finding names.
    (envelope,) = server.stand.agent.poll()[1]["commands"]
    assert agent_wire.verify(server.stand.enrollment["dashboard_key"], envelope["signature"],
                             agent_wire.MESSAGE_PREFIX + base64.b64decode(envelope["payload"]))
    message = payload(envelope)
    assert (message["type"], message["expires_at"] - message["issued_at"]) == ("command", 900)
    assert message["body"] == {"command_id": command.id, "name": "quarantine",
                               "files": [{"root": ROOT, "path": SHELL_PATH, "sha256": sha(SHELL)}]}
    with server.stand.factory() as db:
        (action,) = db.scalars(select(Action).where(Action.data["approved"].as_string() == "quarantine"))
    assert (action.resource_id, action.data["command_id"], action.data["list_sha256"]) == (
        finding["id"], command.id, listed["list_sha256"])
    # Approving changes no lifecycle by itself.
    assert shown(server, finding)["status"] == "open"
    # A command past its expiry can be approved again, as a new attempt.
    with server.stand.factory.begin() as db:
        db.execute(update(AgentMessage).values(expires_at=now() - timedelta(seconds=1)))
    assert shown(server, finding)["quarantine"]["commands"][0]["status"] == "expired"
    again = quarantine(server, finding)
    assert again.status_code == 202 and again.json()["id"] != command.id
    assert [m.idempotency_key[-2:] for m in commands(server)] == [":0", ":1"]


def test_the_result_is_shown_and_manifests_remediate_and_regress_the_finding(server):  # noqa: F811
    finding = opened(server)
    client = server.stand.client
    confirmed = client.post(f"/api/findings/{finding['id']}/transitions", json={"state": "confirmed", "reason": "Shell"})
    assert confirmed.status_code == 200, confirmed.text
    first = quarantine(server, finding).json()
    answer(server, first, "quarantined")
    listed = shown(server, finding)["quarantine"]
    (row,) = listed["commands"]
    assert (row["status"], row["files"][0]["status"], row["files"][0]["path"]) == ("done", "quarantined", SHELL_PATH)
    assert listed["quarantined"] == [{"quarantine_id": QUARANTINE_ID, "root": ROOT, "path": SHELL_PATH,
                                      "sha256": sha(SHELL), "command_id": first["id"]}]
    # The same bytes under another path are still the named SHA-256: no remediation.
    del server.files[SHELL_PATH]
    server.files["wp-content/uploads/other.php"] = server.file("wp-content/uploads/other.php", SHELL)
    server.report()
    assert shown(server, finding)["status"] == "confirmed"
    del server.files["wp-content/uploads/other.php"]
    server.report()
    remediated = shown(server, finding)
    assert (remediated["status"], remediated["cause"]["by"]) == ("remediated", "manifest")
    # Restore is allowed on a Remediated Finding (the dashboard warns it puts the payload back).
    restore = row["restore"]
    assert restore["entries"] == [QUARANTINE_ID]
    path = f"/api/findings/{finding['id']}/restores"
    body = {"command_id": first["id"], "entries_sha256": restore["entries_sha256"]}
    assert client.post(path, json={**body, "password": "wrong"}).status_code == 403
    assert client.post(path, json={**APPROVAL, **body, "entries_sha256": "0" * 64}).json()["code"] == "restore_list_changed"
    assert len(commands(server, "restore")) == 0
    restored = client.post(path, json={**APPROVAL, **body})
    assert restored.status_code == 202, restored.text
    (envelope,) = server.stand.agent.poll()[1]["commands"]
    assert payload(envelope)["body"] == {"command_id": restored.json()["id"], "name": "restore",
                                         "entries": [QUARANTINE_ID]}
    answer(server, restored.json(), "restored")
    assert shown(server, finding)["quarantine"]["quarantined"] == []
    # The named SHA-256 seen again regresses it to Confirmed, with one Alert naming the agent, no path.
    drop_shell(server)
    server.report()
    regressed = shown(server, finding)
    assert (regressed["status"], regressed["cause"]["by"]) == ("confirmed", "regression") and regressed["regressed_at"]
    with server.stand.factory() as db:
        (alert,) = db.scalars(select(Notification))
    assert (alert.data["source"], alert.data["verdict"], alert.data["link"]) == (
        "web-1", "Malicious change · regressed", f"/findings/{finding['id']}")
    assert "cache.php" not in json.dumps(alert.data) and ROOT not in json.dumps(alert.data)
    # A Quarantine after a Restore sends a new command.
    again = quarantine(server, finding)
    assert again.status_code == 202 and again.json()["id"] != first["id"]
    assert len(commands(server, "quarantine")) == 2


def test_restore_of_a_confirmed_findings_files_is_allowed(server):  # noqa: F811
    finding = opened(server)
    client = server.stand.client
    assert client.post(f"/api/findings/{finding['id']}/transitions",
                       json={"state": "confirmed", "reason": "Shell"}).status_code == 200
    first = quarantine(server, finding).json()
    answer(server, first, "quarantined")
    (row,) = shown(server, finding)["quarantine"]["commands"]
    restored = client.post(f"/api/findings/{finding['id']}/restores", json={
        **APPROVAL, "command_id": first["id"], "entries_sha256": row["restore"]["entries_sha256"]})
    assert restored.status_code == 202, restored.text
    assert shown(server, finding)["status"] == "confirmed"  # Restore changes no lifecycle by itself


def test_a_hand_opened_finding_names_a_server_change_of_its_own_application(server):  # noqa: F811
    baselined(server)
    drop_shell(server)
    with server.stand.factory() as db:
        (change,) = db.scalars(select(ServerChange))
    client = server.stand.client
    other = application(client, asset_name="Other site")["id"]
    body = {"source": "server_files", "title": "Shell", "source_server_change_id": change.id}
    refused = client.post("/api/findings", json={**body, "application_id": other})
    assert (refused.status_code, refused.json()["code"]) == (422, "invalid_reference")
    missing = client.post("/api/findings", json={**body, "application_id": server.stand.application_id,
                                                 "source_server_change_id": None})
    assert missing.status_code == 422
    created = client.post("/api/findings", json={**body, "application_id": server.stand.application_id}).json()
    assert created["server_files"] == [{"root": ROOT, "path": SHELL_PATH, "sha256": sha(SHELL)}]
    # An edit keeps the change; moving the Finding to another change is refused.
    edited = client.patch(f"/api/findings/{created['id']}", json={"title": "A dropped shell"})
    assert edited.status_code == 200 and edited.json()["source_server_change_id"] == change.id
    assert client.patch(f"/api/findings/{created['id']}", json={"source_server_change_id": "other"}).status_code == 404
