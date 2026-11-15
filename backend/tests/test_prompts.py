import pytest
from sqlalchemy import select

from conftest import FixtureBroker
from numen import artifacts, prompts
from numen.models import Action, JobEvent, Setting
from numen.worker import run_once
from test_artifacts import bundle, queue_cve_analysis
from test_commit_review import assessment, prepared


def default(operation):
    return prompts.render(operation, prompts.context(operation), prompts.defaults())


def test_each_operation_gets_only_the_sections_it_uses():
    triage = default("commit_triage")
    assert "This is Triage: one reply, with no tools." in triage and "untrusted evidence" in triage
    assert "Finding bundle" not in triage
    recipe = default("version_recipe")
    assert "Attack path" not in recipe and "release-corpus.json" in recipe
    analysis = default("commit_analysis")
    for part in ("## Attack path", "## Finding bundle", "prior-analyses.json"):
        assert part in analysis, part
    assert ", ".join(artifacts.REQUIRED) in analysis
    assert "release-corpus.json" not in analysis and "Trail of Bits" not in analysis
    assert "prior-analyses.json" not in default("cve_analysis")
    # No operation builds anything: Analysis, CVE analysis and finding artifacts only draft a bundle.
    assert "build-sandbox" not in prompts.defaults()
    for operation in ("commit_analysis", "cve_analysis", "finding_artifacts"):
        text = default(operation)
        assert "inputs/source is a read-only checkout of the pinned revision" in text, operation
        assert "Build and run nothing" in text and "draft" in text, operation
        assert "Build sandbox" not in text and "DOCKER_HOST" not in text and "/workspace/repo" not in text, operation
    for phase in ("audit_orientation", "audit_function", "audit_synthesis"):
        assert "Trail of Bits" in default(phase) and "Attack path" not in default(phase)


def test_the_bundle_section_describes_the_offline_node_lab():
    bundle = default("commit_analysis").split("## Finding bundle", 1)[1]
    for part in (
        "Labs are Node only",
        "with install scripts disabled",
        "runs it with no network at all",
        "asset-monitor-lab:0.1.0 is Debian bookworm with Python 3.12, Node 24.9.0 and npm",
        "every entry of \"images\" must be asset-monitor-lab:0.1.0.",
        "the Lab places the Own repository at the Verdict's commit under vulnerable-app/",
        # The three vulnerable-app rules (A07), so a bundle carries only the Dockerfile and its own files.
        "own_head: the Lab places the Own repository at its default-branch head",
        "minimal, with the packages and locked_version facts: GarudaNetra writes vulnerable-app/package.json",
        "bundle only the Dockerfile and the files you wrote yourself",
        "COPY . /app/",
        'CMD ["node", "server.js"]',
        "at most 4 GB",
        "15 minutes",
        "10 minutes that include the application's startup",
        "TARGET_URL",
    ):
        assert part in bundle, part
    # Numen's Lab pulled digest-pinned bases and installed dependencies over the network.
    for stale in ("@sha256", "digest", "with network", "internet access", "git clone checked out"):
        assert stale not in bundle, stale


def test_the_detection_rule_section_describes_validation_and_the_cleanup_report():
    analysis = default("commit_analysis")
    assert "A Malicious change drafts the Detection rule below" in analysis
    section = analysis.split("## Detection rule", 1)[1].split("## Attack path", 1)[0]
    for part in (
        "detection-rule.yar",
        "matches nothing in the parent",
        "after the Baseline",
        "yara",
        "no network",
        "include",
        "console module",
        "64 KiB",
        "exactly as commit.json lists them",
        "exactly as the diff's added lines show them",
        "reachable_secrets",
        "never their values",
        "Never execute, install, import or render the payload",
    ):
        assert part in section, part
    # The prose cleanup report is no longer drafted: application code builds it from the result.
    assert "cleanup-report.md" not in analysis
    assert "Detection rule" in prompts.DESCRIPTIONS["detection-rule"]
    for operation in ("cve_analysis", "finding_artifacts", "commit_triage"):
        assert "## Detection rule" not in default(operation), operation


def test_templates_list_their_sections_and_the_operations_using_them(system):
    _, client, _ = system
    body = client.get("/api/prompts").json()
    items = {item["name"]: item for item in body["items"]}
    assert set(items) == set(prompts.defaults())
    assert set(body["variables"]) == {"operation", "required_files", "facts"}
    assert items["attack-path"]["kind"] == "section"
    assert items["attack-path"]["used_by"] == ["commit_analysis", "cve_analysis", "finding_artifacts"]
    assert items["commit_analysis"]["kind"] == "operation"
    assert items["commit_analysis"]["includes"] == ["attack-path", "bundle", "detection-rule", "rules"]
    assert items["detection-rule"]["used_by"] == ["commit_analysis", "served_analysis"]
    assert items["audit-context"]["used_by"] == ["cve_analysis", "finding_artifacts"]
    # Patch drafting (A08) starts from the shared rules only and renders within the runner's bound.
    assert (items["patch_drafting"]["kind"], items["patch_drafting"]["includes"]) == ("operation", ["rules"])
    patch = default("patch_drafting")
    assert len(patch) < prompts.RENDERED_LIMIT
    for part in ("/workspace/outputs/patch.diff", "a/ and b/ paths", "never anything under .git/",
                 "set workflows to true", "Build and run nothing"):
        assert part in patch, part
    assert not any(item["customized"] for item in items.values())
    # Sections come first, then operations.
    kinds = [item["kind"] for item in body["items"]]
    assert kinds == sorted(kinds, key=lambda kind: kind == "operation")


def queue_commit(system):
    _, ident, _ = prepared(system)
    queued = system[1].post(f"/api/commits/{ident}/analyses", json={}).json()["job_id"]
    return queued, FixtureBroker(assessment("Security hardening"), {"report.md": b"# Assessment"})


def queue_cve(system):
    # CVE analysis records its source pin before the agent runs: the event must not contend with it.
    _, queued, result = queue_cve_analysis(system)
    return queued, FixtureBroker(result, bundle())


@pytest.mark.parametrize("queue,operation", [(queue_commit, "commit_analysis"), (queue_cve, "cve_analysis")])
def test_a_customized_section_reaches_the_next_job_and_is_recorded(system, queue, operation):
    app, client, config = system
    source = prompts.defaults()["attack-path"] + "\nOperator rule: name the CWE of {{ operation }}.\n"
    saved = client.put("/api/prompts/attack-path", json={"source": source})
    assert saved.status_code == 200, saved.text
    assert saved.json()["customized"] and saved.json()["source"] == source
    queued, broker = queue(system)
    run_once(config, app.state.factory, broker)
    assert client.get(f"/api/jobs/{queued}").json()["status"] == "succeeded"
    prompt = broker.calls[0]["prompt"]
    assert f"Operator rule: name the CWE of {operation}." in prompt
    # Numen appends the facts itself, after the template.
    assert prompt.rsplit("\n\nFacts:\n", 1)[1].startswith("{")
    with app.state.factory() as db:
        events = [e.data for e in db.scalars(select(JobEvent).where(JobEvent.job_id == queued))]
        record = db.scalar(select(Action).where(Action.resource_type == "prompt"))
    assert {"kind": "prompt_customized", "templates": ["attack-path"]}.items() <= next(
        e for e in events if e["kind"] == "prompt_customized").items()
    assert record.resource_id == "attack-path" and record.data["previous"] is None


def test_resetting_or_saving_the_default_returns_a_template_to_the_default(system):
    app, client, _ = system
    client.put("/api/prompts/rules", json={"source": "Perform {{ operation }} carefully."})
    reset = client.delete("/api/prompts/rules")
    assert reset.status_code == 200
    assert not reset.json()["customized"] and reset.json()["source"] == prompts.defaults()["rules"]
    client.put("/api/prompts/rules", json={"source": "Edited"})
    same = client.put("/api/prompts/rules", json={"source": prompts.defaults()["rules"]})
    assert not same.json()["customized"]
    with app.state.factory() as db:
        actions = [a.data for a in db.scalars(select(Action).where(Action.resource_id == "rules"))]
    assert [a["action"] for a in actions] == ["updated", "reset", "updated", "updated"]
    assert actions[1]["previous"] == "Perform {{ operation }} carefully."


@pytest.mark.parametrize("name,source,message", [
    ("rules", "{% if operation %}unclosed", "Line 1"),
    ("rules", "{{ opertion }}", "Unknown variable opertion"),
    ("rules", '{% include "missing" %}', "no template named missing"),
    ("rules", "{% include operation %}", "quoted name"),
    ("rules", '{% include "commit_analysis" %}', "includes itself"),
])
def test_a_template_that_would_break_a_job_is_refused(system, name, source, message):
    _, client, _ = system
    response = client.put(f"/api/prompts/{name}", json={"source": source})
    assert response.status_code == 422, response.text
    assert message in response.json()["message"]
    assert not next(i for i in client.get("/api/prompts").json()["items"] if i["name"] == name)["customized"]


def test_templates_render_in_a_sandbox_without_python_internals():
    sources = {**prompts.defaults(), "rules": "[{{ facts.__class__.__mro__ }}{{ operation.__class__ }}]"}
    assert prompts.render("commit_triage", prompts.context("commit_triage"), sources).startswith("[]")


def test_unknown_templates_and_operations_are_not_found(system):
    _, client, _ = system
    assert client.put("/api/prompts/nothing", json={"source": "x"}).status_code == 404
    assert client.delete("/api/prompts/nothing").status_code == 404
    assert client.post("/api/prompts/preview", json={"operation": "nothing"}).status_code == 404


def test_a_draft_previews_without_being_saved(system):
    _, client, _ = system
    draft = prompts.defaults()["bundle"] + "\nDraft-only rule.\n"
    preview = client.post("/api/prompts/preview", json={
        "operation": "cve_analysis", "name": "bundle", "source": draft,
    })
    assert preview.status_code == 200, preview.text
    body = preview.json()
    assert "Draft-only rule." in body["prompt"] and body["prompt"].endswith("as JSON)")
    assert "bundle" in body["templates"] and "version_recipe" not in body["templates"]
    assert set(body) == {"prompt", "templates"}
    # A preview no longer takes a build flag.
    assert client.post("/api/prompts/preview", json={"operation": "cve_analysis", "build": True}).status_code == 422
    assert "Draft-only rule." not in client.post("/api/prompts/preview", json={"operation": "cve_analysis"}).json()["prompt"]
    assert client.post("/api/prompts/preview", json={"operation": "cve_analysis", "name": "bundle"}).status_code == 422


def test_a_template_customized_before_its_default_changed_is_flagged(system):
    app, client, _ = system
    client.put("/api/prompts/audit", json={"source": "Follow the audit skill."})
    with app.state.factory.begin() as db:
        row = db.get(Setting, prompts.SETTING)
        templates = dict(row.data["templates"])
        templates["audit"] = {**templates["audit"], "default_digest": "an earlier default"}
        row.data = {**row.data, "templates": templates}
    audit = next(i for i in client.get("/api/prompts").json()["items"] if i["name"] == "audit")
    assert audit["customized"] and audit["default_changed"]
