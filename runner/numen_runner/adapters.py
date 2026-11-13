"""Native command/protocol adapters. No shell interpolation and no result fallback."""
import json
from pathlib import Path

PI_BASE = ["pi", "--no-session", "--no-extensions", "--no-skills", "--no-prompt-templates", "--no-themes", "--no-context-files", "--no-approve"]
CODEX_TRIAGE = "Triage on Codex is refused until a no-tools restriction is verified for it"
CODEX_ANALYSIS = "Analysis and CVE analysis on Codex are refused until a Codex mode without a shell is verified"
# Codex has no flag that removes its shell, so it cannot run the operations whose tools exclude one (ADR-0004).
CODEX_REFUSED = {"commit_triage": CODEX_TRIAGE, "commit_analysis": CODEX_ANALYSIS, "cve_analysis": CODEX_ANALYSIS}


def agent_argv(profile, schema_path="/workspace/schema.json", output_path="/workspace/final.json"):
    """Each operation's tools are fixed here by the flags that decide which tools exist, never by an
    approval list (ADR-0004): Triage gets no tools, Pi and Claude get no shell tool, Codex (whose
    shell no flag removes) is refused for Triage, Analysis and CVE analysis, every other operation
    writes only under outputs/, and only version_recipe reaches the target."""
    agent, model, effort = profile["agent"], profile["model_id"], profile.get("reasoning_effort")
    if agent == "codex" and profile.get("operation") in CODEX_REFUSED:
        raise ValueError(CODEX_REFUSED[profile["operation"]])
    if profile.get("operation") == "commit_triage":
        # One tool-less print-mode call whose plain reply application code validates (A03).
        if agent == "claude":
            args = ["claude", "-p", "--output-format", "json", "--model", model, "--tools", "", "--setting-sources", "",
                    "--strict-mcp-config", "--mcp-config", '{"mcpServers":{}}', "--no-session-persistence"]
            # With no tools, an API key's minimal mode drops nothing and skips hooks, plugins and CLAUDE.md.
            if profile.get("auth_type") == "api_key":
                args.append("--bare")
            return args + (["--effort", effort] if effort else [])
        if agent == "pi":
            return pi_no_tools_argv(profile) + (["--thinking", effort] if effort else [])
        raise ValueError("unsupported agent")
    recipe = profile.get("operation") == "version_recipe"
    if agent == "codex":
        args = ["codex", "exec", "--json", "--ephemeral", "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check", "--color", "never",
                "--model", model, "--output-schema", schema_path, "--output-last-message", output_path,
                "-c", 'default_permissions="numen"', "-c", 'permissions.numen.extends=":workspace"',
                "-c", 'permissions.numen.filesystem./home/job="deny"', "-C", "/workspace", "-c", 'approval_policy="never"',
                "-c", "project_doc_max_bytes=0", "-c", 'shell_environment_policy.inherit="all"',
                "-c", 'shell_environment_policy.include_only=' + json.dumps(["PATH","HOME","NUMEN_FETCH_URL","NUMEN_FETCH_TOKEN"]),
                # Codex keeps its shell, so its sandbox keeps the network off except for
                # version_recipe, whose commands reach the target only through the fetch gateway.
                "-c", "sandbox_workspace_write.network_access=" + ("true" if recipe else "false")]
        if effort:
            args += ["-c", "model_reasoning_effort=" + json.dumps(effort)]
        return args + ["-"]
    if agent == "claude":
        # dontAsk denies whatever is not approved, so --settings approves file writes under outputs/
        # only (an Edit rule covers every file-editing tool) and the target tool for version_recipe.
        allow = ["Edit(//workspace/outputs/**)"]
        target_mcp = {"mcpServers":{}}
        if recipe:
            allow.append("mcp__numen_target__target_fetch")
            target_mcp["mcpServers"]["numen_target"] = {"command":"python","args":["-m","numen_runner.fetch_mcp"]}
        args = ["claude", "--print", "--output-format", "json", "--model", model, "--json-schema", Path(schema_path).read_text(),
                "--tools", "Read,Grep,Glob,Write,Edit", "--settings", json.dumps({"permissions":{"allow":allow}}), "--permission-mode", "dontAsk", "--permission-prompts", "none",
                "--no-session-persistence", "--setting-sources", "", "--strict-mcp-config", "--mcp-config", json.dumps(target_mcp), "--restricted", "--add-dir", "/opt/resources"]
        # Never --bare: its CLAUDE_CODE_SIMPLE tool set drops Grep, Glob and Write from --tools.
        if effort:
            args += ["--effort", effort]
        return args
    if agent == "pi":
        tools = "numen_read,numen_list,numen_write" + (",target_fetch" if recipe else "")
        args = pi_argv(profile) + ["--no-builtin-tools", "--extension", "/opt/numen/pi-tools.ts", "--tools", tools]
        if effort:
            args += ["--thinking", effort]
        return args
    raise ValueError("unsupported agent")


def pi_argv(profile):
    args = PI_BASE + ["--print", "--mode", "json", "--provider", "anthropic" if profile["provider_id"] == "claude" else profile["provider_id"],
                      "--model", profile["model_id"]]
    if profile["provider_id"] == "commandcode":
        args += ["--extension", "/opt/numen/node_modules/pi-commandcode-provider/index.ts"]
    return args


def pi_no_tools_argv(profile):
    """A Pi call with no tools at all (built-in and extension): Triage, and the restatement of a
    final answer as the result JSON. Only an explicitly selected provider extension loads."""
    return pi_argv(profile) + ["--no-tools"]


def pi_event(prefix):
    """Classify a Pi JSON event line from its prefix; see workload.EventLines.

    Every event line starts with its type. Tool results, prompts and the agent_end transcript
    repeat file contents, so they are skipped unbuffered. The assistant message's key order comes
    from the provider, so its role is checked after the whole line is read.
    """
    if prefix.startswith(b'{"type":"agent_end"'):
        return b'{"type":"agent_end"}\n'
    leading_role = prefix.startswith(b'{"type":"message_end","message":{"role":"')
    if not prefix.startswith(b'{"type":"message_end"') or (
            leading_role and not prefix.startswith(b'{"type":"message_end","message":{"role":"assistant"')):
        return None
    return lambda line: "assistant" if json.loads(line).get("message", {}).get("role") == "assistant" else None


def agent_events(agent):
    return pi_event if agent == "pi" else None


def json_objects(text):
    """Top-level JSON objects embedded in text, in order of appearance."""
    decoder, found, index = json.JSONDecoder(), [], text.find("{")
    while index >= 0:
        try:
            value, end = decoder.raw_decode(text, index)
        except ValueError:
            index = text.find("{", index + 1)
            continue
        if isinstance(value, dict):
            found.append(value)
        index = text.find("{", end)
    return found


def result_json(text):
    """Decode the agent's final JSON; surrounding prose or a code fence is tolerated."""
    try:
        return json.loads(text)
    except ValueError:
        found = json_objects(text)
    if not found:
        raise ValueError("agent final response was not valid JSON")
    return found[-1]  # A final answer ends with its result.


def parse_agent(agent, stdout, final_path):
    # Event streams are newline-delimited; JSON strings may contain U+2028 and other line breaks.
    if agent == "codex":
        events = [json.loads(line) for line in stdout.split("\n") if line.startswith("{")]
        if any(e.get("type") in {"turn.failed", "error"} for e in events) or not any(e.get("type") == "turn.completed" for e in events):
            raise ValueError("Codex turn did not complete")
        final = json.loads(Path(final_path).read_text())
        return result_json(final["result_json"])
    if agent == "claude":
        result = claude_result(stdout).get("structured_output")
        if result is None:
            raise ValueError("Claude omitted structured output")
        return result_json(result["result_json"])
    return result_json(pi_final_text(stdout))


def claude_result(stdout):
    event = json.loads(stdout)
    if event.get("is_error") or event.get("subtype") != "success":
        raise ValueError("Claude turn did not complete")
    return event


def final_text(agent, stdout):
    """The final reply text of a completed one-shot turn, unparsed: Triage's application code validates it."""
    if agent == "claude":
        text = claude_result(stdout).get("result")
        if not isinstance(text, str):
            raise ValueError("Claude turn did not complete")
        return text
    return pi_final_text(stdout)


def pi_final_text(stdout):
    events = [json.loads(line) for line in stdout.split("\n") if line.startswith("{")]
    completed = [e for e in events if e.get("type") == "message_end" and e.get("message", {}).get("role") == "assistant"]
    if not completed or not any(e.get("type") == "agent_end" for e in events):
        raise ValueError("Pi turn did not complete")
    message = completed[-1]["message"]
    if message.get("stopReason") != "stop":
        raise ValueError("Pi agent did not complete its final response")
    return "".join(c.get("text", "") for c in message.get("content", []) if c.get("type") == "text")


def codex_models(data):
    return [{"id": m.get("model", m["id"]), "name": m.get("displayName", m.get("model", m["id"])),
             "reasoning_efforts": [e["reasoningEffort"] for e in m.get("supportedReasoningEfforts", [])],
             "default_effort": m.get("defaultReasoningEffort")} for m in data]
