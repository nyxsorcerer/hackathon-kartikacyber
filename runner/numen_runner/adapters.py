"""Native command/protocol adapters. No shell interpolation and no result fallback."""
import json
from pathlib import Path

WRITE_OPERATIONS = {"commit_analysis", "cve_analysis", "version_recipe", "finding_artifacts", "audit_context"}
PI_BASE = ["pi", "--no-session", "--no-extensions", "--no-skills", "--no-prompt-templates", "--no-themes", "--no-context-files", "--no-approve"]


def agent_argv(profile, schema_path="/workspace/schema.json", output_path="/workspace/final.json", build=False, session=False):
    agent, model, effort = profile["agent"], profile["model_id"], profile.get("reasoning_effort")
    # An interactive session writes its result file, so every session operation can write outputs.
    write = session or profile.get("operation") in WRITE_OPERATIONS
    if agent == "codex":
        args = ["codex", "exec", "--json", "--ephemeral", "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check", "--color", "never",
                "--model", model, "--output-schema", schema_path, "--output-last-message", output_path,
                "-c", 'default_permissions="numen"', "-c", 'permissions.numen.extends=' + json.dumps(":workspace" if write else ":read-only"),
                "-c", 'permissions.numen.filesystem./home/job="deny"', "-C", "/workspace", "-c", 'approval_policy="never"',
                "-c", "project_doc_max_bytes=0", "-c", 'shell_environment_policy.inherit="all"',
                "-c", 'shell_environment_policy.include_only=' + json.dumps(
                    ["PATH","HOME","NUMEN_FETCH_URL","NUMEN_FETCH_TOKEN"]
                    + (["DOCKER_HOST","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","NO_PROXY"] if build else [])),
                "-c", "sandbox_workspace_write.network_access=" + ("true" if build or profile.get("operation") == "version_recipe" else "false")]
        if effort:
            args += ["-c", "model_reasoning_effort=" + json.dumps(effort)]
        return args + ["-"]
    if agent == "claude":
        tools = "Read,Grep,Glob,Write,Edit" if write else "Read,Grep,Glob"
        if build:
            tools += ",Bash"
        allowed_tools = tools
        target_mcp = {"mcpServers":{}}
        if profile.get("operation") == "version_recipe":
            allowed_tools += ",mcp__numen_target__target_fetch"
            target_mcp["mcpServers"]["numen_target"] = {"command":"python","args":["-m","numen_runner.fetch_mcp"]}
        args = ["claude", "--print", "--output-format", "json", "--model", model, "--json-schema", Path(schema_path).read_text(),
                "--tools", tools, "--allowedTools", allowed_tools, "--permission-mode", "dontAsk", "--permission-prompts", "none",
                "--no-session-persistence", "--setting-sources", "", "--strict-mcp-config", "--mcp-config", json.dumps(target_mcp), "--restricted", "--add-dir", "/opt/resources"]
        if profile["auth_type"] == "api_key":
            args.append("--bare")
        if effort:
            args += ["--effort", effort]
        return args
    if agent == "pi":
        tools = "numen_read,numen_list,numen_write,target_fetch" if write else "numen_read,numen_list"
        args = pi_argv(profile) + ["--no-builtin-tools", "--extension", "/opt/numen/pi-tools.ts",
                                   "--tools", tools + ",numen_shell" if build else tools]
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


def pi_repair_argv(profile):
    """A tool-less Pi call that restates a final answer as the result JSON."""
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
        event = json.loads(stdout)
        if event.get("is_error") or event.get("subtype") != "success":
            raise ValueError("Claude turn did not complete")
        result = event.get("structured_output")
        if result is None:
            raise ValueError("Claude omitted structured output")
        return result_json(result["result_json"])
    return result_json(pi_final_text(stdout))


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
