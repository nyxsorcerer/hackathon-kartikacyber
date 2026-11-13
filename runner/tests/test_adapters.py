import json
import pytest
from numen_runner.adapters import agent_argv, codex_models, final_text, parse_agent

def test_codex_preserves_native_sandbox_and_exact_effort():
    p = {"agent":"codex", "model_id":"account-model", "reasoning_effort":"xhigh", "operation":"audit_context"}
    args = agent_argv(p)
    assert 'permissions.numen.extends=":workspace"' in args
    assert 'permissions.numen.filesystem./home/job="deny"' in args
    assert 'model_reasoning_effort="xhigh"' in args
    assert "--output-schema" in args and "--json" in args
    assert not any("dangerously" in a for a in args)

def test_claude_never_runs_bare_so_every_profile_tool_exists(tmp_path):
    """--bare sets CLAUDE_CODE_SIMPLE, which drops Grep, Glob and Write from any --tools list."""
    schema = tmp_path / "schema.json"
    schema.write_text('{"type":"object"}')
    for auth_type in ("native_oauth", "api_key"):
        p = {"agent":"claude", "model_id":"m", "auth_type":auth_type, "operation":"commit_analysis"}
        assert "--bare" not in agent_argv(p, str(schema))

def test_codex_requires_complete_turn_and_valid_final(tmp_path):
    final = tmp_path / "result.json"
    final.write_text(json.dumps({"result_json":json.dumps({"category":"Insufficient context"})}))
    with pytest.raises(ValueError):
        parse_agent("codex", '{"type":"turn.failed"}', str(final))
    assert parse_agent("codex", '{"type":"turn.completed"}', str(final))["category"] == "Insufficient context"

def test_models_keep_native_effort_names():
    data = [{"id":"model-id", "model":"account-model", "displayName":"Account model", "supportedReasoningEfforts":[{"reasoningEffort":"minimal"}],"defaultReasoningEffort":"minimal"}]
    assert codex_models(data)[0]["reasoning_efforts"] == ["minimal"]


def test_claude_target_mcp_is_allowed_without_becoming_a_builtin(tmp_path):
    schema=tmp_path/'schema.json'
    schema.write_text('{"type":"object"}')
    args=agent_argv({'agent':'claude','model_id':'m','auth_type':'api_key','operation':'version_recipe'},str(schema))
    assert 'mcp__numen_target__target_fetch' not in args[args.index('--tools')+1]
    assert 'mcp__numen_target__target_fetch' in json.loads(args[args.index('--settings')+1])['permissions']['allow']


def pi_stream(text):
    events = [{"type": "message_end", "message": {"role": "assistant", "stopReason": "stop", "content": [
        {"type": "thinking", "thinking": "plan\u2028next"}, {"type": "text", "text": text}]}}, {"type": "agent_end"}]
    # Like JSON.stringify: compact, and U+2028 stays unescaped inside strings.
    return "\n".join(json.dumps(e, separators=(",", ":"), ensure_ascii=False) for e in events)


def test_pi_final_json_tolerates_a_fence_and_unicode_line_breaks():
    assert parse_agent("pi", pi_stream('```json\n{"ok": true}\n```'), None) == {"ok": True}
    assert parse_agent("pi", pi_stream('{"note": "a\u2028b"}'), None) == {"note": "a\u2028b"}
    with pytest.raises(ValueError, match="not valid JSON"):
        parse_agent("pi", pi_stream("Done. The recipe is written."), None)


def test_pi_final_json_is_found_after_prose_and_the_last_object_wins():
    final = 'Recipe written.\n\n```json\n{"metadata": {"a": 1}}\n```\nDone, see {notes}.'
    assert parse_agent("pi", pi_stream(final), None) == {"metadata": {"a": 1}}
    assert parse_agent("pi", pi_stream('{"draft": 1} then {"metadata": {}}'), None) == {"metadata": {}}


@pytest.mark.parametrize("operation", ["commit_analysis", "cve_analysis", "version_recipe",
                                       "audit_context", "finding_artifacts"])
def test_tool_profiles_are_fixed_per_operation_without_a_shell_or_allowed_tools(tmp_path, operation):
    """Existence flags decide which tools a run has; nothing grants a shell, a daemon or an approval list."""
    schema = tmp_path / "schema.json"
    schema.write_text('{"type":"object"}')
    profile = {"provider_id":"openai","model_id":"m","auth_type":"api_key","reasoning_effort":None,
               "operation":operation,"enabled_plugins":[]}
    recipe = operation == "version_recipe"
    claude = agent_argv({**profile, "agent":"claude", "provider_id":"claude"}, str(schema))
    pi = agent_argv({**profile, "agent":"pi"}, str(schema))
    if operation in ("commit_analysis", "cve_analysis"):
        # Codex has no flag that removes its shell, which Analysis and CVE analysis must not have.
        with pytest.raises(ValueError, match="Analysis and CVE analysis on Codex are refused"):
            agent_argv({**profile, "agent":"codex"}, str(schema))
        runs = (claude, pi)
    else:
        codex = agent_argv({**profile, "agent":"codex"}, str(schema))
        assert 'shell_environment_policy.include_only=["PATH", "HOME", "NUMEN_FETCH_URL", "NUMEN_FETCH_TOKEN"]' in codex
        assert "sandbox_workspace_write.network_access=" + ("true" if recipe else "false") in codex
        runs = (codex, claude, pi)
    for args in runs:
        assert "--allowedTools" not in args and "--dangerously-skip-permissions" not in args
        assert not any(word in arg for arg in args for word in ("Bash", "numen_shell", "DOCKER_HOST", "PROXY"))
    assert claude[claude.index("--tools") + 1] == "Read,Grep,Glob,Write,Edit"
    assert claude[claude.index("--permission-mode") + 1] == "dontAsk"
    assert json.loads(claude[claude.index("--settings") + 1]) == {"permissions": {"allow":
        ["Edit(//workspace/outputs/**)"] + (["mcp__numen_target__target_fetch"] if recipe else [])}}
    assert pi[pi.index("--tools") + 1] == "numen_read,numen_list,numen_write" + (",target_fetch" if recipe else "")
    assert "--no-builtin-tools" in pi


def test_patch_drafting_tools(tmp_path):
    """Patch drafting reads the Own checkout and writes only outputs/patch.diff (A08): Pi and Claude get
    the fixed non-Triage profile with no shell, and Codex is refused (ADR-0004)."""
    schema = tmp_path / "schema.json"
    schema.write_text('{"type":"object"}')
    profile = {"model_id":"m","auth_type":"api_key","reasoning_effort":None,"operation":"patch_drafting","enabled_plugins":[]}
    with pytest.raises(ValueError, match="Patch drafting on Codex is refused"):
        agent_argv({**profile, "agent":"codex", "provider_id":"openai"}, str(schema))
    claude = agent_argv({**profile, "agent":"claude", "provider_id":"claude"}, str(schema))
    pi = agent_argv({**profile, "agent":"pi", "provider_id":"deepseek"}, str(schema))
    for args in (claude, pi):
        assert "--allowedTools" not in args and "--dangerously-skip-permissions" not in args
        assert not any(word in arg for arg in args for word in ("Bash", "numen_shell", "target_fetch", "DOCKER_HOST"))
    assert claude[claude.index("--tools") + 1] == "Read,Grep,Glob,Write,Edit"
    assert json.loads(claude[claude.index("--settings") + 1]) == {"permissions": {"allow": ["Edit(//workspace/outputs/**)"]}}
    assert "--restricted" in claude and "--bare" not in claude
    assert pi[pi.index("--tools") + 1] == "numen_read,numen_list,numen_write" and "--no-builtin-tools" in pi


def test_triage_is_offered_no_tools():
    """Triage is one print-mode call with no tools at all; application code validates its reply."""
    base = {"model_id":"m", "reasoning_effort":"high", "operation":"commit_triage", "enabled_plugins":[]}
    claude = agent_argv({**base, "agent":"claude", "provider_id":"claude", "auth_type":"api_key"})
    assert claude[:2] == ["claude", "-p"] and claude[claude.index("--tools") + 1] == ""
    assert claude[claude.index("--setting-sources") + 1] == ""
    assert claude[claude.index("--mcp-config") + 1] == '{"mcpServers":{}}'
    assert {"--strict-mcp-config", "--no-session-persistence", "--bare"} <= set(claude)
    assert claude[claude.index("--effort") + 1] == "high"
    assert not {"--allowedTools", "--json-schema", "--permission-mode", "--settings", "--add-dir"} & set(claude)
    native = agent_argv({**base, "agent":"claude", "provider_id":"claude", "auth_type":"native_oauth"})
    assert "--bare" not in native and native[native.index("--tools") + 1] == ""
    pi = agent_argv({**base, "agent":"pi", "provider_id":"deepseek", "auth_type":"api_key"})
    assert "--no-tools" in pi and "--tools" not in pi and "/opt/numen/pi-tools.ts" not in pi
    assert {"--no-extensions", "--no-skills", "--no-context-files", "--no-approve"} <= set(pi)
    assert pi[pi.index("--thinking") + 1] == "high"
    with pytest.raises(ValueError, match="Triage on Codex is refused"):
        agent_argv({**base, "agent":"codex", "provider_id":"openai"})


def test_triage_final_text_is_the_plain_reply_of_a_completed_turn():
    reply = '{"decision": "unrelated"}'
    assert final_text("claude", json.dumps({"type":"result","subtype":"success","is_error":False,"result":reply})) == reply
    assert final_text("pi", pi_stream(reply)) == reply
    for event in ({"type":"result","subtype":"error_max_turns","is_error":True,"result":reply},
                  {"type":"result","subtype":"success","is_error":False}):
        with pytest.raises(ValueError, match="Claude turn did not complete"):
            final_text("claude", json.dumps(event))
