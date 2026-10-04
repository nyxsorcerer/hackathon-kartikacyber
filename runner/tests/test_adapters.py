import json
import pytest
from numen_runner.adapters import agent_argv, parse_agent, codex_models

def test_codex_preserves_native_sandbox_and_exact_effort():
    p = {"agent":"codex", "model_id":"account-model", "reasoning_effort":"xhigh", "operation":"commit_triage"}
    args = agent_argv(p)
    assert 'permissions.numen.extends=":read-only"' in args
    assert 'permissions.numen.filesystem./home/job="deny"' in args
    assert 'model_reasoning_effort="xhigh"' in args
    assert "--output-schema" in args and "--json" in args
    assert not any("dangerously" in a for a in args)

def test_native_claude_omits_bare_api_mode(tmp_path):
    schema = tmp_path / "schema.json"
    schema.write_text('{"type":"object"}')
    p = {"agent":"claude", "model_id":"m", "auth_type":"native_oauth", "operation":"commit_analysis"}
    assert "--bare" not in agent_argv(p, str(schema))
    p["auth_type"] = "api_key"
    assert "--bare" in agent_argv(p, str(schema))

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
    assert 'mcp__numen_target__target_fetch' in args[args.index('--allowedTools')+1]


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
