"""Read the whole native conversation, independently of Herdr's bounded screen buffer."""
import json
import os
import stat
import tempfile
from pathlib import Path

HOME = Path("/home/job")
STATE = ".numen-session.json"
SCROLLBACK = ".numen-scrollback.json"
LOGS = {
    "pi": "session-transcripts/pi/*.jsonl",
    "claude": ".claude/projects/**/*.jsonl",
    "codex": ".codex/sessions/**/*.jsonl",
}


def regular_file(path, home):
    # Native output is untrusted. Never follow links into an auth cache or another file.
    if any(part.is_symlink() for part in [path, *path.parents] if part != home.parent):
        raise ValueError("session history contains a linked path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise ValueError("session history must be a regular file")
    return os.fdopen(fd, encoding="utf-8")


def content(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "\n".join(content(item) for item in value)
    if isinstance(value, dict):
        for key in ("text", "thinking"):
            if isinstance(value.get(key), str):
                return value[key]
        if value.get("type") == "tool_result" and "content" in value:
            return f"[tool result · {value.get('tool_use_id', '')}]\n{content(value['content'])}"
        if value.get("type") in {"tool_use", "toolCall"}:
            arguments = value.get("input", value.get("arguments"))
            return f"[tool call · {value.get('name', '')}]\n{content(arguments)}"
        # Keep tool calls, attachments, and new native record shapes inspectable.
    return json.dumps(value, ensure_ascii=False, indent=2)


def render_record(record):
    message = record.get("message")
    if isinstance(message, dict):  # Claude and Pi conversation records.
        label = str(message.get("role", record.get("type", "message")))
        if message.get("toolName"):
            label += " · " + str(message["toolName"])
        return f"[{label}]\n{content(message.get('content', message))}"
    if record.get("type") == "response_item":
        item = record.get("payload", {})
        if not isinstance(item, dict):
            return content(record)
        label = str(item.get("role", item.get("type", "response")))
        if item.get("name"):
            label += " · " + str(item["name"])
        parts = [content(item[key]) for key in ("summary", "content", "arguments", "input", "output") if key in item]
        if parts:
            return f"[{label}]\n" + "\n".join(parts)
        item = {key: value for key, value in item.items() if key != "encrypted_content"}
        return f"[{label}]\n{content(item)}"
    # Preserve unfamiliar and supplemental events rather than silently dropping output.
    return content(record)


def read_state(home=HOME):
    with regular_file(home / STATE, home) as handle:
        state = json.load(handle)
    if not isinstance(state, dict) or state.get("agent") not in LOGS:
        raise ValueError("unsupported session history")
    return state


def read_history(home=HOME, include_partial=True):
    state = read_state(home)
    agent = state["agent"]
    sections = []
    for path in sorted(home.glob(LOGS[agent])):
        sections.append(f"=== {path.relative_to(home)} ===")
        with regular_file(path, home) as handle:
            for line in handle:
                # In-flight partial JSON is deferred during live reads, retained on final archive.
                try:
                    record = json.loads(line)
                except ValueError:
                    if line.endswith("\n") or include_partial:
                        sections.append(line.rstrip("\n"))
                    continue
                sections.append(render_record(record) if isinstance(record, dict) else content(record))
    if agent == "claude":
        # Claude moves large tool results out of JSONL. Read only its known sidecar roots,
        # never the arbitrary absolute paths printed by untrusted tool output.
        for pattern in (".claude/projects/**/tool-results/**/*.txt", ".claude/projects/**/tool-results/**/*.json",
                        "session-output/claude/**/tasks/*.output"):
            for path in sorted(home.glob(pattern)):
                with regular_file(path, home) as handle:
                    text = handle.read()
                if path.suffix == ".json":
                    try:
                        text = content(json.loads(text))
                    except ValueError:
                        pass
                sections.append(f"=== {path.relative_to(home)} ===\n{text}")
    if agent == "pi":
        for path in sorted(home.glob("session-output/pi/pi-bash-*.log")):
            with regular_file(path, home) as handle:
                sections.append(f"=== {path.relative_to(home)} ===\n{handle.read()}")
    if isinstance(state.get("screen"), str) and state["screen"]:
        sections.append("=== Latest terminal view ===\n" + state["screen"])
    return {"agent": agent, "agent_status": state.get("agent_status", "unknown"),
            "held": state.get("held", False), "screen": "\n\n".join(sections), "live": False}


def write_json(target, value, home):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=home, delete=False) as handle:
        temp = Path(handle.name)
        try:
            json.dump(value, handle)
            handle.flush()
            temp.replace(target)
        finally:
            temp.unlink(missing_ok=True)


def save_state(agent, screen="", status="unknown", held=False, home=HOME):
    write_json(home / STATE, {"agent": agent, "agent_status": status, "screen": screen, "held": held}, home)


def read_scrollback(home=HOME):
    """Terminal lines that scrolled off screen, as saved by the watching session."""
    try:
        with regular_file(home / SCROLLBACK, home) as handle:
            value = json.load(handle)
    except FileNotFoundError:
        return {"trimmed": 0, "lines": []}
    lines = value.get("lines") if isinstance(value, dict) else None
    if not isinstance(lines, list) or not all(isinstance(line, str) for line in lines) \
            or not isinstance(value.get("trimmed", 0), int):
        raise ValueError("unsupported terminal scrollback")
    return {"trimmed": value.get("trimmed", 0), "lines": lines}


def save_scrollback(scrollback, home=HOME):
    write_json(home / SCROLLBACK, scrollback, home)
