"""Interactive agent sessions through Herdr, so an operator can watch, steer and chat with a run.

With NUMEN_AGENT_BACKEND=herdr an agent workload starts a private Herdr server inside its own
container and runs the agent's interactive TUI in a Herdr pane instead of its one-shot print
mode. The agent writes its application result to RESULT; the session ends when that file
validates and the agent is quiet. The broker reaches a session only by executing
`python -m numen_runner.session read|send` in the workload container.
"""
import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match

from .session_history import read_history, read_scrollback, read_state, save_scrollback, save_state

AGENT = "numen"
RESULT = Path("/workspace/outputs/result.json")
HOLD = Path("/home/job/session-hold")
NUDGES = 3
POLL = 2  # seconds between session checks
SETTLED = 3  # unchanged polls before a quiet agent counts as finished with its turn
STALLED = 8  # unchanged polls before a quiet agent without a result is reminded
# Herdr's ANSI read normalizes the screen to SGR style codes; settling compares the bare text.
STYLE = re.compile(r"\x1b\[[0-9;:]*m")
RECENT = 1000  # Herdr returns at most this many terminal lines per read
SCROLLBACK = 10000  # terminal lines kept, about a real terminal's scrollback
TRIM = 1000  # the oldest lines are dropped together, so kept lines rarely shift
GAP = "\x1b[2m… more output scrolled past than one read holds; the Transcript has the full conversation …\x1b[0m"
INSTRUCTIONS = (
    "\nWhen you finish, write only the application result JSON object to /workspace/outputs/result.json and stop."
    " An operator may watch this session and send you messages; follow their instructions.")


class HerdrError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(f"herdr: {code}")


def call(method, **params):
    path = os.environ.get("HERDR_SOCKET_PATH") or str(Path.home() / ".config/herdr/herdr.sock")
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(330)  # agent.start waits for readiness up to its own timeout
        connection.connect(path)
        connection.sendall((json.dumps({"id": "numen", "method": method, "params": params}) + "\n").encode())
        reply = json.loads(connection.makefile("rb").readline())
    if "error" in reply:
        raise HerdrError(f"{method} {reply['error'].get('code')}")
    return reply["result"]


def agent_argv(argv, agent):
    """The interactive form of a print-mode argv from adapters.agent_argv."""
    if agent == "claude":
        print_only = {"--print": 0, "--output-format": 1, "--json-schema": 1, "--no-session-persistence": 0, "--permission-prompts": 1}
        args, skip = [], 0
        for arg in argv[1:]:
            if skip:
                skip -= 1
            elif arg in print_only:
                skip = print_only[arg]
            else:
                args.append(arg)
        return args
    if agent == "codex":
        exec_only = {"exec", "--json", "--ephemeral", "--ignore-user-config", "--ignore-rules", "--skip-git-repo-check", "-"}
        args, skip = ["--no-alt-screen", "-c", 'projects."/workspace".trust_level="trusted"'], 0
        for arg in argv[1:]:
            if skip:
                skip -= 1
            elif arg in {"--color", "--output-schema", "--output-last-message"}:
                skip = 1
            elif arg not in exec_only:
                args.append(arg)
        return args
    args = [a for a in argv[1:] if a not in {"--print", "--no-session"}]
    mode = args.index("--mode")
    return args[:mode] + args[mode + 2:] + ["--session-dir", "/home/job/session-transcripts/pi", "--tui-mode", "regular", "--offline"]


def seed_claude(env, profile):
    # First-run onboarding, workspace trust and API-key approval would block an unattended start.
    state = {"hasCompletedOnboarding": True, "theme": "dark",
             "projects": {"/workspace": {"hasTrustDialogAccepted": True, "hasCompletedProjectOnboarding": True}}}
    key = env.get("ANTHROPIC_API_KEY")
    if profile["auth_type"] == "api_key" and key:
        state["customApiKeyResponses"] = {"approved": [key[-20:]], "rejected": []}
    path = Path(env["CLAUDE_CONFIG_DIR"]) / ".claude.json"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(state))
    path.chmod(0o600)


def screen_lines(text):
    lines = text.replace("\r\n", "\n").split("\n")
    return lines[:-1] if lines and lines[-1] == "" else lines


def merge_scrollback(saved, scrolled):
    """`saved` extended by the lines of `scrolled` that follow its overlap with them."""
    if not scrolled:
        return saved
    for overlap in range(min(len(saved), len(scrolled)), 0, -1):
        if saved[-overlap:] == scrolled[:overlap]:
            return saved + scrolled[overlap:]
    return saved + ([GAP] if saved else []) + scrolled


def read_terminal(pane, scrollback):
    """Scrollback extended by the lines that left the screen, the whole terminal with its colors,
    and the screen's plain text used to tell when it settles.

    Herdr keeps more history than one read returns, so every poll saves what scrolled off.
    """
    visible = screen_lines(call("pane.read", pane_id=pane, source="visible", format="ansi")["read"]["text"])
    recent = screen_lines(call("pane.read", pane_id=pane, source="recent", format="ansi", lines=RECENT)["read"]["text"])
    rows = len(visible)
    lines = merge_scrollback(scrollback["lines"], recent[:-rows] if rows else recent)
    trimmed = scrollback["trimmed"]
    if len(lines) > SCROLLBACK:
        drop = len(lines) - SCROLLBACK + TRIM
        lines, trimmed = lines[drop:], trimmed + drop
    note = [f"\x1b[2m… {trimmed} earlier lines are not kept here; the Transcript has the full conversation …\x1b[0m"]
    shown = (note if trimmed else []) + lines + (recent[-rows:] if rows else [])
    return {"trimmed": trimmed, "lines": lines}, "\n".join(shown), STYLE.sub("", "\n".join(visible))


def result_error(schema):
    """None when RESULT holds a schema-valid result, otherwise what is wrong with it."""
    if RESULT.is_symlink():
        return f"{RESULT} must be a regular file"
    try:
        result = json.loads(RESULT.read_text())
    except FileNotFoundError:
        return f"{RESULT} does not exist yet"
    except ValueError as exc:
        return f"{RESULT} is not valid JSON ({exc})"
    error = best_match(Draft202012Validator(schema).iter_errors(result))
    return None if error is None else f"{RESULT} does not match the schema: {error.message[:500]}"


def watch(schema, pane, sleep=time.sleep, agent=None):
    """Wait for a valid result while the operator may steer; remind a stalled agent."""
    previous, quiet, nudges = None, 0, 0
    scrollback = {"trimmed": 0, "lines": []}
    while True:
        sleep(POLL)
        status = call("agent.get", target=AGENT)["agent"]["agent_status"]
        scrollback, terminal, screen = read_terminal(pane, scrollback)
        if agent:
            save_scrollback(scrollback)
            save_state(agent, terminal, status, HOLD.exists())
        # A color-only change (a pulsing spinner) is not new output.
        quiet = quiet + 1 if screen == previous else 0
        previous = screen
        # Herdr reports Codex as unknown while idle; an unchanged screen guards that fallback.
        if status in {"working", "blocked"} or quiet < SETTLED or HOLD.exists():
            continue
        error = result_error(schema)
        if error is None:
            result = json.loads(RESULT.read_text())
            RESULT.unlink()  # The result travels as the run result, not as an artifact.
            return result
        if quiet < STALLED:
            continue
        if nudges == NUDGES:
            raise ValueError("agent session ended without a valid result")
        nudges, quiet = nudges + 1, 0
        submit(f"The task is not finished: {error}. Continue, then write the result file.", time.monotonic() + 60)


def run(argv, profile, env, prompt, schema):
    save_state(profile["agent"])
    env = dict(env)
    if profile["agent"] in {"claude", "pi"}:
        temporary = Path("/home/job/session-output") / profile["agent"]
        temporary.mkdir(parents=True, exist_ok=True, mode=0o700)
        if profile["agent"] == "claude":
            env.update({"CLAUDE_CODE_TMPDIR": str(temporary), "CLAUDE_CODE_PROJECT_DIR_NAME": "numen"})
        else:
            env["TMPDIR"] = str(temporary)
    if profile["agent"] == "claude":
        # Claude's fullscreen renderer draws on the alternate screen, which has no scrollback,
        # so the conversation could not be scrolled back in the session view. Codex gets
        # --no-alt-screen and Pi --tui-mode regular for the same reason.
        env["CLAUDE_CODE_DISABLE_ALTERNATE_SCREEN"] = "1"
        seed_claude(env, profile)
    server = subprocess.Popen(["herdr", "server"], env=env, cwd="/workspace", stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        # Herdr's error code names the failed step (e.g. "agent.prompt agent_not_ready").
        try:
            pane = start(argv, profile, server)
            submit(prompt + INSTRUCTIONS, time.monotonic() + 120)
        except HerdrError as exc:
            raise ValueError(f"interactive agent session did not start ({exc.code})") from None
        try:
            return watch(schema, pane, agent=profile["agent"])
        except HerdrError as exc:
            raise ValueError(f"interactive agent session ended unexpectedly ({exc.code})") from None
    except Exception:
        # A held session stays inspectable after a failure until the operator releases it.
        while HOLD.exists():
            time.sleep(POLL)
        raise
    finally:
        server.kill()
        server.wait()


def start(argv, profile, server):
    deadline = time.monotonic() + 30
    while True:
        try:
            call("ping")
            break
        except (OSError, ValueError):
            if time.monotonic() > deadline or server.poll() is not None:
                raise HerdrError("server unavailable") from None
            time.sleep(.2)
    pane = call("workspace.create", cwd="/workspace", label=AGENT)["root_pane"]["pane_id"]
    call("agent.start", name=AGENT, kind=profile["agent"], pane_id=pane,
         args=agent_argv(argv, profile["agent"]), timeout_ms=120000)
    # agent.start can return before the agent is ready (Pi still loading its provider plugin),
    # and Herdr can call Claude ready before its TUI draws: wait for both, then a settled screen.
    previous, stable, deadline = None, 0, time.monotonic() + 120
    while stable < 3 and time.monotonic() < deadline:
        time.sleep(1)
        ready = call("agent.get", target=AGENT)["agent"].get("interactive_ready")
        screen = call("pane.read", pane_id=pane, source="visible")["read"]["text"]
        stable = stable + 1 if ready and screen == previous and len(screen.strip().splitlines()) > 3 else 0
        previous = screen
    return pane


def submit(text, deadline):
    """agent.prompt, retried while Herdr still reports the agent as not ready."""
    while True:
        try:
            return call("agent.prompt", target=AGENT, text=text)
        except HerdrError as exc:
            if not exc.code.endswith("agent_not_ready") or time.monotonic() > deadline:
                raise
            time.sleep(1)


def main():
    command = sys.argv[1]
    if command == "read":
        try:
            agent = call("agent.get", target=AGENT)["agent"]
            try:
                saved = read_scrollback()
            except (OSError, ValueError):
                saved = {"trimmed": 0, "lines": []}  # A damaged file never blocks a live read.
            screen = read_terminal(agent["pane_id"], saved)[1]
        except (OSError, HerdrError):
            print(json.dumps(read_history()))  # The server can end before its workload exits.
        else:
            kind = read_state()["agent"]
            save_state(kind, screen, agent["agent_status"], HOLD.exists())
            print(json.dumps({**read_history(include_partial=False), "live": True}))
    elif command == "archive":
        print(json.dumps(read_history()))
    elif command == "send":
        # Bounded and validated by the broker; this is the operator's own message to the agent.
        request = json.loads(sys.argv[2])
        if request["action"] == "prompt":
            call("agent.prompt", target=AGENT, text=request["text"])
        elif request["action"] == "keys":
            call("agent.send_keys", target=AGENT, keys=request["keys"])
        elif request["action"] == "hold":
            HOLD.touch()
        else:
            HOLD.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError) as exc:
        print(json.dumps({"error": str(exc)[:200]}))
        sys.exit(1)
