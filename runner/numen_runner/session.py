"""Interactive agent sessions through Herdr, so an operator can watch, steer and chat with a run.

With NUMEN_AGENT_BACKEND=herdr an agent workload starts a private Herdr server inside its own
container and runs the agent's interactive TUI in a Herdr pane instead of its one-shot print
mode. The agent writes its application result to RESULT; the session ends when that file
validates and the agent is quiet. The broker reaches a session only by executing
`python -m numen_runner.session read|send` in the workload container.
"""
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import best_match

AGENT = "numen"
RESULT = Path("/workspace/outputs/result.json")
HOLD = Path("/home/job/session-hold")
NUDGES = 3
POLL = 2  # seconds between session checks
SETTLED = 3  # unchanged polls before a quiet agent counts as finished with its turn
STALLED = 8  # unchanged polls before a quiet agent without a result is reminded
INSTRUCTIONS = (
    "\nWhen you finish, write only the application result JSON object to /workspace/outputs/result.json and stop."
    " An operator may watch this session and send you messages; follow their instructions.")


class HerdrError(ValueError):
    pass


def call(method, **params):
    path = os.environ.get("HERDR_SOCKET_PATH") or str(Path.home() / ".config/herdr/herdr.sock")
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(330)  # agent.start waits for readiness up to its own timeout
        connection.connect(path)
        connection.sendall((json.dumps({"id": "numen", "method": method, "params": params}) + "\n").encode())
        reply = json.loads(connection.makefile("rb").readline())
    if "error" in reply:
        raise HerdrError(f"herdr {method}: {reply['error'].get('code')}")
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
    args = [a for a in argv[1:] if a != "--print"]
    mode = args.index("--mode")
    return args[:mode] + args[mode + 2:] + ["--tui-mode", "regular", "--offline"]


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


def watch(schema, pane, sleep=time.sleep):
    """Wait for a valid result while the operator may steer; remind a stalled agent."""
    previous, quiet, nudges = None, 0, 0
    while True:
        sleep(POLL)
        status = call("agent.get", target=AGENT)["agent"]["agent_status"]
        screen = call("pane.read", pane_id=pane, source="visible")["read"]["text"]
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
        call("agent.prompt", target=AGENT, text=f"The task is not finished: {error}. Continue, then write the result file.")


def run(argv, profile, env, prompt, schema):
    if profile["agent"] == "claude":
        seed_claude(env, profile)
    server = subprocess.Popen(["herdr", "server"], env=env, cwd="/workspace", stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        try:
            pane = start(argv, profile, server)
            call("agent.prompt", target=AGENT, text=prompt + INSTRUCTIONS)
        except HerdrError:
            raise ValueError("interactive agent session did not start") from None
        try:
            return watch(schema, pane)
        except HerdrError:
            raise ValueError("interactive agent session ended unexpectedly") from None
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
                raise HerdrError("herdr server did not start") from None
            time.sleep(.2)
    pane = call("workspace.create", cwd="/workspace", label=AGENT)["root_pane"]["pane_id"]
    call("agent.start", name=AGENT, kind=profile["agent"], pane_id=pane,
         args=agent_argv(argv, profile["agent"]), timeout_ms=120000)
    # Readiness can be reported before the TUI draws; wait for its screen to settle.
    previous, stable, deadline = None, 0, time.monotonic() + 120
    while stable < 3 and time.monotonic() < deadline:
        time.sleep(1)
        screen = call("pane.read", pane_id=pane, source="visible")["read"]["text"]
        stable = stable + 1 if screen == previous and len(screen.strip().splitlines()) > 3 else 0
        previous = screen
    return pane


def main():
    command = sys.argv[1]
    if command == "read":
        agent = call("agent.get", target=AGENT)["agent"]
        screen = call("pane.read", pane_id=agent["pane_id"], source="recent_unwrapped", lines=400)["read"]["text"]
        print(json.dumps({"agent": agent.get("agent"), "agent_status": agent["agent_status"],
                          "screen": screen, "held": HOLD.exists()}))
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
