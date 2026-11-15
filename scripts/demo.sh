#!/bin/sh
# The demo (A16) on a disposable VM (ADR-0005): the normal stack plus the local stand-ins
# (compose.demo.yaml) under its own Compose project, never the Operator's asset-monitor project.
# The run sheet is docs/demo.md.
#   ./scripts/demo.sh up | seed | step <name> | status | down | run <file in tests/integration> [args]
set -eu
numen_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$numen_root"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-asset-monitor-demo}"
export NUMEN_PORT="${NUMEN_DEMO_PORT:-8790}"
export NUMEN_PUSH_PORT="${NUMEN_DEMO_PUSH_PORT:-8793}" NUMEN_AGENT_PORT="${NUMEN_DEMO_AGENT_PORT:-8794}"
export NUMEN_DASHBOARD_URL="http://localhost:$NUMEN_PORT"
demo_fail() {
    printf '%s\n' "$1" >&2
    exit 1
}
case "$COMPOSE_PROJECT_NAME" in
    asset-monitor-demo|asset-monitor-demo-*) ;;
    *) demo_fail "The demo runs only on an asset-monitor-demo project, never on $COMPOSE_PROJECT_NAME." ;;
esac
# The canned dry-run overlay (compose.demo-test.yaml) is for make test-demo only, never the real demo.
case "$COMPOSE_PROJECT_NAME" in
    asset-monitor-demo-test) ;;
    *) [ -z "${NUMEN_DEMO_OVERLAY:-}" ] || demo_fail "NUMEN_DEMO_OVERLAY is for make test-demo only." ;;
esac
demo_compose() {
    ./scripts/compose.sh -p "$COMPOSE_PROJECT_NAME" -f compose.yaml -f compose.demo.yaml \
        ${NUMEN_DEMO_OVERLAY:+-f "$NUMEN_DEMO_OVERLAY"} "$@"
}
[ "$(demo_compose config | head -n 1)" = "name: $COMPOSE_PROJECT_NAME" ] \
    || demo_fail "The demo's Compose configuration does not name the $COMPOSE_PROJECT_NAME project."
# A driver in tests/integration, run in the application image on the demo project's network. The
# keys are passed by name, so no value is ever echoed. It runs as the host user, who owns the 0600
# bootstrap password (uid 10001 cannot read it on a Linux host); it writes only to /tmp.
demo_run() {
    case "${1:-}" in
        *.py) case "$1" in */*) demo_fail "Name a Python file in tests/integration." ;; esac ;;
        *) demo_fail "Name a Python file in tests/integration." ;;
    esac
    demo_file=$1
    shift
    demo_compose run --rm --no-deps -T --user "$(id -u):$(id -g)" \
        --volume "$numen_root/tests/integration:/demo:ro" \
        --volume "$numen_root/.numen/bootstrap-password:/run/secrets/demo-password:ro" \
        -e ANTHROPIC_API_KEY -e DEEPSEEK_API_KEY -e DISCORD_WEBHOOK_URL \
        -e DEMO_TRIAGE_MODEL -e DEMO_ANALYSIS_MODEL -e NUMEN_PORT \
        --entrypoint python app "/demo/$demo_file" "$@"
}
case "${1:-}" in
    up)
        [ "${ASSET_MONITOR_DEMO_VM:-}" = 1 ] || demo_fail "Run the demo only on a disposable VM that holds \
demo-scoped, spend-capped keys (ADR-0005), and set ASSET_MONITOR_DEMO_VM=1 there."
        # The stand-in server's image holds the real On-server agent binary, built from agent/ (B04).
        demo_compose build server-standin
        demo_compose up -d --wait app worker scheduler runner-broker fetch-gateway fixtures ingress-push ingress-agent \
            server-standin
        # As the host user, for the same 0600 password file; bootstrap writes only to the database.
        demo_compose --profile setup run --rm --user "$(id -u):$(id -g)" bootstrap-operator
        demo_run demo.py seed
        printf '%s\n' "The demo dashboard is at $NUMEN_DASHBOARD_URL (username admin, password in .numen/bootstrap-password)."
        ;;
    seed) demo_run demo.py seed ;;
    step)
        shift
        demo_run demo.py step "$@"
        ;;
    status)
        demo_compose ps
        demo_run demo.py status
        ;;
    run)
        shift
        demo_run "$@"
        ;;
    down) demo_compose down -v ;;
    *) demo_fail "Usage: $0 up | seed | step <name> | status | down | run <file in tests/integration> [args]" ;;
esac
