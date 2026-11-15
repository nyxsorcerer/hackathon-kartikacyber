#!/bin/sh
# The demo smoke test (A16): the demo overlay under the isolated asset-monitor-demo-test project,
# seeded twice with no model keys, then every demo step run and checked; then the dry run, with
# canned agent decisions. It never touches the Operator's asset-monitor project, and it makes no
# paid model request.
set -eu
numen_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$numen_root"
export COMPOSE_PROJECT_NAME=asset-monitor-demo-test NUMEN_DEMO_PORT=18790 NUMEN_DEMO_PUSH_PORT=18793 NUMEN_DEMO_AGENT_PORT=18794 ASSET_MONITOR_DEMO_VM=1
unset ANTHROPIC_API_KEY DEEPSEEK_API_KEY DISCORD_WEBHOOK_URL DEMO_TRIAGE_MODEL DEMO_ANALYSIS_MODEL
# demo.sh refuses any project but an asset-monitor-demo one. Checked on an unrelated name with no
# subcommand, so even a broken guard could act on nothing.
case "$(COMPOSE_PROJECT_NAME=asset-monitor-unrelated ./scripts/demo.sh 2>&1 || true)" in
    *'runs only on an asset-monitor-demo project'*) printf '%s\n' 'PASS demo.sh refuses a project that is not a demo project' ;;
    *) printf '%s\n' 'demo.sh accepted a project that is not a demo project.' >&2; exit 1 ;;
esac
case "$(COMPOSE_PROJECT_NAME=asset-monitor-demo NUMEN_DEMO_OVERLAY=compose.demo-test.yaml ./scripts/demo.sh 2>&1 || true)" in
    *'NUMEN_DEMO_OVERLAY is for make test-demo only'*) printf '%s\n' 'PASS demo.sh refuses the canned dry-run overlay on the real demo project' ;;
    *) printf '%s\n' 'demo.sh accepted the canned dry-run overlay on the real demo project.' >&2; exit 1 ;;
esac
case "$(ASSET_MONITOR_DEMO_VM= ./scripts/demo.sh up 2>&1 || true)" in
    *'set ASSET_MONITOR_DEMO_VM=1'*) printf '%s\n' 'PASS demo.sh up refuses to start off a disposable demo VM' ;;
    *) printf '%s\n' 'demo.sh up started without ASSET_MONITOR_DEMO_VM=1.' >&2; exit 1 ;;
esac
# The demo scripts never approve: no request path in demo.py names an Approval route.
if grep -nE "(lab-runs|approvals|quarantines|restores)['\"]" tests/integration/demo.py; then
    printf '%s\n' 'demo.py requests an Approval route.' >&2
    exit 1
fi
printf '%s\n' 'PASS demo.py makes no /lab-runs, /approvals, /quarantines or /restores request'
# The run sheet names every step demo.py accepts.
for demo_step in $(sed -n "s/^STEPS = (\(.*\))$/\1/p" tests/integration/demo.py | tr -d "',"); do
    grep -qF "make demo-step STEP=$demo_step" docs/demo.md \
        || { printf '%s\n' "docs/demo.md does not name make demo-step STEP=$demo_step." >&2; exit 1; }
done
printf '%s\n' 'PASS docs/demo.md names every demo step'
./scripts/demo.sh down
./scripts/demo.sh run fixture_server.py check
./scripts/demo.sh up
# The seed is idempotent: a second run creates nothing new. With no model keys it still completes
# and says which steps need them.
demo_seed=$(./scripts/demo.sh run demo.py seed)
printf '%s\n' "$demo_seed"
case "$demo_seed" in
    *'NEEDS MODEL KEYS'*'SEED DONE'*) printf '%s\n' 'PASS the seed without model keys completes and names the steps that need them' ;;
    *) printf '%s\n' 'The seed without model keys did not say which steps need them.' >&2; exit 1 ;;
esac
./scripts/demo.sh run demo_check.py smoke seed
# Every demo step in run-sheet order through the Operator's own command, each checked for what
# needs no agent. With no model keys no patch or revert is drafted, so steps 2 and merge-revert
# refuse clearly; the test approves the node2shell bump itself, so merge-bump has one to merge.
for demo_step in 1 2 3 merge-revert 4 5 merge-bump php-inject php-clean server-inject; do
    case "$demo_step" in
        2|merge-revert)
            demo_action=patch
            [ "$demo_step" = 2 ] || demo_action=revert
            if demo_out=$(./scripts/demo.sh step "$demo_step" 2>&1); then
                printf '%s\n' "demo.sh step $demo_step succeeded without an open $demo_action Remediation PR." >&2
                exit 1
            fi
            case "$demo_out" in
                *"approve the $demo_action Remediation PR in the dashboard first"*)
                    printf '%s\n' "PASS step $demo_step with no open $demo_action Remediation PR fails and says what to approve first" ;;
                *) printf '%s\n' "$demo_out" "demo.sh step $demo_step did not say what to approve first." >&2; exit 1 ;;
            esac
            continue
            ;;
        merge-bump) ./scripts/demo.sh run demo_check.py smoke approve ;;
    esac
    ./scripts/demo.sh step "$demo_step"
    ./scripts/demo.sh run demo_check.py smoke "$demo_step"
done
demo_status=$(./scripts/demo.sh status)
printf '%s\n' "$demo_status"
case "$demo_status" in
    *'bump Remediation PR merged: https://github.com/asset-monitor-demo/shop/pull/1'*'bump Remediation PR ready, pending Approval'*)
        printf '%s\n' 'PASS status lists the Findings, their Remediation PRs with pull URLs, and what waits for Approval' ;;
    *) printf '%s\n' 'demo.sh status did not list the Remediation PRs and pending Approvals.' >&2; exit 1 ;;
esac
./scripts/demo.sh down
printf '%s\n' 'DEMO SMOKE PASSED'

# The dry run (brief 5(b)): the same demo on a fresh project, with only the agent decisions replaced
# by the canned Verdicts of the test-only overlay compose.demo-test.yaml, from the seed to the last
# Remediation PR. The placeholder keys are not keys: the canned broker never forwards them.
./scripts/demo.sh run canned_broker.py check
export NUMEN_DEMO_OVERLAY=compose.demo-test.yaml ANTHROPIC_API_KEY=canned-dry-run-not-a-key DEEPSEEK_API_KEY=canned-dry-run-not-a-key
./scripts/demo.sh down
if ! demo_up=$(./scripts/demo.sh up 2>&1); then
    printf '%s\n' "$demo_up" 'demo.sh up failed under the dry-run overlay.' >&2
    exit 1
fi
printf '%s\n' "$demo_up"
case "$demo_up" in
    *"$ANTHROPIC_API_KEY"*) printf '%s\n' 'The seed printed a model key.' >&2; exit 1 ;;
    *'NEEDS MODEL KEYS'*) printf '%s\n' 'The seed with model keys still said it needs them.' >&2; exit 1 ;;
    *'SEED DONE'*) printf '%s\n' 'PASS the seed with model keys completes and never prints a key' ;;
    *) printf '%s\n' 'The seed under the dry-run overlay did not finish.' >&2; exit 1 ;;
esac
./scripts/demo.sh run demo_check.py dry-run
./scripts/demo.sh down
printf '%s\n' 'DEMO DRY RUN PASSED'
