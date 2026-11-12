#!/bin/sh
set -eu
numen_case=${1:-all}
case "$numen_case" in
    all) numen_selector='' ;;
    auth-persistence|application-configuration) numen_selector='auth_application or inherited_interval or api_survives_replacement' ;;
    source-monitoring) numen_selector='github_old_dated or github_archive or wordpress or nvd' ;;
    job-recovery) numen_selector='lease_recovery or postgres' ;;
    review-notification) numen_selector='explicit_commit or webhook' ;;
    account-capabilities) numen_selector='capabilities or profile_runtime' ;;
    commit-analysis) numen_selector='explicit_commit_analysis or profile_runtime' ;;
    audit-context) numen_selector='audit_coordinator' ;;
    cve-monitoring|cve-dispatch) numen_selector='score_gate or unconfirmed_match or cve_applicability or cve_analysis or nvd' ;;
    finding-artifacts) numen_selector='bundle_draft or paths_archives or cve_analysis or finding_generation' ;;
    *) printf '%s\n' "Unknown integration case: $numen_case" >&2; exit 2 ;;
esac
numen_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$numen_root"
./scripts/compose.sh up -d --wait db
./scripts/compose.sh --profile test run --build --no-deps --rm \
    backend-tests sh -c '
export NUMEN_TEST_DATABASE_URL="$NUMEN_DATABASE_URL"
if [ -n "$1" ]; then
    exec pytest -q -p no:cacheprovider -k "$1"
fi
exec pytest -q -p no:cacheprovider
' sh "$numen_selector"
