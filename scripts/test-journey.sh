#!/bin/sh
set -eu
numen_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$numen_root"
export NUMEN_PORT=18788 NUMEN_PUSH_PORT=18791 NUMEN_AGENT_PORT=18792
export NUMEN_DASHBOARD_URL=http://localhost:18788
numen_test_compose() {
    ./scripts/compose.sh -p asset-monitor-test -f compose.yaml -f compose.test.yaml "$@"
}
# The same application image supplies Python; the journey runs inside Docker
# and reaches app/fixtures on the isolated test project's network.
numen_journey() {
    numen_test_compose run --rm --no-deps -T \
        --volume "$numen_root/tests/integration:/journey:ro" \
        --volume "$numen_root/.numen/bootstrap-password:/run/secrets/journey-password:ro" \
        --entrypoint python app "$@"
}
numen_check_transcripts() {
    numen_journey /journey/transcripts.py check --base-url http://app:8080 \
        --password-file /run/secrets/journey-password --expected "$numen_transcripts"
}
# Each check runs in its ingress service's own container, so it reaches only that service's two
# networks and logs in as its role (AC-B01).
numen_ingress_check() {
    numen_test_compose run --rm --no-deps -T --volume "$numen_root/tests/integration:/journey:ro" \
        --entrypoint python ingress-push /journey/ingress_check.py push
    numen_test_compose run --rm --no-deps -T --volume "$numen_root/tests/integration:/journey:ro" \
        --entrypoint python ingress-agent /journey/ingress_check.py agent "$(sed -n 's/^NUMEN_AGENT_TLS_PIN=//p' .env)"
}
# Each ingress role with its LOGIN, CONNECTION LIMIT and statement_timeout, every table privilege,
# and every column UPDATE (B02: the push role's UPDATE (last_accepted, last_refusal) on push_webhooks,
# which table_privileges does not list).
numen_ingress_grants() {
    numen_test_compose exec -T db psql -U numen -d numen -tAc "SELECT r.rolname, r.rolcanlogin, r.rolconnlimit, r.rolconfig,
        (SELECT string_agg(p.table_name || ':' || p.privilege_type, ',' ORDER BY p.table_name, p.privilege_type)
         FROM information_schema.table_privileges p WHERE p.grantee = r.rolname),
        (SELECT string_agg(c.table_name || '.' || c.column_name || ':' || c.privilege_type, ',' ORDER BY c.table_name, c.column_name)
         FROM information_schema.column_privileges c WHERE c.grantee = r.rolname AND c.privilege_type = 'UPDATE')
        FROM pg_roles r WHERE r.rolname IN ('asset_monitor_push', 'asset_monitor_agent') ORDER BY r.rolname"
}
numen_services='app worker scheduler runner-broker fetch-gateway fixtures ingress-push ingress-agent'
numen_test_compose up -d --wait $numen_services
numen_ingress_check
numen_test_compose --profile setup run --rm bootstrap-operator
numen_journey /journey/journey.py \
    --base-url http://app:8080 --fixture-url http://fixtures:8090 \
    --password-file /run/secrets/journey-password

# A Finding's Transcripts survive a container rebuild and a backup and restore (AC-A14), all on
# the isolated test project: `down -v` removes only its volumes.
numen_transcripts=$(numen_journey /journey/transcripts.py seed)
numen_test_compose up -d --wait --force-recreate $numen_services
numen_check_transcripts
printf '%s\n' 'PASS a container rebuild keeps the Transcripts'
# backup.sh and restore.sh act on the project these name; restore.sh must never reach the
# Operator's asset-monitor project.
export COMPOSE_PROJECT_NAME=asset-monitor-test COMPOSE_FILE=compose.yaml:compose.test.yaml
[ "$(./scripts/compose.sh config | head -n 1)" = 'name: asset-monitor-test' ] || { printf '%s\n' 'The backup round trip must run on asset-monitor-test.' >&2; exit 1; }
numen_grants=$(numen_ingress_grants)
case "$numen_grants" in
    asset_monitor_agent\|t\|*asset_monitor_push\|t\|*\|push_deliveries:INSERT,push_webhooks:SELECT\|push_webhooks.last_accepted:UPDATE,push_webhooks.last_refusal:UPDATE) ;;
    *) printf '%s\n' "$numen_grants" 'Both ingress roles must exist with LOGIN, and the push role with its push grants, before the backup.' >&2; exit 1 ;;
esac
numen_backup=.numen/test-backups/$(date -u +%Y%m%dT%H%M%SZ)
./scripts/backup.sh "$numen_backup"
numen_test_compose down -v
numen_test_compose up -d --wait db
# restore.sh rewrites the shared .env with the backup's copy, which must be the same bytes.
cmp -s .env "$numen_backup/deployment.env" || { printf '%s\n' '.env changed during the backup round trip.' >&2; exit 1; }
# restore.sh refuses a backup without the ingress keys before it changes anything. Had it gone on,
# it would have copied the stripped deployment.env over the shared .env: put that back first.
numen_stripped=$numen_backup-without-ingress-key
cp -R "$numen_backup" "$numen_stripped"
grep -v '^NUMEN_INGRESS_KEY=' "$numen_backup/deployment.env" > "$numen_stripped/deployment.env"
if numen_refusal=$(./scripts/restore.sh "$numen_stripped" 2>&1); then
    cp "$numen_backup/deployment.env" .env
    printf '%s\n' 'restore.sh restored a backup without NUMEN_INGRESS_KEY.' >&2
    exit 1
fi
case "$numen_refusal" in
    *'lacks NUMEN_INGRESS_KEY.'*'before release 2, copy them from the current .env'*) ;;
    *) printf '%s\n' "$numen_refusal" 'restore.sh did not name the missing ingress key.' >&2; exit 1 ;;
esac
cmp -s .env "$numen_backup/deployment.env" || { printf '%s\n' '.env changed when restore.sh refused a backup.' >&2; exit 1; }
rm -rf "$numen_stripped"
printf '%s\n' 'PASS restore.sh refuses a backup without the ingress keys and changes nothing'
./scripts/restore.sh "$numen_backup"
# No migrate has run on the fresh volume yet, so restore.sh itself created the roles.
[ "$(numen_test_compose exec -T db psql -U numen -d numen -tAc "SELECT count(*) FROM pg_roles WHERE rolname IN ('asset_monitor_push', 'asset_monitor_agent')")" = 2 ] \
    || { printf '%s\n' 'restore.sh did not create the ingress roles.' >&2; exit 1; }
printf '%s\n' 'PASS the ingress roles exist right after restore.sh on a fresh database volume'
numen_test_compose up -d --wait $numen_services
numen_check_transcripts
[ "$(numen_ingress_grants)" = "$numen_grants" ] \
    || { printf '%s\n' "$(numen_ingress_grants)" 'The ingress roles or their grants differ after the restore.' >&2; exit 1; }
printf '%s\n' 'PASS the restore brings back the ingress roles, their limits and their grants'
numen_ingress_check
rm -rf "$numen_backup"
printf '%s\n' 'PASS a backup, an empty project and a restore keep the Transcripts'
printf '%s\n' 'Isolated journey stack remains at http://localhost:18788 for browser inspection.'
printf '%s\n' 'Stop it with: ./scripts/compose.sh -p asset-monitor-test -f compose.yaml -f compose.test.yaml down'
