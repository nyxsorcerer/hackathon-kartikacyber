#!/bin/sh
set -eu
numen_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$numen_root"
export NUMEN_PORT=18788
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
numen_services='app worker scheduler runner-broker fetch-gateway fixtures'
numen_test_compose up -d --wait $numen_services
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
numen_backup=.numen/test-backups/$(date -u +%Y%m%dT%H%M%SZ)
./scripts/backup.sh "$numen_backup"
numen_test_compose down -v
numen_test_compose up -d --wait db
# restore.sh rewrites the shared .env with the backup's copy, which must be the same bytes.
cmp -s .env "$numen_backup/deployment.env" || { printf '%s\n' '.env changed during the backup round trip.' >&2; exit 1; }
./scripts/restore.sh "$numen_backup"
numen_test_compose up -d --wait $numen_services
numen_check_transcripts
rm -rf "$numen_backup"
printf '%s\n' 'PASS a backup, an empty project and a restore keep the Transcripts'
printf '%s\n' 'Isolated journey stack remains at http://localhost:18788 for browser inspection.'
printf '%s\n' 'Stop it with: ./scripts/compose.sh -p asset-monitor-test -f compose.yaml -f compose.test.yaml down'
