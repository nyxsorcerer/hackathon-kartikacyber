#!/bin/sh
set -eu
numen_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$numen_root"
export NUMEN_PORT=18788
export NUMEN_DASHBOARD_URL=http://localhost:18788
numen_test_compose() {
    ./scripts/compose.sh -p asset-monitor-test -f compose.yaml -f compose.test.yaml "$@"
}
numen_test_compose up -d --wait app worker scheduler runner-broker fetch-gateway fixtures
numen_test_compose --profile setup run --rm bootstrap-operator
# The same application image supplies Python; the journey runs inside Docker
# and reaches app/fixtures on the isolated test project's network.
numen_test_compose run --rm --no-deps -T \
    --volume "$numen_root/tests/integration:/journey:ro" \
    --volume "$numen_root/.numen/bootstrap-password:/run/secrets/journey-password:ro" \
    --entrypoint python app /journey/journey.py \
    --base-url http://app:8080 --fixture-url http://fixtures:8090 \
    --password-file /run/secrets/journey-password
printf '%s\n' 'Isolated journey stack remains at http://localhost:18788 for browser inspection.'
printf '%s\n' 'Stop it with: ./scripts/compose.sh -p asset-monitor-test -f compose.yaml -f compose.test.yaml down'
