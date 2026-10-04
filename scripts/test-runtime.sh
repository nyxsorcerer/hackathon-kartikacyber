#!/bin/sh
set -eu
numen_case=${1:-all}
case "$numen_case" in
    all|execution-boundary|execution-recovery|version-recipe|finding-lab) ;;
    *) printf '%s\n' "Unknown runtime case: $numen_case" >&2; exit 2 ;;
esac
numen_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$numen_root"
# These share one engine fixture and bounded workload images. Run together so
# setup/cleanup and native sandbox evidence stay consistent.
exec ./scripts/compose.sh --profile test run --build --no-deps --rm runner-runtime-tests
