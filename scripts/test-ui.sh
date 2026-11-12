#!/bin/sh
set -eu
numen_case=${1:-all}
case "$numen_case" in
    all|register-application|review-decision) ;;
    *) printf '%s\n' "Unknown UI case: $numen_case" >&2; exit 2 ;;
esac
numen_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$numen_root"
exec ./scripts/compose.sh --profile test run --build --no-deps --rm frontend-tests
