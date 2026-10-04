#!/bin/sh
set -eu
umask 077
numen_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$numen_root"
numen_destination=${1:-.numen/backups/$(date -u +%Y%m%dT%H%M%SZ)}
if [ -e "$numen_destination" ]; then
    printf '%s\n' 'Backup destination already exists; choose a new directory.' >&2
    exit 1
fi
mkdir -p "$numen_destination"
numen_services=''
for numen_service in $(./scripts/compose.sh ps --services --status running); do
    case "$numen_service" in
        app|worker|scheduler) numen_services="$numen_services $numen_service" ;;
    esac
done
numen_resume() {
    if [ -n "$numen_services" ]; then
        # Values above are restricted to three literal service names.
        ./scripts/compose.sh start $numen_services >/dev/null
    fi
}
trap numen_resume EXIT INT TERM
if [ -n "$numen_services" ]; then
    ./scripts/compose.sh stop -t 30 $numen_services
fi
./scripts/compose.sh exec -T db pg_dump -U numen -d numen > "$numen_destination/database.sql"
./scripts/compose.sh run --rm --no-deps -T --entrypoint python app -c '
import sys
import tarfile
with tarfile.open(fileobj=sys.stdout.buffer, mode="w|gz") as archive:
    archive.add("/data/artifacts", arcname="artifacts")
' > "$numen_destination/artifacts.tar.gz"
cp .env "$numen_destination/deployment.env"
printf '%s\n' 'Numen consistent database/artifact/credential-key backup' > "$numen_destination/README.txt"
printf '%s\n' "Backup saved to $numen_destination. Keep this directory private."
