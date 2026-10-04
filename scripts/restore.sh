#!/bin/sh
set -eu
umask 077
if [ "$#" -ne 1 ]; then
    printf '%s\n' 'Usage: ./scripts/restore.sh <Numen backup directory>' >&2
    exit 2
fi
numen_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
numen_backup=$(CDPATH= cd -- "$1" && pwd)
cd "$numen_root"
for numen_file in database.sql artifacts.tar.gz deployment.env README.txt; do
    if [ ! -f "$numen_backup/$numen_file" ] || [ -L "$numen_backup/$numen_file" ]; then
        printf '%s\n' "Backup is missing a regular $numen_file file." >&2
        exit 1
    fi
done
# Validate matching database credentials before changing data. For a fresh
# deployment, copy deployment.env to .env before starting its empty DB volume.
./scripts/compose.sh run --rm --no-deps -T \
    --volume "$numen_root/.env:/tmp/numen-current.env:ro" \
    --volume "$numen_backup/deployment.env:/tmp/numen-backup.env:ro" \
    --entrypoint python app -c '
from dotenv import dotenv_values
current = dotenv_values("/tmp/numen-current.env", interpolate=False)
backup = dotenv_values("/tmp/numen-backup.env", interpolate=False)
if current.get("POSTGRES_PASSWORD") != backup.get("POSTGRES_PASSWORD"):
    raise SystemExit("Database credentials differ. Use this backup deployment.env in a fresh Numen project/database volume.")
if not backup.get("NUMEN_SECRET_KEY") or not backup.get("NUMEN_BROKER_TOKEN"):
    raise SystemExit("Backup credential keys are missing.")
'
numen_services=''
for numen_service in $(./scripts/compose.sh ps --services --status running); do
    case "$numen_service" in
        app|worker|scheduler|runner-broker) numen_services="$numen_services $numen_service" ;;
    esac
done
numen_resume() {
    if [ -n "$numen_services" ]; then
        ./scripts/compose.sh up -d --wait $numen_services >/dev/null
    fi
}
trap numen_resume EXIT INT TERM
if [ -n "$numen_services" ]; then
    ./scripts/compose.sh stop -t 30 $numen_services
fi
./scripts/compose.sh exec -T db psql -v ON_ERROR_STOP=1 -U numen -d numen \
    -c 'DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION numen;' >/dev/null
./scripts/compose.sh exec -T db psql -v ON_ERROR_STOP=1 -U numen -d numen \
    < "$numen_backup/database.sql" >/dev/null
./scripts/compose.sh run --rm --no-deps -T \
    --volume "$numen_backup/artifacts.tar.gz:/tmp/numen-artifacts.tar.gz:ro" \
    --entrypoint python app -c '
from pathlib import Path
import shutil
import tarfile
root = Path("/data/artifacts")
with tarfile.open("/tmp/numen-artifacts.tar.gz", "r:gz") as archive:
    members = archive.getmembers()
    for member in members:
        path = Path(member.name)
        if not path.parts or path.parts[0] != "artifacts" or ".." in path.parts or path.is_absolute() or member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
            raise SystemExit("Backup contains an unsafe artifact member.")
    for path in root.iterdir():
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
    archive.extractall("/data", members=members, filter="data")
'
cp "$numen_backup/deployment.env" .env
chmod 600 .env
printf '%s\n' 'Database, immutable artifacts, and credential keys restored. Use the operator password from this backup.'
