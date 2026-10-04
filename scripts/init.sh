#!/bin/sh
set -eu
numen_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$numen_root"
if [ -f .env ]; then
    printf '%s\n' '.env already exists; existing credentials were preserved.'
    exit 0
fi
if command -v docker >/dev/null 2>&1; then
    numen_docker=$(command -v docker)
elif [ -x /Applications/Docker.app/Contents/Resources/bin/docker ]; then
    numen_docker=/Applications/Docker.app/Contents/Resources/bin/docker
else
    printf '%s\n' 'Docker CLI was not found. Install Docker Engine/Desktop and Docker Compose.' >&2
    exit 1
fi
numen_bootstrap_image=${NUMEN_BOOTSTRAP_IMAGE:-python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c}
numen_cli_path="$(dirname -- "$numen_docker"):${PATH}"
env "PATH=$numen_cli_path" "$numen_docker" run --rm -i --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$numen_root,dst=/workspace" --workdir /workspace \
    "$numen_bootstrap_image" python - <<'PY'
import base64
import os
from pathlib import Path
import secrets

root = Path('/workspace')
environment = root / '.env'
if environment.exists():
    raise SystemExit('Existing .env was preserved.')
private = root / '.numen'
private.mkdir(mode=0o700, exist_ok=True)
os.chmod(private, 0o700)
password = secrets.token_urlsafe(24)
values = {
    'POSTGRES_PASSWORD': secrets.token_urlsafe(32),
    'NUMEN_SECRET_KEY': base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
    'NUMEN_BROKER_TOKEN': secrets.token_urlsafe(32),
    'NUMEN_ADMIN_PASSWORD': password,
    'NUMEN_PORT': '8787',
    'NUMEN_DASHBOARD_URL': 'http://localhost:8787',
}
fd = os.open(environment, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as stream:
    stream.write('# Generated locally. Keep this file private and back it up securely.\n')
    for key, value in values.items():
        stream.write(f'{key}={value}\n')
password_file = private / 'bootstrap-password'
fd = os.open(password_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as stream:
    stream.write(password + '\n')
print('Created protected .env and .numen/bootstrap-password. Operator username: admin.')
print('Read the initial password locally with: cat .numen/bootstrap-password')
PY
