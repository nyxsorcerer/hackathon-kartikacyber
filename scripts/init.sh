#!/bin/sh
set -eu
numen_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$numen_root"
# An existing .env keeps every line; only missing keys are appended (the release-2 ingress keys
# and NUMEN_SIGNING_KEY).
if [ -f .env ]; then
    numen_complete=1
    for numen_key in NUMEN_INGRESS_KEY NUMEN_SIGNING_KEY NUMEN_PUSH_DATABASE_PASSWORD NUMEN_AGENT_DATABASE_PASSWORD NUMEN_AGENT_TLS_KEY NUMEN_AGENT_TLS_PIN; do
        grep -q "^$numen_key=" .env || numen_complete=
    done
    if [ -n "$numen_complete" ]; then
        printf '%s\n' '.env already exists; existing credentials were preserved.'
        exit 0
    fi
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
import hashlib
import os
from pathlib import Path
import secrets
import subprocess

root = Path('/workspace')
environment = root / '.env'


def fernet_key():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


def openssl(*arguments, data=None):
    return subprocess.run(['openssl', *arguments], input=data, capture_output=True, check=True).stdout


def ingress_keys(present):
    """The release-2 keys missing from present (ADR-0006, B04). The TLS key and its pin stay a pair."""
    keys = {}
    # NUMEN_SIGNING_KEY encrypts the Dashboard key (B04); only the app gets it.
    for name in ('NUMEN_INGRESS_KEY', 'NUMEN_SIGNING_KEY'):
        if name not in present:
            keys[name] = fernet_key()
    for name in ('NUMEN_PUSH_DATABASE_PASSWORD', 'NUMEN_AGENT_DATABASE_PASSWORD'):
        if name not in present:
            keys[name] = secrets.token_urlsafe(32)
    key = present.get('NUMEN_AGENT_TLS_KEY')
    if key is None:
        if 'NUMEN_AGENT_TLS_PIN' in present:
            raise SystemExit('.env has NUMEN_AGENT_TLS_PIN but no NUMEN_AGENT_TLS_KEY. Restore the key, '
                             'or remove NUMEN_AGENT_TLS_PIN to make a new pair; nothing was changed.')
        # A P-256 key in DER PKCS#8, one line of standard base64.
        der = openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-outform', 'DER')
        key = keys['NUMEN_AGENT_TLS_KEY'] = base64.b64encode(der).decode()
    if 'NUMEN_AGENT_TLS_PIN' not in present:
        try:
            # The pin On-server agents require: the hex SHA-256 of the DER SubjectPublicKeyInfo.
            public = openssl('pkey', '-inform', 'DER', '-pubout', '-outform', 'DER',
                             data=base64.b64decode(key, validate=True))
        except (ValueError, subprocess.CalledProcessError):
            raise SystemExit('NUMEN_AGENT_TLS_KEY in .env is not a base64 DER key; nothing was changed.')
        keys['NUMEN_AGENT_TLS_PIN'] = hashlib.sha256(public).hexdigest()
    return keys


if environment.exists():
    text = environment.read_text()
    present = dict(line.split('=', 1) for line in text.splitlines() if '=' in line and not line.startswith('#'))
    added = ingress_keys(present)
    if added:
        with open(environment, 'a') as stream:
            if text and not text.endswith('\n'):
                stream.write('\n')
            for key, value in added.items():
                stream.write(f'{key}={value}\n')
        print('Added to .env: ' + ', '.join(added) + '. Existing lines were preserved.')
    else:
        print('.env already exists; existing credentials were preserved.')
    raise SystemExit
private = root / '.numen'
private.mkdir(mode=0o700, exist_ok=True)
os.chmod(private, 0o700)
password = secrets.token_urlsafe(24)
values = {
    'POSTGRES_PASSWORD': secrets.token_urlsafe(32),
    'NUMEN_SECRET_KEY': fernet_key(),
    'NUMEN_BROKER_TOKEN': secrets.token_urlsafe(32),
    'NUMEN_ADMIN_PASSWORD': password,
    'NUMEN_PORT': '8788',
    'NUMEN_DASHBOARD_URL': 'http://localhost:8788',
    **ingress_keys({}),
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
