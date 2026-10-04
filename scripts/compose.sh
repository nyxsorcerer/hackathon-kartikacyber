#!/bin/sh
set -eu
numen_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$numen_root"
if command -v docker >/dev/null 2>&1; then
    numen_docker=$(command -v docker)
elif [ -x /Applications/Docker.app/Contents/Resources/bin/docker ]; then
    numen_docker=/Applications/Docker.app/Contents/Resources/bin/docker
else
    printf '%s\n' 'Docker CLI was not found. Install Docker Engine/Desktop and Docker Compose.' >&2
    exit 1
fi
numen_cli_path="$(dirname -- "$numen_docker"):${PATH}"
exec env "PATH=$numen_cli_path" "$numen_docker" compose "$@"
