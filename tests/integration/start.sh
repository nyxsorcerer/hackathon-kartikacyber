#!/bin/sh
set -eu
cd /fixtures
python -c 'import fixture_server; fixture_server.initialize_svn()'
if [ "${NUMEN_FIXTURE_SVN:-0}" = 1 ]; then
    svnserve --daemon --foreground --root /tmp/numen-fixture-svn/repo --listen-port 3690 &
    numen_svn_pid=$!
    trap 'kill "$numen_svn_pid" 2>/dev/null || true' EXIT INT TERM
fi
python /fixtures/fixture_server.py &
numen_http_pid=$!
trap 'kill "$numen_http_pid" "${numen_svn_pid:-}" 2>/dev/null || true' EXIT INT TERM
wait "$numen_http_pid"
