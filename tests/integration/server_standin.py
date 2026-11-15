"""The stand-in server (B04) of compose.test.yaml: the real On-server agent binary, run as the
Operator runs it on a server.

It waits for an enroll drop, /standin/drop/enroll-<n>.json, that the fixture's POST
/admin/server/enroll writes. It runs `asset-monitor-agent enroll` from it with an argv list (no
shell) and the Enrollment code on standard input only, and writes the run's exit status and output
to result-<n>.json, which the fixture's /admin/state shows. After a successful Enrollment it keeps
`asset-monitor-agent run` running, as the systemd unit would, against the fixture web root.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

DROP = Path('/standin/drop')
WEB_ROOT = Path('/var/www/html')
CONFIG = Path('/etc/asset-monitor-agent/config.json')
STATE = Path('/var/lib/asset-monitor-agent/state.json')
AGENT = '/usr/local/bin/asset-monitor-agent'
FIELDS = ('url', 'tls_pin', 'dashboard_key', 'key_id', 'agent_id', 'code')


def write(path: Path, data: dict) -> None:
    temporary = path.with_name(f'.{path.name}.tmp')
    temporary.write_text(json.dumps(data))
    os.replace(temporary, path)


def enroll(drop: Path) -> dict:
    values = json.loads(drop.read_text())
    if not all(isinstance(values.get(field), str) for field in FIELDS):
        return {'returncode': None, 'stdout': '', 'stderr': 'the drop lacks a field'}
    argv = [AGENT, 'enroll', '--url', values['url'], '--tls-pin', values['tls_pin'],
            '--dashboard-key', values['dashboard_key'], '--key-id', values['key_id'],
            '--agent-id', values['agent_id'], '--allow', str(WEB_ROOT), '--unit-dir', '/tmp/unit']
    try:
        run = subprocess.run(argv, input=values['code'] + '\n', capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        return {'returncode': None, 'stdout': '', 'stderr': 'enroll timed out'}
    return {'returncode': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr}


def main() -> None:
    DROP.mkdir(parents=True, exist_ok=True)
    if not any(WEB_ROOT.iterdir()):
        # B05: a small site. wp-config.php is on the secret list: reported by hash only.
        (WEB_ROOT / 'index.php').write_text("<?php echo 'Toko Batik Sari';\n")
        (WEB_ROOT / 'style.css').write_text('body { font-family: serif; }\n')
        (WEB_ROOT / 'wp-config.php').write_text("<?php define('DB_PASSWORD', 'stand-in-not-a-secret');\n")
    agent = None
    while True:
        for drop in sorted(DROP.glob('enroll-*.json'), key=lambda path: int(path.stem.split('-', 1)[1])):
            result = DROP / drop.name.replace('enroll-', 'result-')
            if result.exists():
                continue
            outcome = enroll(drop)
            write(result, outcome)
            if outcome['returncode'] == 0:
                if agent:
                    agent.terminate()
                    agent.wait()
                    agent = None
                # A new Enrollment is a new agent id, whose sequences start again at 1.
                # ponytail: a real re-enrolled server keeps state.json; the agent should reset it.
                STATE.unlink(missing_ok=True)
        if (agent is None or agent.poll() is not None) and CONFIG.exists():
            agent = subprocess.Popen([AGENT, 'run'])
        time.sleep(1)


if __name__ == '__main__':
    main()
