"""The demo dry run's broker (A16, brief 5(b)), test only: compose.demo-test.yaml runs it in place
of the runner-broker for app, worker and scheduler. It speaks the broker contract of
docs/implementation-contract.md (X-Broker-Token, /internal/runs, /internal/attempts, /health).

Only the agent decisions are replaced. A run of kind `agent` or `capabilities` is answered here at
once with a canned reply chosen by its operation and the prepared demo commit, served change or Server change it is
about, and is never forwarded: its credential reaches no provider and is never stored. Every report
says that no agent ran, the catalogue's model is named 'Canned dry run, no agent', and its session
read is refused, so no run has an Analysis Transcript. A login run is refused. Every other run (lab,
probe, detection_rule) and every read of one is forwarded unchanged to the real runner-broker, so
Labs, served-content fetches and yara run for real. GET /state lists what was canned and what was
forwarded.
"""

from __future__ import annotations

import base64
import difflib
import hashlib
import hmac
import io
import json
import os
import re
import sys
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fixture_server import CLICKFIX_HOST, DEMO_CONTENT, REACT_FIX
from journey import R2S_POC

TOKEN = os.environ['NUMEN_BROKER_TOKEN']
UPSTREAM = os.environ.get('NUMEN_UPSTREAM_BROKER_URL', 'http://runner-broker:8081').rstrip('/')
CANNED = 'Canned dry-run reply: no agent ran.'
MODEL = {'id': 'canned-dry-run-no-agent', 'name': 'Canned dry run, no agent', 'reasoning_efforts': ['high'],
         'default_effort': 'high'}
JUDOL_HOST = 'slot-gacor.test'


def subject(message: str) -> str:
    return message.strip().split('\n', 1)[0]


INVOICE, TELEMETRY = (subject((DEMO_CONTENT / 'shop' / name / 'MESSAGE').read_text())
                      for name in ('1-invoice-download', '3-install-telemetry'))
FIX = subject(REACT_FIX)

LAB_APP = {
    'vulnerable-app/Dockerfile': b'FROM asset-monitor-lab:0.1.0\nWORKDIR /app\nCOPY . /app/\nCMD ["node", "server.js"]\n',
    'vulnerable-app/compose.yaml': b'services:\n  app:\n    build: .\n    ports: ["127.0.0.1:18080:8080"]\n',
    'vulnerable-app/README.md': b'# Toko Batik shop\nThe Own repository at the vulnerable revision. Run docker compose up --build.\n',
}
# Step 1's Proof: the invoice download's path traversal reads the Lab container's own /etc/passwd.
TRAVERSAL_POC = (b'import os,sys,time,urllib.request\n'
                 b'for _ in range(50):\n'
                 b'    try:\n        body=urllib.request.urlopen(os.environ["TARGET_URL"]+"/invoices/..%2f..%2f..%2f..%2fetc%2fpasswd",timeout=1).read();break\n'
                 b'    except OSError:time.sleep(0.2)\n'
                 b'else:sys.exit("the application never answered")\n'
                 b'sys.exit(0 if b"root:" in body else 1)\n')
# Step 3's Detection rule: the loader's string array and its decoder call, in scripts/telemetry.js only.
LOADER_RULE = (b'rule demo_shop_install_loader\n{\n  strings:\n    $array = "var _0x3f1a=["\n'
               b'    $decoder = "_0x2e9b(_0x51c7)"\n  condition:\n    all of them\n}\n')
INVOICE_ANCHOR = '    const file = path.join(INVOICES, decodeURIComponent(invoice[1]));\n'
CONTAINMENT = '    if (!file.startsWith(INVOICES + path.sep)) return page(response, 404, "<p>No such invoice</p>");\n'


def report(title: str, text: str) -> bytes:
    return f'# {title}\n\n{CANNED}\n\n{text}\n'.encode()


def lock(revision: str, version: str) -> bytes:
    return json.dumps({'version': version, 'source_ref': revision, 'images': ['asset-monitor-lab:0.1.0']}).encode()


def verdict(name: str, title: str, path: str, **extra) -> dict:
    return {'verdict': name, 'confidence': 'high', 'title': title, 'summary': CANNED,
            'evidence': [{'path': path, 'detail': CANNED}], 'open_questions': [], 'before_after': CANNED,
            'affected_behavior': CANNED, **extra}


def commit_analysis(commit: dict, found: dict) -> tuple[dict, dict]:
    """The canned Verdict of a prepared demo commit (A16 steps 1, 3 and 4)."""
    name = subject(commit['message'])
    if name == INVOICE:
        title = 'Path traversal in the invoice download'
        return verdict('Vulnerability introduced', title, 'server.js', vulnerable_ref=commit['revision']), {
            'report.md': report(title, 'GET /invoices/<name> joins the decoded name onto invoices/ with no containment '
                                       'check, so ../ reads any file the process can read.'),
            'poc.py': TRAVERSAL_POC, **LAB_APP, 'vulnerable-app/application.lock.json': lock(commit['revision'], '1.0.0')}
    if name == TELEMETRY:
        title = 'Obfuscated postinstall loader'
        return verdict('Malicious change', title, 'scripts/telemetry.js', indicators={
            'files': ['package.json', 'scripts/telemetry.js'], 'hosts': [], 'urls': [],
            'commands': ['node scripts/telemetry.js']}, reachable_secrets=['NPM_TOKEN', 'GITHUB_TOKEN']), {
            'report.md': report(title, 'A postinstall hook runs an _0x string-array and base64 loader that names the npm '
                                       'publish token and the GitHub token.'),
            'detection-rule.yar': LOADER_RULE}
    if name == FIX:
        title = 'Server references resolved through inherited members'
        return verdict('Vulnerability fix', title, 'packages/react-server-dom-webpack/index.js',
                       vulnerable_ref=found['parent_revisions'][0], addresses=['GHSA-fv66-9v8q-g76r']), {
            'report.md': report(title, 'resolveServerReference now resolves only the manifest\'s own modules and exports.')}
    raise LookupError('no canned Verdict for this commit')


def served_analysis(content: dict) -> tuple[dict, dict]:
    """The canned Verdict of the demo PHP Application's served-content change: judol links or the
    ClickFix loader, told apart by the host the change added."""
    (host,) = [h for h in (JUDOL_HOST, CLICKFIX_HOST) if h in json.dumps(content['diff'])]
    kind, title = (('judol', 'Gambling links served only to Googlebot') if host == JUDOL_HOST
                   else ('clickfix', 'ClickFix loader on the checkout page'))
    rule = f'rule demo_{kind}\n{{\n  strings:\n    $host = "{host}"\n  condition:\n    $host\n}}\n'.encode()
    return {'verdict': 'Malicious change', 'confidence': 'high', 'title': title, 'summary': CANNED,
            'evidence': [{'path': content['page_url'], 'detail': CANNED}], 'open_questions': [],
            'indicators': {'files': [], 'hosts': [host], 'urls': [], 'commands': []}, 'reachable_secrets': []}, {
        'report.md': report(title, f'{content["page_url"]} serves {host} to {content["user_agent"]}.'),
        'detection-rule.yar': rule}


def server_analysis(listing: dict) -> tuple[dict, dict]:
    """The canned Verdict of the demo server's Server change (B06): the PHP file the change added is a
    Malicious change, named by its root and path. Its bytes are never run."""
    added = [f"{e['root']}/{e['path']}" for e in listing['diff']['added'] if e['path'].endswith('.php')]
    if not added:
        raise LookupError('no added PHP file in this Server change')
    title = 'A PHP shell dropped in an uploads folder'
    return {'verdict': 'Malicious change', 'confidence': 'high', 'title': title, 'summary': CANNED,
            'evidence': [{'path': 'server-files.json', 'detail': CANNED}], 'open_questions': [],
            'indicators': {'files': added, 'hosts': [], 'urls': [], 'commands': []}, 'reachable_secrets': []}, {
        'report.md': report(title, f'{", ".join(added)} appeared on {listing["agent"]} where only media belongs.')}


def patch(files: dict) -> tuple[dict, dict]:
    """Step 1's patch Remediation PR: the containment check, diffed against the Own head's server.js."""
    old = files['source/server.js'].decode()
    if INVOICE_ANCHOR not in old:
        raise LookupError('the Own head has no invoice download to patch')
    new = old.replace(INVOICE_ANCHOR, INVOICE_ANCHOR + CONTAINMENT)
    diff = ''.join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), 'a/server.js', 'b/server.js'))
    return {'summary': 'Refuse an invoice name that resolves outside invoices/. ' + CANNED}, {'patch.diff': diff.encode()}


def facts(prompt: str) -> dict:
    """The run's facts, which prompts.prompt appends to every prompt as JSON."""
    return json.loads(prompt.rsplit('\n\nFacts:\n', 1)[1])


def inputs(request: dict) -> dict[str, bytes]:
    files = {}
    for item in request.get('inputs') or []:
        data = base64.b64decode(item['content_base64'])
        if item.get('archive'):
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
                files.update({f'{item["path"]}/{member.name}': archive.extractfile(member).read()
                              for member in archive if member.isfile()})
        else:
            files[item['path']] = data
    return files


def reply(request: dict) -> tuple[dict, dict]:
    """(result, outputs) of a canned run, by its operation (served Triage and served Analysis run on
    the commit operations' tool profiles)."""
    if request['kind'] == 'capabilities':
        return {'models': [MODEL]}, {}
    operation, found, files = request['profile'].get('operation'), facts(request['prompt']), inputs(request)
    if operation == 'commit_triage':
        # A served-content or Server change has no commit: check for them before reading one.
        flagged = ('page_url' in found or 'server_change' in found
                   or subject(found['commit']['message']) in (INVOICE, TELEMETRY, FIX))
        decision = {'decision': 'security_candidate' if flagged else 'unrelated',
                    'title': 'Canned dry run: ' + ('a security candidate' if flagged else 'unrelated'), 'reason': CANNED}
        return {'reply': json.dumps(decision)}, {}
    if operation == 'commit_analysis' and 'served-content.json' in files:
        return served_analysis(json.loads(files['served-content.json']))
    if operation == 'commit_analysis' and 'server-files.json' in files:
        return server_analysis(json.loads(files['server-files.json']))
    if operation == 'commit_analysis':
        return commit_analysis(json.loads(files['commit.json']), found)
    if operation == 'patch_drafting':
        return patch(files)
    if operation == 'finding_artifacts':
        # The n-day Proof of step 4 on the Own head with the Locked version installed (own_head).
        return {'summary': CANNED}, {
            'poc.py': R2S_POC, 'report.md': report('React2Shell n-day Proof', 'An action whose server reference names an '
                                                   'inherited manifest member is answered with the stand-in\'s marker.'),
            **LAB_APP, 'vulnerable-app/application.lock.json': lock(found['source_ref'], '19.0.0')}
    raise LookupError(f'no canned reply for operation {operation!r}')


def canned_run(request: dict) -> dict:
    """The finished run of `request`, keyed by its attempt token. A run with no canned reply fails,
    naming why, so a dry run never passes on a decision nobody wrote."""
    run = {'run_id': request['attempt_token'], 'status': 'succeeded', 'progress': 100, 'events': []}
    try:
        result, outputs = reply(request)
    except Exception as error:  # the job fails with this message
        print(f"canned-broker: no canned reply: {error!r}", file=sys.stderr)
        return {**run, 'status': 'failed', 'error': {'code': 'no_canned_reply', 'message': f'Canned dry run: {error}'}}
    return {**run, 'result': result, 'outputs': [
        {'path': path, 'content_base64': base64.b64encode(data).decode(), 'size': len(data),
         'sha256': hashlib.sha256(data).hexdigest()} for path, data in outputs.items()]}


class State:
    lock = threading.Lock()
    runs: dict[str, dict] = {}  # attempt token: canned run
    canned: list[dict] = []
    forwarded: list[str] = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:  # request lines only, never bodies
        sys.stderr.write('canned-broker: ' + (args[0] % args[1:]) + '\n')

    def send(self, status: int, body: bytes = b'', content_type: str = 'application/json') -> None:
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def json(self, status: int, value) -> None:
        self.send(status, json.dumps(value).encode())

    def forward(self, method: str, body: bytes) -> None:
        headers = {name: value for name, value in self.headers.items() if name.lower() in ('x-broker-token', 'content-type')}
        request = Request(UPSTREAM + self.path, data=body if method != 'GET' else None, headers=headers, method=method)
        try:
            response = urlopen(request, timeout=900)
        except HTTPError as error:
            response = error
        except (URLError, OSError):
            return self.json(503, {'code': 'broker_unavailable', 'message': 'The runner-broker is unavailable'})
        with response:
            self.send(response.status, response.read(), response.headers.get('Content-Type', 'application/json'))

    def route(self, method: str) -> None:
        body = self.rfile.read(int(self.headers.get('Content-Length') or 0))
        if self.path == '/health':
            return self.forward(method, body)
        if not hmac.compare_digest(self.headers.get('X-Broker-Token', '').encode(), TOKEN.encode()):
            return self.json(401, {'detail': 'invalid broker token'})
        if (method, self.path) == ('GET', '/state'):
            with State.lock:
                return self.json(200, {'canned': State.canned, 'forwarded': State.forwarded})
        if (method, self.path) == ('POST', '/internal/runs'):
            request = json.loads(body)
            kind = request.get('kind')
            if kind == 'account_login':
                return self.json(422, {'code': 'login_refused', 'message': 'The canned dry run signs in to no provider'})
            if kind not in ('agent', 'capabilities'):
                with State.lock:
                    State.forwarded.append(kind)
                return self.forward(method, body)
            with State.lock:
                if request['attempt_token'] not in State.runs:
                    State.runs[request['attempt_token']] = canned_run(request)
                    State.canned.append({'kind': kind, 'operation': (request.get('profile') or {}).get('operation')})
                run = State.runs[request['attempt_token']]
            return self.json(202, {'run_id': run['run_id'], 'status': run['status']})
        match = re.fullmatch(r'/internal/(runs|attempts)/([^/?]+)(/[a-z-]+)?', self.path)
        run = State.runs.get(match[2]) if match else None
        if run is None:
            return self.forward(method, body)
        part = match[3] or ''
        if match[1] == 'attempts':
            return self.json(200, {'run_id': run['run_id'], 'status': run['status'], 'reconciled': True})
        if part in ('', '/cancel'):
            return self.json(200, run)
        if part == '/outputs':
            return self.json(200, {'outputs': run.get('outputs', [])})
        if part == '/session':
            return self.json(409, {'detail': 'Canned dry run: no agent ran, so the run has no session'})
        if part == '/credential' and method == 'DELETE':
            return self.send(204)
        if part == '/credential':
            return self.json(404, {'detail': 'credential unavailable or expired'})
        return self.json(409, {'detail': 'run is not waiting for login input'})

    def do_GET(self) -> None:
        self.route('GET')

    def do_POST(self) -> None:
        self.route('POST')

    def do_DELETE(self) -> None:
        self.route('DELETE')


def check() -> None:
    """python canned_broker.py check: each prepared change gets its intended canned decision."""
    def run(operation, prompt_facts, files=None, kind='agent'):
        listed = [{'path': p, 'content_base64': base64.b64encode(d).decode()} for p, d in (files or {}).items()]
        return canned_run({'attempt_token': 't', 'kind': kind, 'profile': {'operation': operation},
                           'prompt': 'Template\n\nFacts:\n' + json.dumps(prompt_facts), 'inputs': listed})

    def triage(message):
        return json.loads(run('commit_triage', {'commit': {'message': message}})['result']['reply'])['decision']

    assert [triage(m) for m in (INVOICE + '\n\nbody', TELEMETRY, REACT_FIX, 'Release 19.0.1', 'GarudaNetra patch of abc1234 (#1)')] == [
        'security_candidate'] * 3 + ['unrelated'] * 2
    assert json.loads(run('commit_triage', {'page_url': 'http://toko-batik.test:8090/served/'})['result']['reply'])['decision'] == 'security_candidate'
    shop = DEMO_CONTENT / 'shop'
    commit = {'commit.json': json.dumps({'message': INVOICE, 'revision': 'a' * 40}).encode()}
    assert run('commit_analysis', {}, commit)['result']['vulnerable_ref'] == 'a' * 40
    source = io.BytesIO()
    with tarfile.open(fileobj=source, mode='w:gz') as archive:
        data = (shop / '1-invoice-download' / 'server.js').read_bytes()
        info = tarfile.TarInfo('server.js')
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    drafted = canned_run({'attempt_token': 't', 'kind': 'agent', 'profile': {'operation': 'patch_drafting'},
                          'prompt': '\n\nFacts:\n{}', 'inputs': [
                              {'path': 'source', 'content_base64': base64.b64encode(source.getvalue()).decode(), 'archive': True}]})
    diff = base64.b64decode(drafted['outputs'][0]['content_base64']).decode()
    assert diff.startswith('--- a/server.js\n+++ b/server.js\n') and '+' + CONTAINMENT in diff, diff
    fix = run('commit_analysis', {'parent_revisions': ['b' * 40]}, {'commit.json': json.dumps({'message': REACT_FIX}).encode()})
    assert (fix['result']['verdict'], fix['result']['vulnerable_ref'], fix['result']['addresses']) == (
        'Vulnerability fix', 'b' * 40, ['GHSA-fv66-9v8q-g76r'])
    served = {'page_url': 'p', 'user_agent': 'browser', 'diff': {'script_hosts': {'added': [CLICKFIX_HOST]}}}
    assert run('commit_analysis', {}, {'served-content.json': json.dumps(served).encode()})['result']['indicators']['hosts'] == [CLICKFIX_HOST]
    assert run('commit_analysis', {}, {'commit.json': json.dumps({'message': 'Release 19.0.1'}).encode()})['status'] == 'failed'
    assert json.loads(run('commit_triage', {'server_change': {'added': []}})['result']['reply'])['decision'] == 'security_candidate'
    listing = {'agent': 'Demo server', 'diff': {'added': [{'root': '/var/www/html', 'path': 'wp-content/uploads/cache.php'},
                                                          {'root': '/var/www/html', 'path': 'logo.png'}]}}
    shell = run('commit_analysis', {}, {'server-files.json': json.dumps(listing).encode()})
    assert (shell['result']['verdict'], shell['result']['indicators']['files'], [o['path'] for o in shell['outputs']]) == (
        'Malicious change', ['/var/www/html/wp-content/uploads/cache.php'], ['report.md'])
    assert run(None, {}, kind='capabilities')['result'] == {'models': [MODEL]}
    print('CANNED BROKER CHECK PASSED')


if __name__ == '__main__':
    if sys.argv[1:] == ['check']:
        check()
    else:
        ThreadingHTTPServer(('0.0.0.0', 8081), Handler).serve_forever()
