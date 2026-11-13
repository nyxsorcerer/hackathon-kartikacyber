"""Controlled source/target/webhook fixture for the Docker operator journey.

This standalone stdlib service provides real HTTP boundaries. It has no provider
credentials and is deployed only by the test override. Fixture data and control
tokens are intentionally public test inputs, never production monitoring data.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
import io
import json
import os
import re
from pathlib import Path
import subprocess
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class FixtureState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.generation = 0
        self.version = '1.2.0'
        self.score = 7.0
        self.modified_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec='milliseconds')
        self.notifications: list[dict] = []
        self.requests: list[str] = []
        # The Remediation PR GitHub API (A08): what was written, never a header value.
        self.writes: list[dict] = []
        self.refs: dict[str, str] = {}
        self.commits: dict[str, dict] = {}
        self.pulls: list[dict] = []


STATE = FixtureState()
BASE_SHA = 'a' * 40
FIX_SHA = 'b' * 40
OLD_DATED_SHA = 'c' * 40
SHARED_ASSET = b'/* fixture shared distributed asset */\nwindow.fixture=true;\n'
SVN_ROOT = Path('/tmp/numen-fixture-svn')


def initialize_svn() -> None:
    """Create a real local SVN repository without external source access."""
    if os.environ.get('NUMEN_FIXTURE_SVN') != '1':
        return
    repository = SVN_ROOT / 'repo'
    seed = SVN_ROOT / 'seed' / 'fixture-plugin' / 'trunk'
    checkout = SVN_ROOT / 'checkout'
    seed.mkdir(parents=True, exist_ok=True)
    if not repository.exists():
        subprocess.run(['svnadmin', 'create', str(repository)], check=True, capture_output=True)
        (seed / 'fixture-plugin.php').write_text('<?php\n/* Plugin Name: Fixture Plugin\nVersion: 1.2.0 */\nfunction private_metadata($request) { return $request["data"]; }\n')
        (seed / 'readme.txt').write_text('=== Fixture Plugin ===\nStable tag: 1.2.0\n')
        subprocess.run(['svn', 'import', str(SVN_ROOT / 'seed'), repository.as_uri(), '-m', 'Initial fixture release', '--non-interactive'], check=True, capture_output=True)
    if not checkout.exists():
        subprocess.run(['svn', 'checkout', repository.as_uri() + '/fixture-plugin/trunk', str(checkout), '--non-interactive'], check=True, capture_output=True)


def advance_svn(version: str) -> None:
    if os.environ.get('NUMEN_FIXTURE_SVN') != '1':
        return
    checkout = SVN_ROOT / 'checkout'
    revision = int(subprocess.run(['svnlook', 'youngest', str(SVN_ROOT / 'repo')], check=True, capture_output=True, text=True).stdout.strip()) + 1
    (checkout / 'fixture-plugin.php').write_text(f'<?php\n/* Plugin Name: Fixture Plugin\nVersion: {version} */\nfunction private_metadata($request) {{ if (empty($request["operator"])) {{ return null; }} return $request["data"]; }}\n/* Fixture source event {revision} */\n')
    (checkout / 'readme.txt').write_text(f'=== Fixture Plugin ===\nStable tag: {version}\n')
    subprocess.run(['svn', 'commit', str(checkout), '-m', 'Validate access before returning private metadata', '--non-interactive'], check=True, capture_output=True)


def commit(sha: str) -> dict:
    descriptions = {
        BASE_SHA: ('Initial fixture release', '2026-09-20T00:00:00Z', []),
        FIX_SHA: ('Validate access before returning private metadata', '2026-10-01T00:00:00Z', [BASE_SHA, OLD_DATED_SHA]),
        OLD_DATED_SHA: ('Old branch change merged after the baseline', '2026-08-01T00:00:00Z', [BASE_SHA]),
    }
    message, date, parents = descriptions[sha]
    return {
        'sha': sha,
        'html_url': f'https://github.com/numen/fixture/commit/{sha}',
        'url': f'/repos/numen/fixture/commits/{sha}',
        'commit': {
            'message': message,
            'author': {'name': 'Fixture Maintainer', 'email': 'fixture@example.invalid', 'date': date},
            'committer': {'name': 'Fixture Maintainer', 'date': date},
        },
        'parents': [{'sha': parent} for parent in parents],
        'files': [{
            'filename': 'app.py',
            'status': 'modified' if parents else 'added',
            'additions': 2,
            'deletions': 1 if parents else 0,
            'patch': '@@ -1 +1,3 @@\n-return request.data\n+if not authorized(request):\n+    return forbidden()\n+return request.data',
        }],
        'stats': {'additions': 2, 'deletions': 1, 'total': 3},
    }


def source_files(sha: str) -> dict[str, bytes]:
    return {
        'app.py': b'def authorized(request):\n    return request.get("operator", False)\n\ndef metadata(request):\n    return request.get("data", {})\n',
        'README.md': b'# Fixture application\nPinned controlled source for Numen tests.\n',
        'assets/app.js': SHARED_ASSET,
        'VERSION': b'1.2.0\n' if sha == BASE_SHA else b'1.2.1\n',
    }


def git_sha(value: object) -> str:
    """A blob's git object id, as GitHub lists it; a JSON body's stand-in id otherwise."""
    if isinstance(value, bytes):
        return hashlib.sha1(b'blob %d\0' % len(value) + value).hexdigest()
    return hashlib.sha1(json.dumps(value, sort_keys=True).encode()).hexdigest()


def archive(sha: str) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as bundle:
        for path, content in source_files(sha).items():
            entry = tarfile.TarInfo(f'numen-fixture-{sha[:7]}/{path}')
            entry.size = len(content)
            entry.mode = 0o644
            entry.mtime = 0
            bundle.addfile(entry, io.BytesIO(content))
    return output.getvalue()


def cve_records() -> dict:
    with STATE.lock:
        score = STATE.score
        modified_at = STATE.modified_at
    metrics = {
        'cvssMetricV31': [{
            'source': 'fixture@example.invalid', 'type': 'Primary',
            'cvssData': {'version': '3.1', 'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', 'baseScore': score, 'baseSeverity': 'HIGH'},
        }],
        'cvssMetricV40': [{
            'source': 'fixture@example.invalid', 'type': 'Primary',
            'cvssData': {'version': '4.0', 'vectorString': 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N', 'baseScore': score, 'baseSeverity': 'HIGH'},
        }],
    }
    return {
        'resultsPerPage': 2, 'startIndex': 0, 'totalResults': 2, 'format': 'NVD_CVE', 'version': '2.0',
        'timestamp': '2026-10-03T00:00:00.000',
        'vulnerabilities': [
            {'cve': {
                'id': 'CVE-2026-99001', 'sourceIdentifier': 'fixture@example.invalid',
                'published': '2026-10-01T00:00:00.000',
                'lastModified': modified_at,
                'vulnStatus': 'Analyzed',
                'descriptions': [{'lang': 'en', 'value': 'Numen Fixture application exposes private metadata before version 1.2.1.'}],
                'metrics': metrics,
                'references': [{'url': 'https://github.com/numen/fixture', 'source': 'fixture@example.invalid', 'tags': ['Vendor Advisory']}],
                'configurations': [{'nodes': [{'operator': 'OR', 'negate': False, 'cpeMatch': [{
                    'vulnerable': True, 'criteria': 'cpe:2.3:a:numen:fixture:*:*:*:*:*:*:*:*',
                    'versionEndExcluding': '1.2.1', 'matchCriteriaId': '00000000-0000-4000-8000-000000000001',
                }]}]}],
            }},
            {'cve': {
                'id': 'CVE-2026-99002', 'sourceIdentifier': 'fixture@example.invalid',
                'published': '2026-10-01T00:00:00.000', 'lastModified': '2026-10-01T00:00:00.000',
                'vulnStatus': 'Awaiting Analysis',
                'descriptions': [{'lang': 'en', 'value': 'Numen Fixture unscored record for the analysis gate.'}],
                'metrics': {}, 'references': [{'url': 'https://github.com/numen/fixture'}],
            }},
        ],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = 'NumenTestFixture/1'

    def log_message(self, format: str, *args: object) -> None:
        # Test request paths are recorded without authorization/header values.
        return

    def send(self, status: int, body: bytes, content_type: str = 'application/json', headers: dict | None = None) -> None:
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def json(self, data: object, status: int = 200) -> None:
        self.send(status, json.dumps(data).encode())

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/') or '/'
        # Repositories outlive a journey run, so each run links its own numen/fixture-<run>.
        path = re.sub(r'^/repos/numen/fixture-[0-9a-f]+(?=/|$)', '/repos/numen/fixture', path)
        query = parse_qs(parsed.query)
        with STATE.lock:
            STATE.requests.append(path)
            generation = STATE.generation
            version = STATE.version
        if path == '/health':
            return self.json({'ok': True})
        if path == '/admin/state':
            with STATE.lock:
                return self.json({'generation': STATE.generation, 'version': STATE.version, 'score': STATE.score, 'notifications': STATE.notifications, 'requests': STATE.requests, 'pulls': STATE.pulls, 'writes': STATE.writes})
        if path in ('/target', '/'):
            return self.send(200, f'<html><head><meta name="generator" content="Numen Fixture {version}"></head><body><script src="/assets/app.js"></script></body></html>'.encode(), 'text/html', {'X-Product-Version': version})
        if path == '/assets/app.js':
            return self.send(200, SHARED_ASSET, 'application/javascript')
        if path == '/readme.txt':
            return self.send(200, f'=== Numen Fixture ===\nStable tag: {version}\n'.encode(), 'text/plain')
        if path == '/fingerprints':
            return self.json({'sha256': hashlib.sha256(SHARED_ASSET).hexdigest(), 'versions': ['1.2.0', '1.2.1']})
        if path == '/repos/numen/fixture/commits':
            if int(query.get('page', ['1'])[0]) > 1:
                return self.json([])
            if query.get('sha') == [BASE_SHA]:
                revisions = [BASE_SHA]
            else:
                revisions = [BASE_SHA] if generation == 0 else [FIX_SHA, OLD_DATED_SHA, BASE_SHA]
            body = json.dumps([commit(sha) for sha in revisions]).encode()
            etag = '"' + hashlib.sha256(body).hexdigest()[:16] + '"'
            if self.headers.get('If-None-Match') == etag:
                return self.send(304, b'', headers={'ETag': etag})
            return self.send(200, body, headers={'ETag': etag})
        if path.startswith('/repos/numen/fixture/commits/'):
            sha = path.rsplit('/', 1)[1]
            if sha in (BASE_SHA, FIX_SHA, OLD_DATED_SHA):
                return self.json(commit(sha))
        if path == '/repos/numen/fixture':
            return self.json({'full_name': 'numen/fixture', 'default_branch': 'main'})
        if path == '/repos/numen/fixture/git/ref/heads/main':
            sha = BASE_SHA if generation == 0 else FIX_SHA
            return self.json({'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': sha}})
        if path.startswith('/repos/numen/fixture/git/ref/heads/'):
            ref = path.removeprefix('/repos/numen/fixture/git/ref/')
            with STATE.lock:
                sha = STATE.refs.get(ref)
            if sha:
                return self.json({'ref': f'refs/{ref}', 'object': {'type': 'commit', 'sha': sha}})
        # A seeded commit's tree shares its sha and holds its archive's files.
        if path.startswith('/repos/numen/fixture/git/commits/'):
            sha = path.rsplit('/', 1)[1]
            if sha in (BASE_SHA, FIX_SHA, OLD_DATED_SHA):
                seeded = commit(sha)
                return self.json({'sha': sha, 'tree': {'sha': sha}, 'message': seeded['commit']['message'], 'parents': seeded['parents']})
            with STATE.lock:
                created = STATE.commits.get(sha)
            if created:
                return self.json(created)
        if path.startswith('/repos/numen/fixture/git/trees/'):
            sha = path.rsplit('/', 1)[1]
            if sha in (BASE_SHA, FIX_SHA, OLD_DATED_SHA):
                entries = [{'path': name, 'mode': '100644', 'type': 'blob', 'sha': git_sha(content)} for name, content in source_files(sha).items()]
                return self.json({'sha': sha, 'tree': entries, 'truncated': False})
        if path == '/repos/numen/fixture/pulls':
            with STATE.lock:
                return self.json([pull for pull in STATE.pulls if 'numen:' + pull['head']['ref'] in query.get('head', [])])
        if path.startswith('/repos/numen/fixture/pulls/'):
            number = int(path.rsplit('/', 1)[1])
            with STATE.lock:
                if 0 < number <= len(STATE.pulls):
                    return self.json(STATE.pulls[number - 1])
        if path.startswith('/repos/numen/fixture/compare/'):
            comparison = path.rsplit('/', 1)[1].split('...', 1)
            identical = len(comparison) == 2 and comparison[0] == comparison[1]
            revisions = [] if identical or int(query.get('page', ['1'])[0]) > 1 else [OLD_DATED_SHA, FIX_SHA]
            return self.json({'status': 'identical' if identical else 'ahead', 'ahead_by': 0 if identical else 2, 'total_commits': 0 if identical else 2, 'commits': [commit(sha) for sha in revisions], 'files': commit(FIX_SHA)['files']})
        if '/tarball/' in path or '/archive/' in path:
            sha = BASE_SHA if BASE_SHA in path else FIX_SHA
            return self.send(200, archive(sha), 'application/gzip')
        if path in ('/rest/json/cves/2.0', '/cves'):
            if int(query.get('startIndex', ['0'])[0]) > 0:
                result = cve_records()
                result['vulnerabilities'] = []
                return self.json(result)
            return self.json(cve_records())
        return self.json({'message': 'Fixture route not found', 'path': path}, 404)

    def do_POST(self) -> None:
        original = urlparse(self.path).path.rstrip('/')
        path = re.sub(r'^/repos/numen/fixture-[0-9a-f]+(?=/|$)', '/repos/numen/fixture', original)
        length = int(self.headers.get('Content-Length', '0'))
        if length > 1_000_000:
            return self.json({'message': 'Fixture request too large'}, 413)
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw) if raw else {}
        except ValueError:
            return self.json({'message': 'Invalid JSON'}, 400)
        if path == '/admin/advance':
            with STATE.lock:
                STATE.generation += 1
                STATE.version = str(data.get('version', STATE.version))
                STATE.score = float(data.get('score', STATE.score))
                STATE.modified_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec='milliseconds')
                generation = STATE.generation
                version = STATE.version
            advance_svn(version)
            return self.json({'generation': generation})
        if path == '/admin/reset':
            with STATE.lock:
                STATE.generation = 0
                STATE.version = '1.2.0'
                STATE.score = 7.0
                STATE.modified_at = datetime.now(timezone.utc).replace(tzinfo=None).isoformat(timespec='milliseconds')
                STATE.notifications.clear()
                STATE.requests.clear()
                STATE.writes.clear()
                STATE.refs.clear()
                STATE.commits.clear()
                STATE.pulls.clear()
            return self.json({'ok': True})
        if path.startswith('/repos/numen/fixture/'):
            return self.github_write(original, path.removeprefix('/repos/numen/fixture'), data)
        if path.startswith('/webhooks/') or path.startswith('/api/webhooks/'):
            with STATE.lock:
                STATE.notifications.append(data)
                message_id = str(len(STATE.notifications))
            return self.json({'id': message_id, 'channel_id': 'fixture', 'content': data.get('content', '')})
        return self.json({'message': 'Fixture route not found'}, 404)

    def github_write(self, original: str, path: str, data: dict) -> None:
        """The git data and pull request writes of a Remediation PR (A08), kept in memory."""
        with STATE.lock:
            STATE.writes.append({'method': 'POST', 'path': original})
            if path in ('/git/blobs', '/git/trees'):
                return self.json({'sha': git_sha(data)}, 201)
            if path == '/git/commits':
                sha = git_sha(data)
                STATE.commits[sha] = {'sha': sha, 'tree': {'sha': data['tree']}, 'message': data['message'], 'parents': [{'sha': p} for p in data['parents']]}
                return self.json(STATE.commits[sha], 201)
            if path == '/git/refs':
                ref = data['ref'].removeprefix('refs/')
                if ref == 'heads/main' or ref in STATE.refs:
                    return self.json({'message': 'Reference already exists'}, 422)
                STATE.refs[ref] = data['sha']
                return self.json({'ref': data['ref'], 'object': {'type': 'commit', 'sha': data['sha']}}, 201)
            if path == '/pulls':
                head = STATE.refs.get('heads/' + data['head'])
                if not head:
                    return self.json({'message': 'Validation Failed'}, 422)
                number = len(STATE.pulls) + 1
                repo = original.removeprefix('/repos/').removesuffix('/pulls')
                STATE.pulls.append({
                    'number': number, 'html_url': f'https://github.com/{repo}/pull/{number}', 'state': 'open',
                    'draft': bool(data.get('draft')), 'title': data['title'], 'body': data['body'],
                    'head': {'ref': data['head'], 'sha': head}, 'base': {'ref': data['base']},
                    'merged': False, 'merge_commit_sha': None,
                })
                return self.json(STATE.pulls[-1], 201)
        return self.json({'message': 'Fixture route not found'}, 404)


if __name__ == '__main__':
    initialize_svn()
    ThreadingHTTPServer(('0.0.0.0', 8090), Handler).serve_forever()
