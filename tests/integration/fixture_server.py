"""Controlled source/target/webhook fixture for the Docker operator journey.

This standalone stdlib service provides real HTTP boundaries. It has no provider
credentials and is deployed only by the test override. Fixture data and control
tokens are intentionally public test inputs, never production monitoring data.

In demo mode (NUMEN_FIXTURE_DEMO=1, A16) it also hosts the demo stand-ins: the demo Own repository
and a stand-in React Upstream repository as real git repositories behind the GitHub API, and the
stand-in advisories, published one demo step at a time. `python fixture_server.py check` is its
self-check.

It also hosts the GitHub push stand-in (B02), numen/push-app-<run>, which sends signed Push
deliveries to ingress-push over the test overlay's stand-ins network.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
from datetime import datetime, timezone
import io
import json
import os
import re
import secrets
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import parse_qs, quote, unquote, urlparse
from urllib.request import Request, urlopen

DEMO = os.environ.get('NUMEN_FIXTURE_DEMO') == '1'


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
        # The Served-content fixture (A10): the variants served and each /served request's user agent.
        self.served_variants: set[str] = set()
        self.served_requests: list[dict] = []
        # The demo stand-ins (A16): the stand-in advisories published so far (outside demo mode
        # node2shell always is, as the journey's Advisory check expects), and each demo repository's
        # pull requests.
        self.published: set[str] = set() if DEMO else {'node2shell'}
        self.demo_pulls: dict[str, list[dict]] = {}
        # The GitHub push stand-in (B02): each numen/push-app-<run>'s commits, newest first, the hooks
        # registered on them, and every delivery sent, by delivery id.
        self.push_repos: dict[str, list[dict]] = {}
        self.hooks: list[dict] = []
        self.deliveries: dict[str, dict] = {}


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


def tar_gz(files: dict[str, bytes]) -> bytes:
    """The same gzipped tarball bytes on every call, so a registry integrity stays valid."""
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as bundle:
        for path, content in files.items():
            entry = tarfile.TarInfo(path)
            entry.size = len(content)
            entry.mode = 0o644
            entry.mtime = 0
            bundle.addfile(entry, io.BytesIO(content))
    return gzip.compress(output.getvalue(), mtime=0)


def archive(sha: str) -> bytes:
    return tar_gz({f'numen-fixture-{sha[:7]}/{path}': content for path, content in source_files(sha).items()})


# React2Shell (A07, A16). A harmless stand-in for react-server-dom-webpack, not React's code and no
# exploit, that models the class of flaw: decodeAction resolves an action's "$$id" ("module#export")
# through a server manifest. 19.0.0 does so with no own-property check, so an inherited member such
# as "app/actions#constructor" resolves; it never loads or calls what it resolved and answers a
# fixed marker instead. 19.0.1 resolves only the manifest's own entries and refuses anything else.
# The two versions differ only in resolveServerReference, which the React stand-in's fix commit changes.
NPM = 'http://fixtures:8090/npm'
STAND_IN_HEAD = '''"use strict";
// Asset Monitor stand-in for react-server-dom-webpack: not React's code and no exploit. It models
// the class of flaw behind React2Shell only. An action names its server function by "$$id"
// ("module#export"), resolved through the server manifest. Nothing resolved is ever loaded or
// called: where the flaw reaches an inherited member, such as Object from
// "app/actions#constructor", this stand-in answers a fixed marker instead.
const manifest = {
  "app/actions": {
    addToCart: { id: "app/actions", name: "addToCart", chunks: [] },
    checkout: { id: "app/actions", name: "checkout", chunks: [] },
  },
};

'''
STAND_IN_RESOLVE = {
    '19.0.0': '''function resolveServerReference(id) {
  const [module, name] = String(id).split("#");
  const exports = manifest[module];
  return exports === undefined ? undefined : exports[name];
}
''',
    '19.0.1': '''const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);

function resolveServerReference(id) {
  const [module, name] = String(id).split("#");
  // Only the manifest's own entries resolve, never an inherited member such as "constructor".
  if (!own(manifest, module) || !own(manifest[module], name)) return undefined;
  return manifest[module][name];
}
''',
}
STAND_IN_TAIL = '''
exports.decodeAction = (body) => {
  const action = JSON.parse(body || "{}");
  if (!("$$id" in action)) return "ok";
  const reference = resolveServerReference(action.$$id);
  if (reference === undefined) throw new Error("unknown server action");
  // A manifest entry is an action; a function here is an inherited member.
  return typeof reference === "function" ? "asset-monitor-simulated-flaw" : "ok";
};
'''
STAND_IN = {version: (STAND_IN_HEAD + resolve + STAND_IN_TAIL).encode() for version, resolve in STAND_IN_RESOLVE.items()}


def stand_in_manifest(version: str) -> bytes:
    return json.dumps({'name': 'react-server-dom-webpack', 'version': version, 'main': 'index.js', 'license': 'MIT'}).encode()


NPM_TARBALLS = {
    version: tar_gz({'package/package.json': stand_in_manifest(version), 'package/index.js': source})
    for version, source in STAND_IN.items()
}


def npm_dist(version: str) -> dict:
    return {
        'tarball': f'{NPM}/react-server-dom-webpack/-/react-server-dom-webpack-{version}.tgz',
        'integrity': 'sha512-' + base64.b64encode(hashlib.sha512(NPM_TARBALLS[version]).digest()).decode(),
    }


# The Own Node app numen/node-app-<run>: one head commit, locking the stand-in at 19.0.0.
NODE_SHA = 'd' * 40
NODE_APP = {
    'package.json': json.dumps({'name': 'node-app', 'version': '1.0.0', 'private': True, 'dependencies': {'react-server-dom-webpack': '19.0.0'}}, indent=2).encode(),
    'package-lock.json': json.dumps({'name': 'node-app', 'version': '1.0.0', 'lockfileVersion': 3, 'requires': True, 'packages': {
        '': {'name': 'node-app', 'version': '1.0.0', 'dependencies': {'react-server-dom-webpack': '19.0.0'}},
        'node_modules/react-server-dom-webpack': {'version': '19.0.0', 'resolved': npm_dist('19.0.0')['tarball'], 'integrity': npm_dist('19.0.0')['integrity'], 'license': 'MIT'},
    }}, indent=2).encode(),
    'server.js': b'const { decodeAction } = require("react-server-dom-webpack");\n'
                 b'require("http").createServer((request, response) => {\n'
                 b'  if (request.method !== "POST" || request.url !== "/action") return response.end("ok");\n'
                 b'  let body = "";\n'
                 b'  request.on("data", (chunk) => { body += chunk; });\n'
                 b'  request.on("end", () => {\n'
                 b'    try { response.end(String(decodeAction(body))); }\n'
                 b'    catch (error) { response.statusCode = 400; response.end("refused"); }\n'
                 b'  });\n'
                 b'}).listen(8080);\n',
}
NODE_COMMIT = {
    'sha': NODE_SHA,
    'html_url': f'https://github.com/numen/node-app/commit/{NODE_SHA}',
    'commit': {
        'message': 'Route server actions through react-server-dom-webpack',
        'author': {'name': 'Fixture Maintainer', 'email': 'fixture@example.invalid', 'date': '2026-10-02T00:00:00Z'},
        'committer': {'name': 'Fixture Maintainer', 'date': '2026-10-02T00:00:00Z'},
    },
    'parents': [],
    'files': [{'filename': path, 'status': 'added', 'additions': content.count(b'\n'), 'deletions': 0} for path, content in NODE_APP.items()],
    'stats': {'additions': sum(content.count(b'\n') for content in NODE_APP.values()), 'deletions': 0},
}


def alias(path: str) -> str:
    """Repositories outlive a journey run, so each run links its own numen/fixture-<run>,
    numen/node-app-<run> and numen/advisory-app-<run>; numen/react-fixture, the stand-in's
    Upstream, is the fake Upstream too."""
    path = re.sub(r'^/repos/numen/(?:fixture-[0-9a-f]+|react-fixture)(?=/|$)', '/repos/numen/fixture', path)
    path = re.sub(r'^/repos/numen/advisory-app-[0-9a-f]+(?=/|$)', '/repos/numen/advisory-app', path)
    return re.sub(r'^/repos/numen/node-app-[0-9a-f]+(?=/|$)', '/repos/numen/node-app', path)


# The Advisory check journey (A09): the Own repository numen/advisory-app-<run> pins Node 20.11.1
# in its Dockerfile and .nvmrc, which the fixture CVE-2026-111497 affects. OSV, GHSA and NVD each
# list it, cross-aliased, for node 20.11.1 only and answer every other query empty, so no other
# journey Application opens an advisory Finding.
ADVISORY_SHA = 'e' * 40
ADVISORY_APP = {
    'Dockerfile': b'FROM node:20.11.1-alpine\nWORKDIR /app\nCOPY server.js .\nCMD ["node", "server.js"]\n',
    '.nvmrc': b'20.11.1\n',
    'server.js': b'require("http").createServer((q, r) => r.end("ok")).listen(8080);\n',
}
ADVISORY_COMMIT = {
    'sha': ADVISORY_SHA,
    'html_url': f'https://github.com/numen/advisory-app/commit/{ADVISORY_SHA}',
    'commit': {
        'message': 'Serve the app from the Node 20.11.1 image',
        'author': {'name': 'Fixture Maintainer', 'email': 'fixture@example.invalid', 'date': '2026-10-03T00:00:00Z'},
        'committer': {'name': 'Fixture Maintainer', 'date': '2026-10-03T00:00:00Z'},
    },
    'parents': [],
    'files': [{'filename': path, 'status': 'added', 'additions': content.count(b'\n'), 'deletions': 0} for path, content in ADVISORY_APP.items()],
    'stats': {'additions': sum(content.count(b'\n') for content in ADVISORY_APP.values()), 'deletions': 0},
}
NODE_CVE, NODE_GHSA, NODE_OSV = 'CVE-2026-111497', 'GHSA-9c4w-m7v2-x5qh', 'BIT-node-2026-111497'
NODE_CPE = 'cpe:2.3:a:nodejs:node.js:20.11.1:*:*:*:*:*:*:*'
OSV_NODE = {
    'id': NODE_OSV, 'modified': '2026-11-01T00:00:00Z', 'aliases': [NODE_CVE, NODE_GHSA],
    'summary': 'Node.js HTTP request smuggling (fixture)',
    'affected': [{'package': {'ecosystem': 'Bitnami', 'name': 'node'}, 'ranges': [{'type': 'SEMVER', 'events': [
        {'introduced': '20.0.0'}, {'fixed': '20.19.5'}, {'introduced': '22.0.0'}, {'fixed': '22.12.0'}]}]}],
    'references': [{'type': 'ADVISORY', 'url': 'https://nodejs.org/en/blog/vulnerability/fixture'}],
}
GHSA_NODE = {
    'ghsa_id': NODE_GHSA, 'cve_id': NODE_CVE, 'summary': 'Node.js request smuggling in the HTTP parser (fixture)',
    'severity': 'high', 'identifiers': [{'type': 'GHSA', 'value': NODE_GHSA}, {'type': 'CVE', 'value': NODE_CVE}],
    'references': [f'https://github.com/advisories/{NODE_GHSA}'], 'updated_at': '2026-11-01T00:00:00Z',
    'vulnerabilities': [],
}
NVD_NODE = {
    'id': NODE_CVE, 'lastModified': '2026-11-01T00:00:00.000',
    'descriptions': [{'lang': 'en', 'value': 'Node.js 20 before 20.19.5 allows request smuggling (fixture).'}],
    'metrics': {'cvssMetricV31': [{'source': 'fixture@example.invalid', 'cvssData': {'version': '3.1', 'baseScore': 7.5}}]},
    'configurations': [{'nodes': [{'operator': 'OR', 'negate': False, 'cpeMatch': [{
        'vulnerable': True, 'criteria': 'cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*',
        'versionStartIncluding': '20.0.0', 'versionEndExcluding': '20.19.5'}]}]}],
    'references': [{'url': f'https://nvd.nist.gov/vuln/detail/{NODE_CVE}'}],
}
# The stand-in React2Shell GitHub advisory (A16), listed for react-server-dom-webpack@19.0.0 once
# published. The React stand-in's fix commit names it, so an Analysis can list it in `addresses`.
R2S_GHSA, R2S_CVE = 'GHSA-fv66-9v8q-g76r', 'CVE-2025-55182'
GHSA_REACT2SHELL = {
    'ghsa_id': R2S_GHSA, 'cve_id': R2S_CVE, 'summary': 'React Server Components remote code execution (demo stand-in)',
    'severity': 'critical', 'identifiers': [{'type': 'GHSA', 'value': R2S_GHSA}, {'type': 'CVE', 'value': R2S_CVE}],
    'references': [f'https://github.com/advisories/{R2S_GHSA}'], 'updated_at': '2026-11-01T00:00:00Z',
    'vulnerabilities': [{'package': {'ecosystem': 'npm', 'name': 'react-server-dom-webpack'},
                         'vulnerable_version_range': '>= 19.0.0, < 19.0.1', 'first_patched_version': '19.0.1'}],
}


# The Served-content check journey (A10): judol and ClickFix pages, all inert. Links are never
# fetched and point at .test hosts, the ClickFix command is a harmless placeholder, and
# cdn.clickfix-fixture.test is this fixture's own alias on the isolated served network.
# /served/beacon.js would request /served/executed only if something ran it.
CLICKFIX_HOST = 'cdn.clickfix-fixture.test'
SERVED_BEACON = b"fetch('/served/executed');\n"
SERVED_LOADER = b"/* Asset Monitor fixture: inert ClickFix loader */\nnavigator.clipboard.writeText('echo asset-monitor-fixture');\n"
JUDOL = ('<section><h2>Slot gacor hari ini</h2><p>Daftar situs togel dan slot gacor maxwin terpercaya, bonus deposit setiap hari.</p>'
         '<a href="https://slot-gacor.test/daftar">Slot gacor</a> <a href="https://togel-maxwin.test/">Togel maxwin</a></section>')
CLICKFIX = ('<div id="verify"><h2>Verify you are human</h2><p>Press Win+R, paste the command below and press Enter to finish the check.</p>'
            f'<code>echo asset-monitor-fixture</code></div><script src="http://{CLICKFIX_HOST}:8090/served/loader.js"></script>')


def served_home(judol: bool) -> bytes:
    """The homepage rotates its CSRF token (meta, hidden _token, inline script and logout link),
    its script nonce and its bundle's hash on every request; judol adds gambling links."""
    token, nonce, build = secrets.token_hex(16), secrets.token_hex(12), secrets.token_hex(4)
    return (f'<!doctype html><html><head><title>Toko Batik Fixture</title><meta name="csrf-token" content="{token}">'
            f'<script nonce="{nonce}">window.csrfToken = "{token}";</script>'
            f'<script nonce="{nonce}" src="/served/static/app.{build}.js"></script><script src="/served/beacon.js"></script></head>'
            '<body><h1>Toko Batik Fixture</h1><p>Batik tulis and cap, made to order.</p>'
            f'<form method="post" action="/served/cart"><input type="hidden" name="_token" value="{token}"><button>Add to cart</button></form>'
            f'<a href="/served/verify">Checkout</a> <a href="/served/logout?_token={token}">Log out</a>'
            f'{JUDOL if judol else ""}</body></html>').encode()


def served_app_js() -> bytes:
    """The same bundle on every request, its minified identifiers renamed."""
    a, b = secrets.choice(['a', 'n', 'x']), secrets.choice(['t', 'e', 'r'])
    return f'(function(){{var {a}=document.title,{b}=function({a}){{return {a}.length}};window.appReady={b}({a})}})();\n'.encode()


def osv_results(queries: list, published: bool) -> dict:
    """OSV's querybatch answer: the node record for node 20.11.1 only, while node2shell is published."""
    node = {'package': {'ecosystem': 'Bitnami', 'name': 'node'}, 'version': '20.11.1'}
    return {'results': [
        {'vulns': [{'id': NODE_OSV, 'modified': OSV_NODE['modified']}]} if published and isinstance(query, dict)
        and {key: query.get(key) for key in node} == node else {}
        for query in queries]}


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


# The demo stand-ins (A16), in demo mode: asset-monitor-demo/shop (the demo Own repository) and
# asset-monitor-demo/react (the stand-in React Upstream repository) are bare git repositories under
# GIT_ROOT, rebuilt on every start. Commits have a fixed author and dates one hour apart, so the same
# content gives the same shas and tag creatordate order is build order.
DEMO_OWNER = 'asset-monitor-demo'
DEMO_CONTENT = Path(__file__).resolve().parent / 'demo_repositories'
GIT_ROOT = Path('/tmp/asset-monitor-demo-git')
EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904'
FIRST_DATE = int(datetime(2026, 11, 1, tzinfo=timezone.utc).timestamp())
GIT_ENV = {
    'GIT_AUTHOR_NAME': 'Demo Maintainer', 'GIT_AUTHOR_EMAIL': 'maintainer@asset-monitor-demo.test',
    'GIT_COMMITTER_NAME': 'Demo Maintainer', 'GIT_COMMITTER_EMAIL': 'maintainer@asset-monitor-demo.test',
    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0', 'LC_ALL': 'C',
}
REACT_README = (b"# React (stand-in)\n\nThe Asset Monitor demo's stand-in React Upstream repository: not React's code and no "
                b"exploit. packages/react-server-dom-webpack models the class of flaw behind React2Shell and never "
                b"loads or calls what it resolves.\n")
REACT_FIX = '''Resolve server references through own properties only

resolveServerReference read an action's $$id ("module#export") from the
server manifest with plain property reads, so a reference to an inherited
member such as "app/actions#constructor" resolved to a function the manifest
never listed. Resolve only the manifest's own modules and exports, and refuse
anything else.

Fixes GHSA-fv66-9v8q-g76r (CVE-2025-55182).'''


def git(repo: Path, *args: str, stdin: bytes | None = None, env: dict | None = None, raw: bool = False):
    """git's stdout in the bare repository `repo` (text unless `raw`); raises CalledProcessError."""
    out = subprocess.run(['git', *args], cwd=repo, input=stdin, capture_output=True, check=True,
                         env={'PATH': os.environ.get('PATH', os.defpath), 'HOME': str(repo), **GIT_ENV, **(env or {})}).stdout
    return out if raw else out.decode(errors='replace')


def rev(repo: Path, ref: str) -> str | None:
    """The commit `ref` (a sha, branch, tag or refs/... name) names, or None."""
    if ref.startswith('-'):
        return None
    try:
        return git(repo, 'rev-parse', '--verify', '--quiet', ref + '^{commit}').strip()
    except subprocess.CalledProcessError:
        return None


def iso(timestamp: str) -> str:
    return datetime.fromtimestamp(int(timestamp), timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def commit_items(repo: Path, *args: str) -> list[dict]:
    """GitHub's commit list items for `git log args`."""
    name = repo.name.removesuffix('.git')
    items = []
    for record in filter(None, git(repo, 'log', '-z', '--format=%H%x1f%P%x1f%an%x1f%ae%x1f%at%x1f%cn%x1f%ct%x1f%B', *args).split('\0')):
        sha, parents, author, email, authored, committer, committed, message = record.split('\x1f', 7)
        items.append({
            'sha': sha, 'html_url': f'https://github.com/{DEMO_OWNER}/{name}/commit/{sha}',
            'commit': {'message': message.rstrip('\n'), 'author': {'name': author, 'email': email, 'date': iso(authored)},
                       'committer': {'name': committer, 'date': iso(committed)}},
            'parents': [{'sha': parent} for parent in parents.split()],
        })
    return items


def changed_files(repo: Path, sha: str) -> list[dict]:
    """GitHub's `files` of a commit against its first parent (the empty tree for a root commit).
    A binary file has no patch."""
    parent = rev(repo, sha + '^') or EMPTY_TREE
    statuses = git(repo, 'diff-tree', '-r', '--no-renames', '--name-status', parent, sha).splitlines()
    counts = git(repo, 'diff-tree', '-r', '--no-renames', '--numstat', parent, sha).splitlines()
    files = []
    for status, count in zip(statuses, counts):
        code, path = status.split('\t', 1)
        added, removed, _ = count.split('\t', 2)
        entry = {'filename': path, 'status': {'A': 'added', 'D': 'removed', 'M': 'modified'}.get(code, 'changed'),
                 'additions': int(added) if added != '-' else 0, 'deletions': int(removed) if removed != '-' else 0}
        diff = git(repo, 'diff', '--no-color', '--no-renames', parent, sha, '--', path)
        if added != '-' and '\n@@' in diff:  # GitHub's patch starts at the first hunk
            entry['patch'] = diff[diff.index('\n@@') + 1:].rstrip('\n')
        files.append({**entry, 'changes': entry['additions'] + entry['deletions']})
    return files


def stamp(repo: Path) -> dict:
    """The date of the next commit or tag: an hour after the newest ref's."""
    newest = git(repo, 'for-each-ref', '--sort=-creatordate', '--count=1', '--format=%(creatordate:unix)').strip()
    when = (int(newest) if newest else FIRST_DATE - 3600) + 3600
    return {'GIT_AUTHOR_DATE': f'@{when} +0000', 'GIT_COMMITTER_DATE': f'@{when} +0000'}


def new_commit(repo: Path, tree: str, parents: list[str], message: str) -> str:
    return git(repo, 'commit-tree', tree, *[arg for parent in parents for arg in ('-p', parent)],
               stdin=message.encode(), env=stamp(repo)).strip()


def write_tree(repo: Path, base: str | None, entries: list[dict]) -> str:
    """The tree `base` with `entries` ({path, mode, sha}) applied, built in a temporary index; an entry
    whose sha is None deletes its path."""
    with tempfile.TemporaryDirectory(prefix='asset-monitor-demo-index-') as tmp:
        index = {'GIT_INDEX_FILE': f'{tmp}/index'}
        git(repo, 'read-tree', *([base] if base else ['--empty']), env=index)
        listing = ''.join(f"{entry['mode']} {entry['sha']}\t{entry['path']}\n" if entry.get('sha')
                          else f"0 {'0' * 40}\t{entry['path']}\n" for entry in entries)
        git(repo, 'update-index', '--index-info', stdin=listing.encode(), env=index)
        return git(repo, 'write-tree', env=index).strip()


def commit_files(repo: Path, message: str, files: dict[str, bytes], tag: str | None = None) -> str:
    """Commits `files` ({path: bytes}, each added or changed) onto main, and tags it when `tag` is
    given (annotated): the new head."""
    head = rev(repo, 'refs/heads/main')
    blobs = [{'path': path, 'mode': '100644', 'sha': git(repo, 'hash-object', '-w', '--stdin', stdin=data).strip()}
             for path, data in files.items()]
    sha = new_commit(repo, write_tree(repo, head, blobs), [head] if head else [], message)
    git(repo, 'update-ref', 'refs/heads/main', sha, head or '')
    if tag:
        git(repo, 'tag', '-a', tag, '-m', tag, sha, env=stamp(repo))
    return sha


def commit_directory(source: Path) -> tuple[str, dict[str, bytes]]:
    """(MESSAGE, {path: bytes} of every other file) of a prepared commit directory."""
    files = {str(path.relative_to(source)): path.read_bytes() for path in sorted(source.rglob('*'))
             if path.is_file() and path != source / 'MESSAGE'}
    return (source / 'MESSAGE').read_text().strip(), files


def build_demo(root: Path) -> None:
    """The demo's bare repositories under `root`, from scratch."""
    shutil.rmtree(root, ignore_errors=True)
    react, shop = (root / DEMO_OWNER / f'{name}.git' for name in ('react', 'shop'))
    for repo in (react, shop):
        repo.mkdir(parents=True)
        git(repo, 'init', '--quiet', '--bare', '--initial-branch=main')
        # Exposure's blobless mirror and its lazy blob fetches (sources.github_mirror).
        git(repo, 'config', 'uploadpack.allowFilter', 'true')
        git(repo, 'config', 'uploadpack.allowAnySHA1InWant', 'true')
    package = 'packages/react-server-dom-webpack/'
    commit_files(react, 'Release 19.0.0', {'README.md': REACT_README, package + 'package.json': stand_in_manifest('19.0.0'),
                                           package + 'index.js': STAND_IN['19.0.0']}, tag='v19.0.0')
    commit_files(react, REACT_FIX, {package + 'index.js': STAND_IN['19.0.1']})
    commit_files(react, 'Release 19.0.1', {package + 'package.json': stand_in_manifest('19.0.1')}, tag='v19.0.1')
    # The Own repository locks the stand-in at 19.0.0, vendored as a file: tarball (as lab_run vendors
    # a Locked version), because a Lab's dependency fetch reaches only the public registry.
    message, files = commit_directory(DEMO_CONTENT / 'shop' / 'base')
    manifest = json.loads(files['package.json'])
    vendored = manifest['dependencies']['react-server-dom-webpack']
    lock = {'name': manifest['name'], 'version': manifest['version'], 'lockfileVersion': 3, 'requires': True, 'packages': {
        '': {'name': manifest['name'], 'version': manifest['version'], 'dependencies': manifest['dependencies']},
        'node_modules/react-server-dom-webpack': {'version': '19.0.0', 'resolved': vendored,
                                                  'integrity': npm_dist('19.0.0')['integrity'], 'license': 'MIT'},
    }}
    commit_files(shop, message, {**files, vendored.removeprefix('file:'): NPM_TARBALLS['19.0.0'],
                                 'package-lock.json': (json.dumps(lock, indent=2) + '\n').encode()})


def demo_repository(path: str) -> tuple[Path, str] | None:
    """(bare repository, the rest of the path) of a /repos/asset-monitor-demo/<name> route, else None."""
    match = re.fullmatch(rf'/repos/{DEMO_OWNER}/([a-z0-9-]+)(/.*)?', path)
    repo = match and GIT_ROOT / DEMO_OWNER / f'{match[1]}.git'
    return (repo, unquote(match[2] or '')) if repo and repo.is_dir() else None


# The GitHub push stand-in (B02): numen/push-app-<run>. Its first read creates its base commit, and
# only /admin/push adds one, so /admin/advance never moves it. Each commit changes VERSION, with a
# sha fixed by the repository and the commit's number. A push payload lists only PAYLOAD_SHA, which
# no GitHub route serves: a check imports the pushed commit from the API, never from the payload.
PUSH_REPOSITORY = r'numen/push-app-[0-9a-f]+'
PAYLOAD_SHA = 'f' * 40


def push_commit(repository: str, number: int, parent: str | None) -> dict:
    """The push stand-in's commit `number`, with its files: VERSION becomes 1.0.<number>."""
    sha = hashlib.sha1(f'{repository}:{number}'.encode()).hexdigest()
    date = iso(str(FIRST_DATE + 60 * number))
    return {
        'sha': sha, 'html_url': f'https://github.com/{repository}/commit/{sha}',
        'commit': {'message': f'Release 1.0.{number}', 'author': {'name': 'Fixture Maintainer', 'email': 'fixture@example.invalid', 'date': date},
                   'committer': {'name': 'Fixture Maintainer', 'date': date}},
        'parents': [{'sha': parent}] if parent else [],
        'files': [{'filename': 'VERSION', 'status': 'modified' if parent else 'added', 'additions': 1, 'deletions': 1 if parent else 0,
                   'patch': f'@@ -1 +1 @@\n-1.0.{number - 1}\n+1.0.{number}' if parent else '@@ -0,0 +1 @@\n+1.0.0'}],
    }


def push_commits(repository: str) -> list[dict]:
    """The push stand-in's commits, newest first. The caller holds STATE.lock."""
    return STATE.push_repos.setdefault(repository, [push_commit(repository, 0, None)])


def push_payload(repository: str, before: str, after: str) -> bytes:
    listed = {'id': PAYLOAD_SHA, 'message': 'Listed in the payload only', 'url': f'https://github.com/{repository}/commit/{PAYLOAD_SHA}'}
    return json.dumps({'ref': 'refs/heads/main', 'before': before, 'after': after,
                       'repository': {'full_name': repository, 'html_url': f'https://github.com/{repository}'},
                       'pusher': {'name': 'Fixture Maintainer'}, 'commits': [listed], 'head_commit': listed}).encode()


def signature(secret: str, body: bytes) -> str:
    return 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def deliver(url: str, event: str, body: bytes, signed: str, delivery_id: str | None = None) -> dict:
    """Records a delivery and POSTs it to `url` as GitHub does, under a new delivery id unless one is
    given: {delivery_id, status}, the listener's status."""
    delivery_id = delivery_id or str(uuid.uuid4())
    with STATE.lock:
        STATE.deliveries[delivery_id] = {'url': url, 'event': event, 'body': body, 'signature': signed, 'status': None}
    request = Request(url, body, {'Content-Type': 'application/json', 'User-Agent': 'GitHub-Hookshot/fixture', 'X-GitHub-Event': event,
                                  'X-GitHub-Delivery': delivery_id, 'X-Hub-Signature-256': signed}, method='POST')
    try:
        response = urlopen(request, timeout=10)
    except HTTPError as error:
        response = error
    with response:
        status = response.status
    with STATE.lock:
        STATE.deliveries[delivery_id]['status'] = status
    return {'delivery_id': delivery_id, 'status': status}


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
        if self.path.startswith('/git/'):
            return self.git_http()
        parsed = urlparse(self.path)
        path = alias(parsed.path.rstrip('/') or '/')
        query = parse_qs(parsed.query)
        with STATE.lock:
            STATE.requests.append(path)
            generation = STATE.generation
            version = STATE.version
            published = set(STATE.published)
        if path == '/health':
            return self.json({'ok': True})
        if path == '/admin/state':
            with STATE.lock:
                return self.json({'generation': STATE.generation, 'version': STATE.version, 'score': STATE.score, 'notifications': STATE.notifications, 'requests': STATE.requests, 'pulls': STATE.pulls, 'writes': STATE.writes,
                                  'served_variants': sorted(STATE.served_variants), 'served_requests': STATE.served_requests,
                                  'published': sorted(STATE.published), 'demo_pulls': STATE.demo_pulls,
                                  'hooks': [{'repository': hook['repository'], 'url': hook['url']} for hook in STATE.hooks],
                                  'deliveries': {ident: {key: sent[key] for key in ('url', 'event', 'status')} for ident, sent in STATE.deliveries.items()}})
        if found := demo_repository(path):
            try:
                return self.demo_read(*found, query)
            except (subprocess.CalledProcessError, ValueError):
                return self.json({'message': 'Not Found'}, 404)
        if match := re.fullmatch(rf'/repos/({PUSH_REPOSITORY})(/.*)?', path):
            return self.push_read(match[1], match[2] or '')
        if path == '/served' or path.startswith('/served/'):
            return self.served(path)
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
        if path == '/repos/numen/node-app/commits':
            body = json.dumps([NODE_COMMIT]).encode()
            etag = '"' + hashlib.sha256(body).hexdigest()[:16] + '"'
            if self.headers.get('If-None-Match') == etag:
                return self.send(304, b'', headers={'ETag': etag})
            return self.send(200, body, headers={'ETag': etag})
        if path == f'/repos/numen/node-app/commits/{NODE_SHA}':
            return self.json(NODE_COMMIT)
        if path.startswith('/repos/numen/node-app/contents/') and path.rsplit('/', 1)[1] in NODE_APP:
            return self.send(200, NODE_APP[path.rsplit('/', 1)[1]], 'text/plain')
        if path == f'/repos/numen/node-app/tarball/{NODE_SHA}':
            return self.send(200, tar_gz({f'numen-node-app-{NODE_SHA[:7]}/{p}': c for p, c in NODE_APP.items()}), 'application/gzip')
        if path == '/repos/numen/advisory-app/commits':
            body = json.dumps([ADVISORY_COMMIT]).encode()
            etag = '"' + hashlib.sha256(body).hexdigest()[:16] + '"'
            if self.headers.get('If-None-Match') == etag:
                return self.send(304, b'', headers={'ETag': etag})
            return self.send(200, body, headers={'ETag': etag})
        if path == f'/repos/numen/advisory-app/commits/{ADVISORY_SHA}':
            return self.json(ADVISORY_COMMIT)
        if path == f'/repos/numen/advisory-app/tarball/{ADVISORY_SHA}':
            return self.send(200, tar_gz({f'numen-advisory-app-{ADVISORY_SHA[:7]}/{p}': c for p, c in ADVISORY_APP.items()}), 'application/gzip')
        if path == f'/osv/v1/vulns/{NODE_OSV}':
            return self.json(OSV_NODE)
        if path == '/advisories':
            found = [GHSA_NODE] if 'node2shell' in published and query.get('cve_id') == [NODE_CVE] else []
            if ('react2shell' in published and query.get('ecosystem') == ['npm']
                    and 'react-server-dom-webpack@19.0.0' in ','.join(query.get('affects', [])).split(',')):
                found.append(GHSA_REACT2SHELL)
            return self.json(found)
        if path == '/rest/json/cves/2.0' and 'cpeName' in query:
            found = [{'cve': NVD_NODE}] if 'node2shell' in published and query['cpeName'] == [NODE_CPE] else []
            first = int(query.get('startIndex', ['0'])[0]) == 0
            return self.json({'totalResults': len(found), 'vulnerabilities': found if first else []})
        if path.startswith('/npm/react-server-dom-webpack/'):
            version = path.rsplit('/', 1)[1].removeprefix('react-server-dom-webpack-').removesuffix('.tgz')
            if version in NPM_TARBALLS and path.endswith('.tgz'):
                return self.send(200, NPM_TARBALLS[version], 'application/octet-stream')
            if version in NPM_TARBALLS:
                upstream = f'{DEMO_OWNER}/react' if DEMO else 'numen/react-fixture'
                return self.json({'name': 'react-server-dom-webpack', 'version': version,
                                  'repository': {'type': 'git', 'url': f'git+https://github.com/{upstream}.git'},
                                  'dist': npm_dist(version)})
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
        if self.path.startswith('/git/'):
            return self.git_http()
        original = urlparse(self.path).path.rstrip('/')
        path = alias(original)
        length = int(self.headers.get('Content-Length', '0'))
        if length > 1_000_000:
            return self.json({'message': 'Fixture request too large'}, 413)
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw) if raw else {}
        except ValueError:
            return self.json({'message': 'Invalid JSON'}, 400)
        if not path.startswith('/admin/'):
            with STATE.lock:
                STATE.requests.append(path)
        if path == '/osv/v1/querybatch':
            with STATE.lock:
                published = 'node2shell' in STATE.published
            return self.json(osv_results((data.get('queries') if isinstance(data, dict) else None) or [], published))
        if DEMO and path.startswith('/admin/demo/'):
            return self.demo_admin(path, data if isinstance(data, dict) else {})
        if found := demo_repository(original):
            return self.demo_write(*found, original, data if isinstance(data, dict) else {})
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
                STATE.served_variants.clear()
                STATE.served_requests.clear()
                STATE.push_repos.clear()
                STATE.hooks.clear()
                STATE.deliveries.clear()
            return self.json({'ok': True})
        if path == '/admin/served':
            with STATE.lock:
                STATE.served_variants = set(data.get('variants', []))
            return self.json({'variants': sorted(STATE.served_variants)})
        if path in ('/admin/hooks', '/admin/push', '/admin/hooks/redeliver', '/admin/hooks/replay', '/admin/hooks/forge'):
            return self.push_admin(path, data if isinstance(data, dict) else {})
        if path.startswith('/repos/numen/fixture/'):
            return self.github_write(original, path.removeprefix('/repos/numen/fixture'), data)
        if path.startswith('/webhooks/') or path.startswith('/api/webhooks/'):
            with STATE.lock:
                STATE.notifications.append(data)
                message_id = str(len(STATE.notifications))
            return self.json({'id': message_id, 'channel_id': 'fixture', 'content': data.get('content', '')})
        return self.json({'message': 'Fixture route not found'}, 404)

    def served(self, path: str) -> None:
        """The Served-content fixture: each request is recorded with its user agent, so the journey
        can show that /served/executed is never requested."""
        agent = self.headers.get('User-Agent', '')
        with STATE.lock:
            STATE.served_requests.append({'path': path, 'user_agent': agent})
            variants = set(STATE.served_variants)
        html = 'text/html; charset=utf-8'
        if path == '/served':
            return self.send(200, served_home('judol' in variants and 'Googlebot' in agent), html)
        if path == '/served/verify':
            page = f'<!doctype html><html><head><title>Checkout</title></head><body><h1>Checkout</h1><p>Review your order.</p>{CLICKFIX if "clickfix" in variants else ""}</body></html>'
            return self.send(200, page.encode(), html)
        if re.fullmatch(r'/served/static/app\.[0-9a-f]+\.js', path):
            return self.send(200, served_app_js(), 'application/javascript')
        if path in ('/served/beacon.js', '/served/loader.js'):
            return self.send(200, SERVED_BEACON if path == '/served/beacon.js' else SERVED_LOADER, 'application/javascript')
        return self.send(404, b'Not found', 'text/plain')

    def push_read(self, repository: str, rest: str) -> None:
        """The GitHub REST reads of a source check, answered from the push stand-in. Contents and
        every other route answer 404, so derivation finds no manifest."""
        with STATE.lock:
            commits = list(push_commits(repository))
        shas = [item['sha'] for item in commits]
        if rest == '/commits':
            body = json.dumps(commits).encode()
            etag = '"' + hashlib.sha256(body).hexdigest()[:16] + '"'
            if self.headers.get('If-None-Match') == etag:
                return self.send(304, b'', headers={'ETag': etag})
            return self.send(200, body, headers={'ETag': etag})
        if rest.startswith('/commits/') and (sha := rest.removeprefix('/commits/')) in shas:
            return self.json(commits[shas.index(sha)])
        base, _, head = rest.removeprefix('/compare/').partition('...')
        if rest.startswith('/compare/') and base in shas and head in shas[:shas.index(base) + 1]:
            ahead = commits[shas.index(head):shas.index(base)][::-1]  # chronological, as GitHub lists them
            return self.json({'status': 'ahead' if ahead else 'identical', 'ahead_by': len(ahead), 'behind_by': 0,
                              'total_commits': len(ahead), 'commits': ahead})
        return self.json({'message': 'Not Found'}, 404)

    def push_admin(self, path: str, data: dict) -> None:
        """The push stand-in's hooks (B02). Registering a hook sends it a signed ping, as GitHub does.
        A push adds one commit to that repository only and sends a signed push delivery to each of
        its hooks. Redeliver resends a delivery as it was, replay resends its body and signature under
        a new delivery id, and forge sends each hook a push signed with the wrong secret."""
        if path in ('/admin/hooks/redeliver', '/admin/hooks/replay'):
            ident = str(data.get('delivery_id', ''))
            with STATE.lock:
                sent = STATE.deliveries.get(ident)
            if not sent:
                return self.json({'message': 'No such delivery'}, 404)
            return self.json(deliver(sent['url'], sent['event'], sent['body'], sent['signature'],
                                     ident if path == '/admin/hooks/redeliver' else None))
        repository = str(data.get('repository', ''))
        if not re.fullmatch(PUSH_REPOSITORY, repository):
            return self.json({'message': 'repository is numen/push-app-<hex>'}, 400)
        if path == '/admin/hooks':
            url, secret = str(data.get('url', '')), str(data.get('secret', ''))
            if not url.startswith('http://') or not secret:
                return self.json({'message': 'url and secret are required'}, 400)
            with STATE.lock:
                STATE.hooks.append({'repository': repository, 'url': url, 'secret': secret})
                hook_id = len(STATE.hooks)
            body = json.dumps({'zen': 'Keep it logically awesome.', 'hook_id': hook_id, 'repository': {'full_name': repository},
                               'hook': {'type': 'Repository', 'events': ['push'], 'config': {'content_type': 'json', 'url': url}}}).encode()
            return self.json(deliver(url, 'ping', body, signature(secret, body)))
        with STATE.lock:
            commits = push_commits(repository)
            if path == '/admin/push':
                commits.insert(0, push_commit(repository, len(commits), commits[0]['sha']))
            head = commits[0]['sha']
            body = push_payload(repository, commits[1]['sha'] if len(commits) > 1 else head, head)
            hooks = [hook for hook in STATE.hooks if hook['repository'] == repository]
        forged = path == '/admin/hooks/forge'
        return self.json({'sha': head, 'deliveries': [
            deliver(hook['url'], 'push', body, signature(hook['secret'] + '-forged' if forged else hook['secret'], body)) for hook in hooks]})

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

    def demo_read(self, repo: Path, rest: str, query: dict) -> None:
        """The GitHub REST reads of sources.Sources and remediation, answered from the demo
        repository's git."""
        name = repo.name.removesuffix('.git')

        def arg(key: str, default: str) -> str:
            return query.get(key, [default])[0]

        per_page, page = int(arg('per_page', '30')), int(arg('page', '1'))

        def paged(items: list) -> list:
            return items[(page - 1) * per_page:page * per_page]

        if rest == '':
            return self.json({'full_name': f'{DEMO_OWNER}/{name}', 'default_branch': 'main'})
        if rest == '/commits' and (sha := rev(repo, arg('sha', 'HEAD'))):
            body = json.dumps(commit_items(repo, f'--skip={(page - 1) * per_page}', f'--max-count={per_page}', sha)).encode()
            etag = '"' + hashlib.sha256(body).hexdigest()[:16] + '"'
            if self.headers.get('If-None-Match') == etag:
                return self.send(304, b'', headers={'ETag': etag})
            return self.send(200, body, headers={'ETag': etag})
        if rest.startswith('/commits/') and (sha := rev(repo, rest.removeprefix('/commits/'))):
            return self.json({**commit_items(repo, '-1', sha)[0], 'files': changed_files(repo, sha) if page == 1 else []})
        if rest.startswith('/compare/'):
            base, _, head = rest.removeprefix('/compare/').partition('...')
            base, head = rev(repo, base), rev(repo, head)
            if base and head:
                ahead = commit_items(repo, '--reverse', f'{base}..{head}')
                behind = len(git(repo, 'rev-list', f'{head}..{base}').split())
                status = ('identical' if not ahead and not behind else 'ahead' if not behind
                          else 'behind' if not ahead else 'diverged')
                return self.json({'status': status, 'ahead_by': len(ahead), 'behind_by': behind,
                                  'total_commits': len(ahead), 'commits': paged(ahead)})
        if rest.startswith('/contents/'):
            blob = git(repo, 'cat-file', 'blob', f"{arg('ref', 'HEAD')}:{rest.removeprefix('/contents/')}", raw=True)
            return self.send(200, blob, 'application/vnd.github.raw')
        if rest.startswith('/tarball/') and (sha := rev(repo, rest.removeprefix('/tarball/'))):
            tar = git(repo, 'archive', '--format=tar', f'--prefix={DEMO_OWNER}-{name}-{sha[:7]}/', sha, raw=True)
            return self.send(200, gzip.compress(tar, mtime=0), 'application/gzip')
        if rest == '/tags':
            lines = git(repo, 'for-each-ref', '--sort=-creatordate', '--format=%(refname:strip=2) %(objectname) %(*objectname)', 'refs/tags').splitlines()
            return self.json(paged([{'name': tag, 'commit': {'sha': (peeled or [sha])[0]}} for tag, sha, *peeled in map(str.split, lines)]))
        if rest.startswith('/branches/') and (sha := rev(repo, 'refs/heads/' + rest.removeprefix('/branches/'))):
            return self.json({'name': rest.removeprefix('/branches/'), 'commit': {'sha': sha}, 'protected': False})
        if rest == '/releases':
            return self.json([])
        if rest.startswith('/git/ref/') and (sha := rev(repo, 'refs/' + rest.removeprefix('/git/ref/'))):
            return self.json({'ref': 'refs/' + rest.removeprefix('/git/ref/'), 'object': {'type': 'commit', 'sha': sha}})
        if rest.startswith('/git/commits/') and (sha := rev(repo, rest.removeprefix('/git/commits/'))):
            item = commit_items(repo, '-1', sha)[0]
            return self.json({'sha': sha, 'tree': {'sha': git(repo, 'rev-parse', sha + '^{tree}').strip()},
                              'message': item['commit']['message'], 'parents': item['parents']})
        if rest.startswith('/git/trees/'):
            tree = rest.removeprefix('/git/trees/')
            listing = git(repo, 'ls-tree', *(['-r', '-t'] if arg('recursive', '') else []), '--end-of-options', tree)
            entries = [{'path': path, 'mode': mode, 'type': kind, 'sha': sha}
                       for meta, path in (line.split('\t', 1) for line in listing.splitlines()) for mode, kind, sha in [meta.split()]]
            return self.json({'sha': tree, 'tree': entries, 'truncated': False})
        if rest == '/pulls':
            with STATE.lock:
                return self.json([pull for pull in STATE.demo_pulls.get(name, []) if arg('state', 'open') in ('all', pull['state'])
                                  and (not query.get('head') or f"{DEMO_OWNER}:{pull['head']['ref']}" in query['head'])])
        if rest.startswith('/pulls/') and rest.removeprefix('/pulls/').isdigit():
            number = int(rest.removeprefix('/pulls/'))
            with STATE.lock:
                pulls = STATE.demo_pulls.get(name, [])
                if 0 < number <= len(pulls):
                    return self.json(pulls[number - 1])
        return self.json({'message': 'Not Found'}, 404)

    def demo_write(self, repo: Path, rest: str, original: str, data: dict) -> None:
        """The git data and pull request writes of a Remediation PR (A08), into the demo repository.
        No write moves a ref: main changes only through /admin/demo/push and /admin/demo/merge."""
        name = repo.name.removesuffix('.git')
        with STATE.lock:
            STATE.writes.append({'method': 'POST', 'path': original})
        try:
            if rest == '/git/blobs':
                content = base64.b64decode(data['content']) if data.get('encoding') == 'base64' else data['content'].encode()
                return self.json({'sha': git(repo, 'hash-object', '-w', '--stdin', stdin=content).strip()}, 201)
            if rest == '/git/trees':
                return self.json({'sha': write_tree(repo, data.get('base_tree'), data['tree'])}, 201)
            if rest == '/git/commits':
                sha = new_commit(repo, data['tree'], data['parents'], data['message'])
                return self.json({'sha': sha, 'tree': {'sha': data['tree']}, 'message': data['message'],
                                  'parents': [{'sha': parent} for parent in data['parents']]}, 201)
            with STATE.lock:
                if rest == '/git/refs':
                    ref = data['ref']
                    if ref == 'refs/heads/main' or rev(repo, ref):
                        return self.json({'message': 'Reference already exists'}, 422)
                    if not ref.startswith('refs/heads/'):
                        return self.json({'message': 'Validation Failed'}, 422)
                    git(repo, 'update-ref', ref, data['sha'], '')
                    return self.json({'ref': ref, 'object': {'type': 'commit', 'sha': data['sha']}}, 201)
                if rest == '/pulls':
                    head = rev(repo, 'refs/heads/' + data['head'])
                    if not head:
                        return self.json({'message': 'Validation Failed'}, 422)
                    pulls = STATE.demo_pulls.setdefault(name, [])
                    number = len(pulls) + 1
                    pulls.append({
                        'number': number, 'html_url': f'https://github.com/{DEMO_OWNER}/{name}/pull/{number}', 'state': 'open',
                        'draft': bool(data.get('draft')), 'title': data['title'], 'body': data.get('body') or '',
                        'head': {'ref': data['head'], 'sha': head}, 'base': {'ref': data['base']},
                        'merged': False, 'merge_commit_sha': None,
                    })
                    return self.json(pulls[-1], 201)
        except (KeyError, TypeError, AttributeError, ValueError, subprocess.CalledProcessError):
            return self.json({'message': 'Validation Failed'}, 422)
        return self.json({'message': 'Not Found'}, 404)

    def demo_admin(self, path: str, data: dict) -> None:
        """Advances the demo stand-ins (A16): commits a prepared commit directory onto main (once: a
        MESSAGE already on main answers its sha), squash-merges a pull request, or publishes a
        stand-in advisory."""
        if path == '/admin/demo/publish':
            if data.get('advisory') not in ('react2shell', 'node2shell'):
                return self.json({'message': 'advisory is react2shell or node2shell'}, 400)
            with STATE.lock:
                STATE.published.add(data['advisory'])
                return self.json({'published': sorted(STATE.published)})
        name = str(data.get('repository', ''))
        repo = GIT_ROOT / DEMO_OWNER / f'{name}.git'
        if not re.fullmatch(r'[a-z0-9-]+', name) or not repo.is_dir():
            return self.json({'message': 'No such demo repository'}, 404)
        if path == '/admin/demo/push':
            commit = str(data.get('commit', ''))
            source = DEMO_CONTENT / name / commit
            if not re.fullmatch(r'[a-z0-9-]+', commit) or not (source / 'MESSAGE').is_file():
                return self.json({'message': 'No such prepared commit'}, 404)
            message, files = commit_directory(source)
            with STATE.lock:
                sha = next((item['sha'] for item in commit_items(repo, 'refs/heads/main') if item['commit']['message'].strip() == message),
                           None) or commit_files(repo, message, files)
            return self.json({'sha': sha})
        if path == '/admin/demo/merge':
            number = data.get('number')
            with STATE.lock:
                pulls = STATE.demo_pulls.get(name, [])
                if not isinstance(number, int) or not 0 < number <= len(pulls):
                    return self.json({'message': 'No such pull request'}, 404)
                pull = pulls[number - 1]
                if pull['state'] == 'open':
                    main, head = rev(repo, 'refs/heads/main'), rev(repo, 'refs/heads/' + pull['head']['ref'])
                    try:
                        tree = git(repo, 'merge-tree', '--write-tree', main, head).split()[0]
                    except subprocess.CalledProcessError:
                        return self.json({'message': 'Merge conflict'}, 409)
                    sha = new_commit(repo, tree, [main], f"{pull['title']} (#{number})\n\n{pull['body']}")
                    git(repo, 'update-ref', 'refs/heads/main', sha, main)
                    pull.update(state='closed', merged=True, merge_commit_sha=sha)
                if not pull['merged']:
                    return self.json({'message': 'Closed without merging'}, 409)
                return self.json(pull)
        return self.json({'message': 'Fixture route not found'}, 404)

    def git_http(self) -> None:
        """The read-only clone route: smart HTTP through `git http-backend` (CGI) for the demo
        repositories. Exposure, require_clean_tree and the Malicious change containment clone from it
        (NUMEN_GITHUB_GIT_URL=http://fixtures:8090/git). Pushing is refused."""
        parsed = urlparse(self.path)
        match = re.fullmatch(rf'/git/({DEMO_OWNER}/[a-z0-9-]+\.git)/[\w./-]+', parsed.path)
        if not match or '..' in parsed.path or not (GIT_ROOT / match[1]).is_dir():
            return self.json({'message': 'Fixture route not found'}, 404)
        if 'git-receive-pack' in self.path:
            return self.send(403, b'The demo repositories are read-only\n', 'text/plain')
        # ponytail: only a Content-Length body is read; git sends a chunked one only past
        # http.postBuffer (1 MiB of wants), far beyond the demo repositories
        length = int(self.headers.get('Content-Length') or 0)
        if length > 1_000_000:
            return self.json({'message': 'Fixture request too large'}, 413)
        env = {
            'PATH': os.environ.get('PATH', os.defpath), 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
            'GIT_PROJECT_ROOT': str(GIT_ROOT), 'GIT_HTTP_EXPORT_ALL': '1', 'PATH_INFO': parsed.path.removeprefix('/git'),
            'QUERY_STRING': parsed.query, 'REQUEST_METHOD': self.command, 'CONTENT_TYPE': self.headers.get('Content-Type', ''),
            'CONTENT_LENGTH': str(length), 'HTTP_CONTENT_ENCODING': self.headers.get('Content-Encoding', ''),
            'GIT_PROTOCOL': self.headers.get('Git-Protocol', ''),
        }
        output = subprocess.run(['git', 'http-backend'], input=self.rfile.read(length), env=env, capture_output=True).stdout
        head, _, body = output.partition(b'\r\n\r\n')
        headers = dict(line.split(': ', 1) for line in head.decode(errors='replace').split('\r\n') if ': ' in line)
        status = int(headers.pop('Status', '200').split()[0])
        return self.send(status, body, headers.pop('Content-Type', 'text/plain'), headers)


def check() -> None:
    """python fixture_server.py check: demo mode built in a temporary root and served on 127.0.0.1."""
    global DEMO, GIT_ROOT
    with tempfile.TemporaryDirectory(prefix='asset-monitor-demo-check-') as tmp:
        DEMO, GIT_ROOT = True, Path(tmp, 'git')
        STATE.published.clear()
        build_demo(GIT_ROOT)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = f'http://127.0.0.1:{server.server_port}'

        def raw(path: str, body: object = None, expect: int = 200, headers: dict | None = None):
            request = Request(base + path, None if body is None else json.dumps(body).encode(),
                              {'Content-Type': 'application/json', **(headers or {})})
            try:
                response = urlopen(request, timeout=30)
            except HTTPError as error:
                response = error
            with response:
                payload = response.read()
            assert response.status == expect, (path, response.status, payload[:300])
            return response.headers, payload

        def api(path: str, body: object = None, expect: int = 200):
            return json.loads(raw(path, body, expect)[1])

        react, shop = f'/repos/{DEMO_OWNER}/react', f'/repos/{DEMO_OWNER}/shop'
        package = 'packages/react-server-dom-webpack/'
        assert api(react) == {'full_name': 'asset-monitor-demo/react', 'default_branch': 'main'}
        history = api(react + '/commits?sha=main&per_page=100')
        assert [c['commit']['message'] for c in history] == ['Release 19.0.1', REACT_FIX, 'Release 19.0.0'], history
        release, fix, first = (c['sha'] for c in history)
        assert {c['commit']['author']['name'] for c in history} == {'Demo Maintainer'}
        assert [c['sha'] for c in api(react + '/commits?sha=main&per_page=1&page=2')] == [fix]
        etag = raw(react + '/commits?sha=main&per_page=100')[0]['ETag']
        raw(react + '/commits?sha=main&per_page=100', expect=304, headers={'If-None-Match': etag})
        compared = api(f'{react}/compare/{first}...{release}?per_page=1&page=2')
        assert (compared['status'], compared['total_commits'], [c['sha'] for c in compared['commits']]) == ('ahead', 2, [release]), compared
        assert [c['sha'] for c in api(f'{react}/compare/{first}...{release}')['commits']] == [fix, release]
        assert api(f'{react}/compare/{fix}...{fix}')['status'] == 'identical'
        detail = api(f'{react}/commits/{fix}')
        (changed,) = detail['files']
        assert (changed['filename'], changed['status'], detail['parents']) == (package + 'index.js', 'modified', [{'sha': first}]), detail
        assert changed['patch'].startswith('@@') and '+  if (!own(manifest, module) || !own(manifest[module], name)) return undefined;' in changed['patch']
        root = api(f'{react}/commits/v19.0.0')
        assert (root['sha'], root['parents'], {f['status'] for f in root['files']}) == (first, [], {'added'}), root
        assert [(t['name'], t['commit']['sha']) for t in api(react + '/tags')] == [('v19.0.1', release), ('v19.0.0', first)]
        assert api(react + '/branches/main')['commit']['sha'] == release
        raw(react + '/branches/19.x', expect=404)
        assert api(react + '/releases') == []
        assert raw(f'{react}/contents/{package}index.js?ref=v19.0.0')[1] == STAND_IN['19.0.0']
        print('PASS demo GitHub reads: commits with an ETag, compare, patches, contents, tags and branches')

        (start,) = api(shop + '/commits')
        head = start['sha']
        vendor = 'vendor/react-server-dom-webpack-19.0.0.tgz'
        files = {f['filename']: f for f in api(f'{shop}/commits/{head}')['files']}
        assert 'patch' not in files[vendor] and all('patch' in f for path, f in files.items() if path != vendor), files
        manifest = json.loads(raw(f'{shop}/contents/package.json?ref=main')[1])
        lock = json.loads(raw(f'{shop}/contents/package-lock.json?ref={head}')[1])
        assert lock['packages']['']['dependencies'] == manifest['dependencies'] == {'react-server-dom-webpack': 'file:' + vendor}
        assert lock['packages']['node_modules/react-server-dom-webpack'] == {
            'version': '19.0.0', 'resolved': 'file:' + vendor, 'integrity': npm_dist('19.0.0')['integrity'], 'license': 'MIT'}
        raw(f'{shop}/contents/missing.txt?ref=main', expect=404)
        with tarfile.open(fileobj=io.BytesIO(raw(f'{shop}/tarball/{head}')[1]), mode='r:gz') as bundle:
            prefix = f'{DEMO_OWNER}-shop-{head[:7]}/'
            members = {member.name: member for member in bundle if member.isfile()}
            assert all(name.startswith(prefix) for name in members) and prefix + 'Dockerfile' in members, members
            assert bundle.extractfile(members[prefix + vendor]).read() == NPM_TARBALLS['19.0.0']
        print('PASS the demo Own repository locks the stand-in 19.0.0 as a vendored file: tarball')

        tree = api(f'{shop}/git/commits/{head}')['tree']['sha']
        listed = {entry['path']: entry for entry in api(f'{shop}/git/trees/{tree}?recursive=1')['tree']}
        assert listed['invoices']['type'] == 'tree' and listed['server.js']['sha'] == git_sha((DEMO_CONTENT / 'shop/base/server.js').read_bytes())
        readme = b'# Toko Batik\n'
        blob = api(shop + '/git/blobs', {'content': base64.b64encode(readme).decode(), 'encoding': 'base64'}, 201)['sha']
        assert blob == git_sha(readme)
        tree = api(shop + '/git/trees', {'base_tree': tree, 'tree': [
            {'path': 'README.md', 'mode': '100644', 'type': 'blob', 'sha': blob},
            {'path': 'invoices/INV-1001.txt', 'mode': '100644', 'type': 'blob', 'sha': None}]}, 201)['sha']
        change = api(shop + '/git/commits', {'message': 'Shorten the README', 'tree': tree, 'parents': [head]}, 201)['sha']
        branch = 'asset-monitor/check-patch'
        api(shop + '/git/refs', {'ref': f'refs/heads/{branch}', 'sha': change}, 201)
        for ref in (f'refs/heads/{branch}', 'refs/heads/main'):
            api(shop + '/git/refs', {'ref': ref, 'sha': change}, 422)
        assert api(f'{shop}/git/ref/heads/{branch}')['object']['sha'] == change
        assert api(f'{shop}/git/commits/{change}')['parents'] == [{'sha': head}]
        raw(f'{shop}/contents/invoices/INV-1001.txt?ref={change}', expect=404)
        pull = api(shop + '/pulls', {'title': 'Shorten the README', 'head': branch, 'base': 'main', 'body': 'Shorter.', 'draft': True}, 201)
        assert (pull['number'], pull['html_url'], pull['draft']) == (1, 'https://github.com/asset-monitor-demo/shop/pull/1', True), pull
        assert api(f'{shop}/pulls?head={DEMO_OWNER}:{branch}&state=all') == [pull] == [api(f'{shop}/pulls/1')]
        assert api(f'{shop}/git/ref/heads/main')['object']['sha'] == head
        assert STATE.writes and all(write['path'].startswith(shop + '/') for write in STATE.writes), STATE.writes
        print('PASS a Remediation PR round trip (blob, tree, commit, ref, pull) that never moves main, and heads/main refused')

        pushed = api('/admin/demo/push', {'repository': 'shop', 'commit': '1-invoice-download'})['sha']
        assert api('/admin/demo/push', {'repository': 'shop', 'commit': '1-invoice-download'})['sha'] == pushed
        assert [c['sha'] for c in api(shop + '/commits')] == [pushed, head]
        (changed,) = api(f'{shop}/commits/{pushed}')['files']
        assert changed['filename'] == 'server.js' and '+    const file = path.join(INVOICES, decodeURIComponent(invoice[1]));' in changed['patch']
        assert api(f'{shop}/compare/{change}...{pushed}')['status'] == 'diverged'
        api('/admin/demo/push', {'repository': 'shop', 'commit': '../shop'}, 404)
        print('PASS a prepared commit is pushed onto main once')

        merged = api('/admin/demo/merge', {'repository': 'shop', 'number': 1})
        newest = api(shop + '/commits?sha=main')[0]
        assert (merged['state'], merged['merged'], merged['merge_commit_sha']) == ('closed', True, newest['sha']), merged
        assert (newest['parents'], newest['commit']['message']) == ([{'sha': pushed}], 'Shorten the README (#1)\n\nShorter.'), newest
        assert raw(f'{shop}/contents/README.md?ref=main')[1] == readme
        assert raw(f'{shop}/contents/server.js?ref=main')[1] == (DEMO_CONTENT / 'shop/1-invoice-download/server.js').read_bytes()
        raw(f'{shop}/contents/invoices/INV-1001.txt?ref=main', expect=404)
        assert api('/admin/demo/merge', {'repository': 'shop', 'number': 1}) == api(f'{shop}/pulls/1') == merged
        print('PASS a squash merge whose merge commit main reaches')

        node = {'queries': [{'package': {'ecosystem': 'Bitnami', 'name': 'node'}, 'version': '20.11.1'}]}
        cpe = '/rest/json/cves/2.0?cpeName=' + quote(NODE_CPE)

        def feeds():
            return (api(f'/advisories?cve_id={NODE_CVE}'), api('/osv/v1/querybatch', node)['results'],
                    api('/advisories?ecosystem=npm&affects=react-server-dom-webpack@19.0.0,react@19.0.0'), api(cpe)['totalResults'])

        assert feeds() == ([], [{}], [], 0)
        api('/admin/demo/publish', {'advisory': 'react2shell'})
        assert feeds() == ([], [{}], [GHSA_REACT2SHELL], 0)
        assert api('/advisories?ecosystem=npm&affects=react-server-dom-webpack@19.0.1') == []
        api('/admin/demo/publish', {'advisory': 'node2shell'})
        assert feeds() == ([GHSA_NODE], [{'vulns': [{'id': NODE_OSV, 'modified': OSV_NODE['modified']}]}], [GHSA_REACT2SHELL], 1)
        api('/admin/demo/publish', {'advisory': 'php2shell'}, 400)
        assert api('/admin/state')['published'] == ['node2shell', 'react2shell']
        assert api('/npm/react-server-dom-webpack/19.0.0')['repository']['url'] == 'git+https://github.com/asset-monitor-demo/react.git'
        print('PASS each stand-in advisory is listed only once published')

        env = {'PATH': os.environ.get('PATH', os.defpath), 'HOME': tmp, 'GIT_CONFIG_NOSYSTEM': '1',
               'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
        mirror = Path(tmp, 'mirror.git')
        url = f'{base}/git/{DEMO_OWNER}/react.git'

        def run(*args: str) -> str:
            return subprocess.run(['git', *args], cwd=tmp, env=env, capture_output=True, check=True).stdout.decode()

        run('clone', '--bare', '--filter=blob:none', '--quiet', url, str(mirror))

        def missing() -> list[str]:
            return [line for line in run('-C', str(mirror), 'rev-list', '--objects', '--all', '--missing=print').splitlines() if line.startswith('?')]

        assert missing()  # the blobless clone fetched no blob
        assert '+  if (!own(manifest, module) || !own(manifest[module], name)) return undefined;' in run('-C', str(mirror), 'log', '-p', '--no-color')
        assert not missing()  # git log -p fetched each blob lazily over the clone route
        assert run('-C', str(mirror), 'for-each-ref', '--format=%(refname:strip=2)', '--contains', fix, 'refs/tags/').split() == ['v19.0.1']
        raw(f'/git/{DEMO_OWNER}/react.git/info/refs?service=git-receive-pack', expect=403)
        pushed = subprocess.run(['git', '-C', str(mirror), 'push', '--quiet', url, 'main:refs/heads/pushed'], env=env, capture_output=True)
        assert pushed.returncode != 0 and api(react + '/branches/main')['commit']['sha'] == release
        raw(f'/git/{DEMO_OWNER}/missing.git/info/refs?service=git-upload-pack', expect=404)
        print('PASS a blobless clone over the read-only clone route, with lazy blob fetches and tag containment; pushing refused')

        # The Malicious change's loader decodes to a payload that would only write a marker file.
        script = (DEMO_CONTENT / 'shop/3-install-telemetry/scripts/telemetry.js').read_text()
        chunks = json.loads(re.search(r'_0x3f1a=(\[.*?\]);', script)[1])
        order = [int(index, 16) for index in re.search(r'_0x51c7=\[(.*?)\];', script)[1].split(',')]
        payload = base64.b64decode(''.join(chunks[index] for index in order)).decode()
        assert re.findall(r'require\("([^"]+)"\)', payload) == ['fs'] and 'process' not in payload and 'fetch' not in payload, payload
        assert 'writeFileSync(m,' in payload and 'm="/tmp/.demo-shop-telemetry"' in payload and '"NPM_TOKEN","GITHUB_TOKEN"' in payload, payload
        print('PASS the prepared Malicious change payload is inert: it would only write /tmp/.demo-shop-telemetry')
        server.shutdown()
    print('FIXTURE CHECK PASSED')


if __name__ == '__main__':
    if sys.argv[1:] == ['check']:
        check()
    else:
        initialize_svn()
        if DEMO:
            build_demo(GIT_ROOT)
        ThreadingHTTPServer(('0.0.0.0', 8090), Handler).serve_forever()
