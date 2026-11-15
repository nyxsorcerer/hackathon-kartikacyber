"""Observe the real Compose/API/worker/fixture journey without paid providers.

Run against the isolated asset-monitor-test project. Required provider protocol and
container execution cases live in the backend and runner suites; this journey
proves their application-facing integration, persistence, and human decision
boundaries using the HTTP/SVN/NVD/webhook fixture service.
"""

from __future__ import annotations

import argparse
from http.cookiejar import CookieJar
import hashlib
import json
from pathlib import Path
import re
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPCookieProcessor, Request, build_opener
import uuid

# The gateway's fixed user agent pair for Served-content checks (runner/numen_runner/gateway.py).
USER_AGENTS = {
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
}
# The React2Shell stand-in's n-day PoC (also the demo dry run's, canned_broker.py): its action
# references an inherited member of the server manifest, and it sees the stand-in's marker, never
# anything executed.
R2S_POC = (b'import json,os,sys,time,urllib.error,urllib.request\n'
           b'request=urllib.request.Request(os.environ["TARGET_URL"]+"/action",data=json.dumps({"$$id":"app/actions#constructor"}).encode(),method="POST")\n'
           b'for _ in range(50):\n'
           b'    try:\n        body=urllib.request.urlopen(request,timeout=1).read();break\n'
           b'    except urllib.error.HTTPError as error:\n        body=error.read();break\n'
           b'    except OSError:time.sleep(0.2)\n'
           b'else:sys.exit("the application never answered")\n'
           b'sys.exit(0 if body==b"asset-monitor-simulated-flaw" else 1)\n')


class Client:
    def __init__(self, base: str):
        self.base = base.rstrip('/')
        self.opener = build_opener(HTTPCookieProcessor(CookieJar()))
        self.csrf = None

    def request(self, method: str, path: str, body=None, expect=(200,), headers=None, raw=False):
        data = None
        values = dict(headers or {})
        if body is not None:
            data = json.dumps(body).encode()
            values['Content-Type'] = 'application/json'
        if self.csrf and method not in ('GET', 'HEAD'):
            values['X-CSRF-Token'] = self.csrf
        request = Request(self.base + path, data=data, headers=values, method=method)
        try:
            response = self.opener.open(request, timeout=30)
        except HTTPError as error:
            response = error
        with response:
            payload = response.read()
            if response.status not in expect:
                detail = payload.decode(errors='replace')[:500]
                raise AssertionError(f'{method} {path}: HTTP {response.status}; {detail}')
            if raw:
                return payload
            return json.loads(payload) if payload else None

    def upload(self, path: str, files: dict[str, bytes]):
        boundary = 'numen-journey-' + uuid.uuid4().hex
        data = bytearray()
        for name, content in files.items():
            data.extend(f'--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="{name}"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode())
            data.extend(content)
            data.extend(b'\r\n')
        data.extend(f'--{boundary}--\r\n'.encode())
        request = Request(self.base + path, data=bytes(data), method='POST', headers={
            'Content-Type': f'multipart/form-data; boundary={boundary}',
            'X-CSRF-Token': self.csrf or '',
        })
        try:
            response = self.opener.open(request, timeout=30)
        except HTTPError as error:
            response = error
        with response:
            value = response.read()
            if response.status != 200:
                raise AssertionError(f'Artifact upload HTTP {response.status}: {value.decode(errors="replace")[:500]}')
            return json.loads(value)

    def wait(self, submission: dict, timeout: int = 90):
        ident = submission['job_id']
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            job = self.request('GET', f'/api/jobs/{ident}')
            if job['status'] == 'succeeded':
                return job
            if job['status'] in ('failed', 'cancelled'):
                raise AssertionError(f'Job {job["kind"]} finished {job["status"]}: {job.get("error")}')
            time.sleep(0.5)
        raise AssertionError(f'Job {ident} did not finish within {timeout}s')


def items(value):
    return value['items']


def wait_kind(client, application, kind):
    """Waits for every `kind` job of the Application, such as those another job queued."""
    jobs = items(client.request('GET', f'/api/jobs?application_id={application["id"]}'))
    return [client.wait({'job_id': job['id']}) for job in jobs if job['kind'] == kind]


def check_now(client, application):
    """Check now queues one source check per repository; wait for every one."""
    return [client.wait(queued) for queued in items(client.request('POST', f'/api/applications/{application["id"]}/checks', {}, expect=(202,)))]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base-url', default='http://localhost:18788')
    parser.add_argument('--fixture-url', default='http://localhost:18091')
    parser.add_argument('--password-file', type=Path, default=Path('.numen/bootstrap-password'))
    args = parser.parse_args()
    client = Client(args.base_url)
    fixture = Client(args.fixture_url)
    suffix = uuid.uuid4().hex[:8]
    fixture.request('POST', '/admin/reset', {})
    client.request('GET', '/api/applications', expect=(401,))
    password = args.password_file.read_text().strip()
    session = client.request('POST', '/api/auth/login', {'username': 'admin', 'password': password})
    client.csrf = session['csrf_token']
    assert client.request('GET', '/api/auth/session')['authenticated']
    print('PASS operator login and unauthenticated Application protection')

    # GitHub repositories are never polled without a read token; the fixture accepts any.
    if not [a for a in items(client.request('GET', '/api/accounts')) if a['provider'] == 'github' and a['credential_configured']]:
        client.request('POST', '/api/accounts', {
            'label': 'Fixture GitHub token', 'provider': 'github', 'auth_type': 'api_key',
            'api_key': 'fixture-github-token',
        }, expect=(201,))

    config = {
        'triage_mode': 'disabled',
        'cve_selectors': [
            {'type': 'keyword', 'value': 'Numen Fixture'},
            {'type': 'cpe', 'value': 'cpe:2.3:a:numen:fixture:*:*:*:*:*:*:*:*'},
        ],
        'cve_min_score': 7.0,
        'cve_versions': ['3.1', '4.0'],
        'cve_auto_analyze': False,
    }
    common = {
        'asset_url': 'http://fixtures:8090/target', 'product_name': 'Numen Fixture',
        'monitor_interval_seconds': 300, 'monitor_enabled': False, 'config': config,
    }
    github = client.request('POST', '/api/applications', {
        **common, 'asset_name': f'GitHub fixture {suffix}', 'product_kind': 'CMS',
    }, expect=(200, 201))
    wordpress = client.request('POST', '/api/applications', {
        **common, 'asset_name': f'WordPress fixture {suffix}', 'product_kind': 'plugin',
    }, expect=(200, 201))
    sources = {
        github['id']: {'source_kind': 'github', 'source_url': f'https://github.com/numen/fixture-{suffix}', 'source_ref': 'main'},
        wordpress['id']: {'source_kind': 'wordpress', 'plugin_slug': 'fixture-plugin', 'source_ref': 'trunk'},
    }
    for application in [github, wordpress]:
        client.request('POST', f'/api/applications/{application["id"]}/repositories', sources[application['id']], expect=(201,))
        actual = client.request('GET', f'/api/applications/{application["id"]}')
        assert actual['asset_name'] == application['asset_name']
        assert actual['monitor_interval_seconds'] == 300
        assert actual['monitor_enabled'] is False
        assert [r['role'] for r in actual['repositories']] == ['upstream']
        # The Baseline is the head: nothing earlier is imported, on GitHub or over SVN.
        assert [job['result']['imported'] for job in check_now(client, application)] == [0]
    assert items(client.request('GET', f'/api/applications/{github["id"]}/commits')) == []
    print('PASS persisted GitHub and WordPress Applications and a Baseline that imports no history')

    def svn_cursor():
        return client.request('GET', f'/api/applications/{wordpress["id"]}')['repositories'][0]['cursor']

    def github_revisions():
        commits = items(client.request('GET', f'/api/applications/{github["id"]}/commits'))
        assert len({row['revision'] for row in commits}) == len(commits)
        return commits, {row['revision'] for row in commits}

    # Repositories outlive a journey run (one row per URL), so compare revisions, not counts.
    wp_cursor = svn_cursor()

    fixture.request('POST', '/admin/advance', {'version': '1.2.1'})
    for application in [github, wordpress]:
        check_now(client, application)
    commits, revisions = github_revisions()
    assert revisions == {'b' * 40, 'c' * 40}
    wp_commits = items(client.request('GET', f'/api/applications/{wordpress["id"]}/commits'))
    assert svn_cursor() != wp_cursor and svn_cursor() in {row['revision'] for row in wp_commits}
    jobs = items(client.request('GET', '/api/jobs'))
    assert not [job for job in jobs if job.get('application_id') == github['id'] and job['kind'] in ('commit_triage', 'commit_analysis')]
    print('PASS unseen/old-dated revisions, SVN changes, deduplication, and AI-off boundary')

    repository_id = client.request('GET', f'/api/applications/{github["id"]}')['repositories'][0]['repository_id']
    backfill = client.wait(client.request('POST', f'/api/applications/{github["id"]}/repositories/{repository_id}/backfills', {'count': 1}, expect=(202,)))
    assert backfill['result']['imported'] == 1
    _, revisions = github_revisions()
    assert revisions == {'a' * 40, 'b' * 40, 'c' * 40}
    unchanged = check_now(client, github)[0]['result']
    assert unchanged['not_modified'] is True and unchanged['imported'] == 0
    assert github_revisions()[1] == revisions
    print('PASS Backfill of the Baseline commit and a 304 that imports nothing')

    client.request('PATCH', '/api/settings', {'webhook_url': 'http://fixtures:8090/webhooks/test', 'webhook_enabled': True})
    candidate = next(row for row in commits if row['revision'] == 'b' * 40)
    client.request('POST', f'/api/commits/{candidate["id"]}/review', {'decision': 'candidate'})
    client.request('GET', f'/api/commits/{candidate["id"]}')
    client.request('POST', '/api/settings/webhook/test', expect=(202,))
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if notifications := fixture.request('GET', '/admin/state')['notifications']:
            break
        time.sleep(0.5)
    else:
        raise AssertionError('Webhook test was not delivered to fixture webhook')
    # The candidate mark sends no Alert, so the test delivery is the only one.
    (delivery,) = notifications
    assert delivery['content'].startswith('Asset Monitor: Webhook test')
    assert delivery['allowed_mentions'] == {'parse': []} and 'embeds' not in delivery
    assert not [job for job in items(client.request('GET', '/api/jobs')) if job.get('application_id') == github['id'] and job['kind'] == 'commit_analysis']
    client.request('POST', f'/api/commits/{candidate["id"]}/analyses', {}, expect=(409, 422))
    print('PASS fixed-template webhook test delivery, no Alert for a candidate mark, and explicit analysis/profile prerequisite')

    client.wait(client.request('POST', f'/api/applications/{github["id"]}/cve-sync', {}, expect=(202,)))
    cves = items(client.request('GET', f'/api/cves?application_id={github["id"]}'))
    assert {'CVE-2026-99001', 'CVE-2026-99002'}.issubset({row['id'] for row in cves})
    for cve in cves:
        client.request('POST', f'/api/applications/{github["id"]}/cves/{cve["id"]}/match', {'confirmed': True})
    eligible = items(client.request('GET', f'/api/cves?application_id={github["id"]}'))
    scored = next(row for row in eligible if row['id'] == 'CVE-2026-99001')
    unscored = next(row for row in eligible if row['id'] == 'CVE-2026-99002')
    assert scored['eligible'] is True and unscored['eligible'] is False
    client.request('POST', f'/api/applications/{github["id"]}/cves/CVE-2026-99002/analyses', {}, expect=(409, 422))
    fixture.request('POST', '/admin/advance', {'score': 6.9})
    client.wait(client.request('POST', f'/api/applications/{github["id"]}/cve-sync', {}, expect=(202,)))
    scored = next(row for row in items(client.request('GET', f'/api/cves?application_id={github["id"]}')) if row['id'] == 'CVE-2026-99001')
    assert scored['eligible'] is False
    client.request('POST', f'/api/applications/{github["id"]}/cves/CVE-2026-99001/analyses', {}, expect=(409, 422))
    print('PASS inclusive CVSS gate, missing-score rejection, and modified-record refresh')

    finding = client.request('POST', '/api/findings', {
        'application_id': github['id'], 'source': 'commit', 'title': f'Fixture metadata boundary {suffix}',
        'source_commit_id': candidate['id'],
        'affected_versions': ['1.2.0'], 'fixed_versions': ['1.2.1'],
    }, expect=(200, 201))
    assert finding['status'] == 'open'
    assert finding['artifact_state']['status'] == 'draft'
    # A tiny Node app with no dependencies, so the Lab's `npm ci` needs no registry: its /debug
    # route leaks a secret, and the PoC reads it through TARGET_URL.
    files = {
        'poc.py': b'import os,sys,time,urllib.request\nfor _ in range(50):\n    try:\n        body=urllib.request.urlopen(os.environ["TARGET_URL"]+"/debug",timeout=1).read();break\n    except OSError:time.sleep(0.2)\nelse:sys.exit("the application never answered")\nsys.exit(0 if b"secret=" in body else 1)\n',
        'report.md': b'# Fixture metadata boundary\n\nControlled integration fixture, not a real finding.\n\nUpstream fixed: 1.2.1. Remote deployment status remains independent.\n',
        'vulnerable-app/Dockerfile': b'FROM asset-monitor-lab:0.1.0\nWORKDIR /app\nCOPY . /app/\nCMD ["node", "server.js"]\n',
        'vulnerable-app/package.json': b'{"name": "journey-fixture", "version": "1.2.0", "private": true}\n',
        'vulnerable-app/package-lock.json': json.dumps({'name': 'journey-fixture', 'version': '1.2.0', 'lockfileVersion': 3, 'requires': True, 'packages': {'': {'name': 'journey-fixture', 'version': '1.2.0'}}}).encode(),
        'vulnerable-app/server.js': b'require("http").createServer((q, r) => r.end(q.url === "/debug" ? "secret=fixture" : "ok")).listen(8080);\n',
        'vulnerable-app/compose.yaml': b'services:\n  app:\n    build: .\n    ports: ["127.0.0.1:18080:8080"]\n',
        'vulnerable-app/README.md': b'# Fixture app\nRun docker compose up --build. Version: 1.2.0.\n',
        'vulnerable-app/application.lock.json': json.dumps({'version': '1.2.0', 'fixture': True, 'local_inputs': {'Dockerfile': 'Controlled integration fixture', 'server.js': 'Controlled integration fixture'}, 'images': ['asset-monitor-lab:0.1.0']}).encode(),
    }
    finding = client.upload(f'/api/findings/{finding["id"]}/artifacts', files)
    assert finding['artifact_state']['status'] == 'complete'
    assert {'poc.py', 'report.md', 'vulnerable-app/Dockerfile', 'manifest.json'} <= {a['path'] for a in finding['artifacts']}
    # A15: an Upstream Proof is never exported, overriding Numen's AC-12 for an Upstream Finding.
    assert finding['exportable'] is False
    refused = client.request('GET', f'/api/findings/{finding["id"]}/download', expect=(403,))
    assert refused['code'] == 'upstream_proof_not_exported'
    assert client.request('GET', f'/api/findings/{finding["id"]}')['status'] == 'open'
    print('PASS draft/completed finding bundle, its Upstream download refused, and independent upstream status')

    # A15: every Approval carries the password; A07: the Lab builds and runs offline on the real Engine.
    refused = client.request('POST', f'/api/findings/{finding["id"]}/lab-runs', {'password': 'wrong-' + suffix}, expect=(403,))
    assert refused['code'] == 'approval_refused'
    lab = client.wait(client.request('POST', f'/api/findings/{finding["id"]}/lab-runs', {'password': password}, expect=(202,)), timeout=600)
    finding = client.request('GET', f'/api/findings/{finding["id"]}')
    assert finding['lab_runs'][0]['status'] == 'verified', finding['lab_runs']
    assert finding['status'] == 'confirmed' and finding['cause']['by'] == 'proof'
    assert [e for e in finding['events'] if e.get('action') == 'approved' and e.get('job_id') == lab['id']]
    print('PASS Approval refuses a wrong password, then a Lab on the real Engine reproduces the Proof and confirms the Finding')

    # A08: a Remediation PR on an Own repository, through the fixture GitHub API with the write token.
    write_token = 'github_pat_fixture-write-token'
    if not [a for a in items(client.request('GET', '/api/accounts')) if a['provider'] == 'github_write' and a['credential_configured']]:
        client.request('POST', '/api/accounts', {
            'label': 'Fixture GitHub write token', 'provider': 'github_write', 'auth_type': 'api_key',
            'api_key': write_token,
        }, expect=(201,))
    own_repo = f'numen/fixture-{uuid.uuid4().hex[:8]}'
    own = client.request('POST', '/api/applications', {
        **common, 'asset_name': f'Own fixture {suffix}', 'product_kind': 'CMS',
    }, expect=(200, 201))
    client.request('POST', f'/api/applications/{own["id"]}/repositories', {
        'role': 'own', 'source_kind': 'github', 'source_url': f'https://github.com/{own_repo}', 'source_ref': 'main',
    }, expect=(201,))
    check_now(client, own)
    (link,) = client.request('GET', f'/api/applications/{own["id"]}')['repositories']
    assert link['baseline_revision'] == 'b' * 40
    client.wait(client.request('POST', f'/api/applications/{own["id"]}/repositories/{link["repository_id"]}/backfills', {'count': 1}, expect=(202,)))
    (change,) = items(client.request('GET', f'/api/applications/{own["id"]}/commits'))
    assert change['revision'] == 'b' * 40
    own_finding = client.request('POST', '/api/findings', {
        'application_id': own['id'], 'source': 'commit', 'title': f'Fixture Own change {suffix}',
        'source_commit_id': change['id'],
    }, expect=(200, 201))
    client.wait(client.request('POST', f'/api/findings/{own_finding["id"]}/remediation-prs', {'action': 'revert'}, expect=(202,)))
    (draft,) = client.request('GET', f'/api/findings/{own_finding["id"]}')['remediation_prs']
    assert (draft['status'], draft['paths']) == ('ready', ['VERSION']), draft
    assert '-1.2.1\n+1.2.0\n' in draft['diff']
    approvals = f'/api/findings/{own_finding["id"]}/remediation-prs/{draft["id"]}/approvals'
    refused = client.request('POST', approvals, {'password': 'wrong-' + suffix, 'diff_sha256': draft['diff_sha256']}, expect=(403,))
    assert refused['code'] == 'approval_refused' and fixture.request('GET', '/admin/state')['writes'] == []
    opened = client.wait(client.request('POST', approvals, {'password': password, 'diff_sha256': draft['diff_sha256']}, expect=(202,)))
    (pr,) = client.request('GET', f'/api/findings/{own_finding["id"]}')['remediation_prs']
    assert (pr['status'], pr['pull_number'], pr['branch']) == ('open', 1, 'asset-monitor/bbbbbbb-revert'), pr
    again = client.request('POST', approvals, {'password': password, 'diff_sha256': draft['diff_sha256']}, expect=(202,))
    assert again['job_id'] == opened['id']
    state = fixture.request('GET', '/admin/state')
    (pull,) = state['pulls']
    assert (pull['draft'], pull['head']['ref'], pull['base']['ref']) == (True, 'asset-monitor/bbbbbbb-revert', 'main')
    # Every write went to the Own repository (the fixture refuses any write to main).
    assert state['writes'] and all(w['path'].startswith(f'/repos/{own_repo}/') for w in state['writes'])
    for job in items(client.request('GET', f'/api/jobs?application_id={own["id"]}')):
        seen = [client.request('GET', f'/api/jobs/{job["id"]}'), client.request('GET', f'/api/jobs/{job["id"]}/events')]
        assert write_token not in json.dumps(seen), job['kind']
    print('PASS Remediation PR Approval refuses a wrong password, then opens exactly one draft pull request on the Own repository')

    # React2Shell (A05-A07, A15): an Own Node app locks a harmless stand-in of
    # react-server-dom-webpack@19.0.0 from the fixture registry, whose metadata names numen/react-fixture.
    node = client.request('POST', '/api/applications', {
        **common, 'asset_name': f'React2Shell fixture {suffix}', 'product_kind': 'CMS',
    }, expect=(200, 201))
    client.request('POST', f'/api/applications/{node["id"]}/repositories', {
        'role': 'own', 'source_kind': 'github', 'source_url': f'https://github.com/numen/node-app-{suffix}', 'source_ref': 'main',
    }, expect=(201,))
    check_now(client, node)
    (derived,) = wait_kind(client, node, 'derive_upstreams')
    assert derived['result']['added'] == ['https://github.com/numen/react-fixture'], derived['result']
    upstream = next(r for r in client.request('GET', f'/api/applications/{node["id"]}')['repositories'] if r['role'] == 'upstream')
    assert (upstream['packages'], upstream['locked_version'], upstream['locked_version_source']) == (['npm:react-server-dom-webpack'], '19.0.0', 'manifest'), upstream
    check_now(client, node)
    client.wait(client.request('POST', f'/api/applications/{node["id"]}/repositories/{upstream["repository_id"]}/backfills', {'count': 1}, expect=(202,)))
    # Repositories outlive a run, so any stored commit of the Upstream repository will do.
    upstream_commit = next(row for row in items(client.request('GET', f'/api/applications/{node["id"]}/commits')) if row['repository_id'] == upstream['repository_id'])
    # Operator-opened, so it carries no Exposure row; Exposure itself is proven by test_exposure.py.
    r2s = client.request('POST', '/api/findings', {
        'application_id': node['id'], 'source': 'commit', 'title': f'React2Shell stand-in {suffix}',
        'source_commit_id': upstream_commit['id'], 'affected_versions': ['19.0.0'], 'fixed_versions': ['19.0.1'],
    }, expect=(200, 201))
    disclosure = b'# Server action reference trusted before validation\n\nControlled integration fixture for the numen/react-fixture maintainers, not a real report.\n'
    # The Lab supplies package.json, package-lock.json and server.js from the Own head, with the
    # Locked version vendored. The PoC's action references an inherited member of the server
    # manifest; it sees the stand-in's marker, never anything executed.
    r2s_files = {
        'poc.py': R2S_POC,
        'report.md': b'# React2Shell stand-in\n\nControlled integration fixture, not a real finding: an action whose server reference names an inherited member is answered with a marker.\n',
        'disclosure-report.md': disclosure,
        'vulnerable-app/Dockerfile': b'FROM asset-monitor-lab:0.1.0\nWORKDIR /app\nCOPY . /app/\nCMD ["node", "server.js"]\n',
        'vulnerable-app/compose.yaml': b'services:\n  app:\n    build: .\n    ports: ["127.0.0.1:18080:8080"]\n',
        'vulnerable-app/README.md': b'# Node app\nThe Own repository head with react-server-dom-webpack at its Locked version. Run docker compose up --build.\n',
        'vulnerable-app/application.lock.json': json.dumps({'version': '19.0.0', 'fixture': True, 'local_inputs': {'Dockerfile': 'Controlled integration fixture'}, 'images': ['asset-monitor-lab:0.1.0']}).encode(),
    }
    r2s = client.upload(f'/api/findings/{r2s["id"]}/artifacts', r2s_files)
    assert r2s['artifact_state']['status'] == 'complete', r2s['artifact_state']
    assert r2s['disclosure_report'] == {'text': disclosure.decode(), 'form_url': 'https://github.com/numen/react-fixture/security/advisories/new'}, r2s['disclosure_report']
    assert r2s['exportable'] is False
    assert client.request('GET', f'/api/findings/{r2s["id"]}/download', expect=(403,))['code'] == 'upstream_proof_not_exported'
    paths = {a['path']: a['id'] for a in r2s['artifacts']}
    assert client.request('GET', f'/api/artifacts/{paths["poc.py"]}/content', expect=(403,))['code'] == 'upstream_proof_not_exported'
    assert client.request('GET', f'/api/artifacts/{paths["report.md"]}/content', raw=True) == r2s_files['report.md']
    print('PASS an Upstream Finding shows its Disclosure report for copying, and its Proof is never exported')

    labs = f'/api/findings/{r2s["id"]}/lab-runs'
    assert client.request('POST', labs, {'password': 'wrong-' + suffix}, expect=(403,))['code'] == 'approval_refused'
    client.wait(client.request('POST', labs, {'password': password}, expect=(202,)), timeout=600)
    r2s = client.request('GET', f'/api/findings/{r2s["id"]}')
    run = r2s['lab_runs'][0]
    assert run['status'] == 'verified', run
    assert (run['packages'], run['locked_version'], run['own_ref']) == (['react-server-dom-webpack'], '19.0.0', 'd' * 40), run
    assert r2s['status'] == 'confirmed' and r2s['cause']['by'] == 'proof'
    print('PASS React2Shell stand-in 19.0.0 reproduces in a Lab after Approval')

    link = f'/api/applications/{node["id"]}/repositories/{upstream["repository_id"]}'
    assert client.request('PATCH', link, {'locked_version': '19.0.1'})['locked_version'] == '19.0.1'
    wait_kind(client, node, 'exposure_check')  # none is queued while the repository has no Verdict
    client.wait(client.request('POST', labs, {'password': password}, expect=(202,)), timeout=600)
    after = client.request('GET', f'/api/findings/{r2s["id"]}')
    run = after['lab_runs'][0]
    assert (run['status'], run['locked_version']) == ('not_reproduced', '19.0.1'), run
    assert (after['status'], after['cause']) == (r2s['status'], r2s['cause'])
    print('PASS the fixed 19.0.1 stand-in shows Not reproduced and leaves the Finding as it was')

    # The Advisory check (A09, A06): an Own repository pinning Node 20.11.1 in its Dockerfile and
    # .nvmrc, matched against the fixture's OSV, GHSA and NVD routes, which each list CVE-2026-111497.
    cve, ghsa_id, osv_id = 'CVE-2026-111497', 'GHSA-9c4w-m7v2-x5qh', 'BIT-node-2026-111497'
    advisory = client.request('POST', '/api/applications', {
        **common, 'asset_name': f'Advisory fixture {suffix}', 'product_kind': 'CMS',
    }, expect=(200, 201))
    client.request('POST', f'/api/applications/{advisory["id"]}/repositories', {
        'role': 'own', 'source_kind': 'github', 'source_url': f'https://github.com/numen/advisory-app-{suffix}', 'source_ref': 'main',
    }, expect=(201,))
    check_now(client, advisory)
    checks = f'/api/applications/{advisory["id"]}/advisory-checks'
    first = client.wait(client.request('POST', checks, {}, expect=(202,)))
    wait_kind(client, advisory, 'advisory_check')  # and any the scheduler queued
    wait_kind(client, advisory, 'remediation_draft')
    assert (first['result']['runtimes'], first['result']['opened']) == (2, 1), first['result']

    def advisory_findings():
        return [(f['id'], f['source'], f['source_ref']) for f in items(client.request('GET', f'/api/findings?application_id={advisory["id"]}'))]

    def advisory_alerts():
        return [n for n in fixture.request('GET', '/admin/state')['notifications']
                if f'Application: Advisory fixture {suffix}' in n['content']]

    ((finding_id, source, ref),) = advisory_findings()
    assert (source, ref) == ('advisory', cve)
    found = client.request('GET', f'/api/findings/{finding_id}')
    (match,) = found['advisories']
    assert (match['vulnerability'], match['state'], match['feeds']) == (cve, 'exposed', ['ghsa', 'nvd', 'osv']), match
    assert {ghsa_id, osv_id} <= set(match['aliases'])
    (pin,) = match['pins']
    assert (pin['name'], pin['version'], pin['sources']) == ('node', '20.11.1', ['Dockerfile', '.nvmrc']), pin
    assert pin['ranges'] == {'osv': [[['>=', '20.0.0'], ['<', '20.19.5']], [['>=', '22.0.0'], ['<', '22.12.0']]],
                             'nvd': [[['>=', '20.0.0'], ['<', '20.19.5']]]}, pin
    assert match['report'].startswith(f'{cve} (also ') and 'osv: >=20.0.0 <20.19.5 || >=22.0.0 <22.12.0' in match['report']
    # The bump to the lowest fixed version, drafted by application code, waits for Approval; no Lab.
    (bump,) = found['remediation_prs']
    assert (bump['action'], bump['status'], bump['subject']) == ('bump', 'ready', cve), bump
    assert '-FROM node:20.11.1-alpine\n' in bump['diff'] and '+FROM node:20.19.5-alpine\n' in bump['diff'], bump['diff']
    refused = client.request('POST', f'/api/findings/{finding_id}/lab-runs', {'password': password}, expect=(409,))
    assert refused['code'] == 'lab_not_allowed'
    deadline = time.monotonic() + 30
    while not advisory_alerts() and time.monotonic() < deadline:
        time.sleep(0.5)
    (alert,) = advisory_alerts()
    assert alert['content'].startswith('Asset Monitor: Advisory\n') and f'Source: {cve}' in alert['content'], alert
    # The next check opens no duplicate and sends no second Alert.
    again = client.wait(client.request('POST', checks, {}, expect=(202,)))
    assert (again['result']['matches'], again['result']['opened']) == (1, 0), again['result']
    assert advisory_findings() == [(finding_id, 'advisory', cve)] and len(advisory_alerts()) == 1
    # Every feed request went to a fixture route.
    feeds = {p for p in fixture.request('GET', '/admin/state')['requests'] if p.startswith(('/osv/', '/advisories', '/rest/json/cves/2.0'))}
    assert {'/osv/v1/querybatch', '/advisories'} <= feeds <= {'/osv/v1/querybatch', f'/osv/v1/vulns/{osv_id}', '/advisories', '/rest/json/cves/2.0'}, feeds
    print('PASS the Advisory check opens exactly one advisory Finding for a Dockerfile node pin across OSV, GHSA and NVD, and a second check opens none')

    # Served-content checks (A10) through the real gateway, which reaches the fixture's judol and
    # ClickFix pages only because this test override names the isolated asset-monitor-test-served network.
    served = client.request('POST', '/api/applications', {
        **common, 'asset_url': 'http://fixtures:8090/served/', 'asset_name': f'Served fixture {suffix}', 'product_kind': 'CMS',
    }, expect=(200, 201))
    watched = f'/api/applications/{served["id"]}/watched-pages'
    (home,) = items(client.request('GET', watched))
    assert (home['url'], home['homepage']) == (served['asset_url'], True), home
    verify = client.request('POST', watched, {'url': 'http://fixtures:8090/served/verify'}, expect=(201,))
    assert client.request('DELETE', f'{watched}/{home["id"]}', expect=(409,))['code'] == 'homepage_required'

    def served_check():
        """The Asset's Check now: {(page id, user agent): its row on the Served content tab}."""
        client.wait(client.request('POST', f'/api/applications/{served["id"]}/served-content-checks', {}, expect=(202,)), timeout=300)
        return {(page['id'], row['user_agent']): row for page in items(client.request('GET', watched)) for row in page['user_agents']}

    rows = served_check()
    assert len(rows) == 4 and {row['state'] for row in rows.values()} == {'awaiting_baseline'}, rows
    for (page_id, _), row in rows.items():
        client.request('POST', f'{watched}/{page_id}/baselines', {'fetch_id': row['latest']['id']})
    rows = served_check()
    # AC-A10: the homepage's rotating CSRF token, nonce, bundler hash and minified names change nothing.
    assert {row['state'] for row in rows.values()} == {'matches'}, rows
    print('PASS a Served-content check fetches each Watched page as browser and Googlebot, and the accepted Baseline survives rotating tokens and bundler hashes')

    fixture.request('POST', '/admin/served', {'variants': ['judol', 'clickfix']})
    rows = served_check()
    googlebot, browser = rows[home['id'], 'googlebot'], rows[home['id'], 'browser']
    assert googlebot['state'] == 'changed' and 'slot-gacor.test' in googlebot['diff']['link_hosts']['added'], googlebot
    assert (browser['state'], browser['diff']) == ('matches', {}), browser
    for agent in ('browser', 'googlebot'):
        row = rows[verify['id'], agent]
        assert row['state'] == 'changed' and row['diff']['script_hosts']['added'] == ['cdn.clickfix-fixture.test'], row
    print('PASS gambling links served only to Googlebot change only its fingerprint, and the ClickFix loader host changes both')

    seen = fixture.request('GET', '/admin/state')['served_requests']
    assert '/served/executed' not in {r['path'] for r in seen}, seen
    assert {r['user_agent'] for r in seen if r['path'] == '/served/beacon.js'} == USER_AGENTS, seen
    # Only the page and its scripts were requested, all from the fixture: no link was followed.
    hosts = {urlsplit(r['url']).hostname for row in rows.values() for r in row['latest']['resources']}
    assert hosts == {'fixtures', 'cdn.clickfix-fixture.test'}, hosts
    assert not [job for job in items(client.request('GET', f'/api/jobs?application_id={served["id"]}')) if job['kind'] == 'served_triage']
    print('PASS no fetched script ran, both fixed user agents fetched the scripts, and Triage off starts no served Triage')

    # Push webhooks (B02): the fixture's GitHub push stand-in numen/push-app-<run> sends signed Push
    # deliveries to ingress-push over the test overlay's stand-ins network, and the scheduler's
    # nudge turns an accepted one into a source check. Scheduled monitoring stays off throughout.
    push_repo = f'numen/push-app-{suffix}'
    pushed = client.request('POST', '/api/applications', {
        **common, 'asset_name': f'Push fixture {suffix}', 'product_kind': 'CMS',
    }, expect=(200, 201))
    client.request('POST', f'/api/applications/{pushed["id"]}/repositories', {
        'role': 'own', 'source_kind': 'github', 'source_url': f'https://github.com/{push_repo}', 'source_ref': 'main',
    }, expect=(201,))
    assert [job['result']['imported'] for job in check_now(client, pushed)] == [0]
    (link,) = client.request('GET', f'/api/applications/{pushed["id"]}')['repositories']
    push_webhook = f'/api/applications/{pushed["id"]}/repositories/{link["repository_id"]}/push-webhook'
    shown = client.request('POST', push_webhook, {}, expect=(201,))
    assert set(shown) == {'path', 'secret'} and shown['path'].startswith('/push/'), shown

    def webhook_row():
        return client.request('GET', f'/api/applications/{pushed["id"]}')['repositories'][0]['push_webhook']

    def source_checks():
        return {job['id'] for job in items(client.request('GET', f'/api/jobs?application_id={pushed["id"]}')) if job['kind'] == 'source_check'}

    # As GitHub does, registering the hook sends a ping. The listener knows a new push id only after
    # its next 15 s refresh and answers 404 until then, so redeliver the ping until it is accepted.
    ping = fixture.request('POST', '/admin/hooks', {'repository': push_repo, 'url': f'http://ingress-push:8083{shown["path"]}', 'secret': shown['secret']})
    deadline = time.monotonic() + 30
    while ping['status'] != 200:
        assert ping['status'] == 404 and time.monotonic() < deadline, ping
        time.sleep(1)
        ping = fixture.request('POST', '/admin/hooks/redeliver', {'delivery_id': ping['delivery_id']})
    assert webhook_row()['last_accepted']['event'] == 'ping'
    print('PASS a Push webhook set up on the Own repository accepts its signed ping within the 15 s refresh, and the repository shows it')

    checked = source_checks()
    delivered = fixture.request('POST', '/admin/push', {'repository': push_repo})
    (delivery,) = delivered['deliveries']
    assert delivery['status'] == 200, delivered
    # No Check now: within one scheduler loop the nudge queues exactly one source check.
    deadline = time.monotonic() + 60
    while not (nudged := source_checks() - checked):
        assert time.monotonic() < deadline, 'no source check followed the Push delivery'
        time.sleep(1)
    (nudge,) = nudged
    assert client.wait({'job_id': nudge})['result']['imported'] == 1
    revisions = {row['revision'] for row in items(client.request('GET', f'/api/applications/{pushed["id"]}/commits'))}
    assert delivered['sha'] in revisions and 'f' * 40 not in revisions, revisions
    print('PASS a Push delivery imports the pushed commit through the GitHub API with no Check now, and never a commit listed only in its payload')

    redelivered = fixture.request('POST', '/admin/hooks/redeliver', {'delivery_id': delivery['delivery_id']})
    replayed = fixture.request('POST', '/admin/hooks/replay', {'delivery_id': delivery['delivery_id']})
    (forged,) = fixture.request('POST', '/admin/hooks/forge', {'repository': push_repo})['deliveries']
    assert (redelivered['status'], replayed['status'], forged['status']) == (200, 200, 401), (redelivered, replayed, forged)
    time.sleep(20)  # more than one scheduler loop
    assert source_checks() == checked | nudged
    row = webhook_row()
    assert (row['last_accepted']['event'], row['last_accepted']['delivery_id']) == ('push', delivery['delivery_id']), row
    assert row['last_refusal']['reason'] == 'wrong_signature', row
    print('PASS a redelivery and a replayed body queue no second check, and a forged delivery is refused and the repository shows why')

    client.request('DELETE', push_webhook)
    assert webhook_row() is None
    (gone,) = fixture.request('POST', '/admin/push', {'repository': push_repo})['deliveries']
    assert gone['status'] == 404, gone
    print('PASS after Turn off the old push id is refused at once')

    # On-server agent (B04): server-standin runs the real Go agent binary on the stand-ins network.
    # The fixture drops the enroll command's values and the Enrollment code for it; the agent enrolls
    # over https://ingress-agent:8084, pinned to NUMEN_AGENT_TLS_PIN, and the scheduler verifies
    # each stored request again within one loop.
    server = client.request('POST', '/api/applications', {
        **common, 'asset_name': f'Server fixture {suffix}', 'product_kind': 'CMS',
    }, expect=(200, 201))
    agents_path = f'/api/applications/{server["id"]}/agents'
    agent_url = client.request('GET', agents_path)['agent_url']
    assert agent_url == 'https://ingress-agent:8084', agent_url
    added = client.request('POST', agents_path, {'name': f'web-{suffix}', 'url': agent_url}, expect=(201,))
    enrollment, agent_id = added['enrollment'], added['agent']['id']
    for value in (agent_url, enrollment['tls_pin'], enrollment['dashboard_key'], enrollment['key_id'], agent_id):
        assert value and value in enrollment['command'], (value, enrollment['command'])
    assert enrollment['code'] not in enrollment['command'] and enrollment['code'] not in json.dumps(client.request('GET', agents_path))
    # The stand-in web root outlives a failed run: the file this run drops must not be in its Baseline.
    shell_path = 'wp-content/uploads/cache.php'
    fixture.request('POST', '/admin/server-files', {'remove': [shell_path]})
    dropped = fixture.request('POST', '/admin/server/enroll', {key: enrollment[key] for key in (
        'url', 'tls_pin', 'dashboard_key', 'key_id', 'agent_id', 'code')})

    def enroll_result(number):
        return next((run for run in fixture.request('GET', '/admin/state')['server']['enroll_results']
                     if run['number'] == number), None)

    def agent_row():
        return next(row for row in items(client.request('GET', agents_path)) if row['id'] == agent_id)

    def wait_agent(ready, what, timeout=120):
        deadline = time.monotonic() + timeout
        while not ready(row := agent_row()):
            assert time.monotonic() < deadline, f'{what}: {row}'
            time.sleep(1)
        return row

    deadline = time.monotonic() + 120
    while (enrolled := enroll_result(dropped['number'])) is None:
        assert time.monotonic() < deadline, 'the stand-in server never ran enroll'
        time.sleep(1)
    assert enrolled['returncode'] == 0, enrolled
    fingerprint = re.search(r'Agent key fingerprint: (sha256:[0-9a-f]{64})', enrolled['stdout'])[1]
    row = wait_agent(lambda row: row['status'] == 'pending', 'the Enrollment was not bound')
    assert (row['fingerprint'], row['allowed_paths']) == (fingerprint, ['/var/www/html']), row
    assert row['configuration'] is None and row['commands'] == [], row
    print('PASS the real agent enrolls through the stand-in server over pinned TLS, and the agent shows as pending with the fingerprint enroll printed and its Allowed paths')

    confirmed = client.request('POST', f'/api/agents/{agent_id}/confirmations', {'fingerprint': fingerprint})
    assert (confirmed['status'], confirmed['watched_roots']) == ('enrolled', ['/var/www/html']), confirmed
    row = wait_agent(lambda row: row['last_seen_at'] and (row['configuration'] or {}).get('status') == 'done',
                     'the agent never accepted its signed configuration')
    assert row['config_sequence'] == row['configuration']['sequence'] == 1, row
    print('PASS Confirm fingerprint signs the first configuration, and the agent polls, verifies and accepts it')

    command = client.request('POST', f'/api/agents/{agent_id}/rescans', {}, expect=(202,))
    row = wait_agent(lambda row: any(listed['id'] == command['id'] and listed['status'] == 'done'
                                     for listed in row['commands']), 'the rescan command never ran', 90)
    assert row['last_refusal'] is None or row['last_refusal']['route'] != 'result', row
    print('PASS Check now signs a rescan command that the agent runs once and answers done')

    # B05: the agent reports File manifests; the scheduler verifies each report again, asks for the
    # bytes it does not hold and holds what the agent uploads. The first one becomes the Baseline only
    # when the Operator accepts it, by its SHA-256 (not an Approval: no password).
    row = wait_agent(lambda row: (row['latest_manifest'] or {}).get('status') == 'complete'
                     and row['latest_manifest']['sequence'] >= row['report_sequence'] > 0,
                     'no complete File manifest', 120)
    manifest = row['latest_manifest']
    assert (row['baseline'], row['accept_allowed'], row['changes']) == (None, True, []), row
    stale = client.request('POST', f'/api/agents/{agent_id}/baselines',
                           {'manifest_id': manifest['id'], 'manifest_sha256': '0' * 64}, expect=(409,))
    assert stale['code'] == 'manifest_changed', stale
    accepted = client.request('POST', f'/api/agents/{agent_id}/baselines',
                              {'manifest_id': manifest['id'], 'manifest_sha256': manifest['sha256']})
    assert accepted['baseline']['manifest_id'] == manifest['id'] and not accepted['accept_allowed'], accepted
    print('PASS the first File manifest is reported, verified again and accepted as the Baseline by its SHA-256')

    # A webshell-like inert PHP file dropped on the server (if run it would only print a marker;
    # nothing runs it) is one Server change after Check now, with its bytes held.
    shell = ("<?php /* stand-in dropped shell: if run it would only print a marker */ "
             "if (isset($_GET['c'])) { echo 'asset-monitor-fixture'; } ?>")
    fixture.request('POST', '/admin/server-files', {'write': {shell_path: shell}})
    client.request('POST', f'/api/agents/{agent_id}/rescans', {}, expect=(202,))
    row = wait_agent(lambda row: row['changes'], 'the dropped file never became a Server change', 180)
    (change,) = row['changes']
    added = [entry for entry in change['diff']['added'] if entry['path'] == shell_path]
    sha = hashlib.sha256(shell.encode()).hexdigest()
    assert len(added) == 1 and added[0]['sha256'] == sha and sha in change['held'], change
    assert (change['diff']['modified'], change['diff']['removed'], change['triage_status']) == ([], [], 'disabled'), change
    assert change['baseline_manifest_id'] == manifest['id'] and not change['incomplete'], change
    sequence = row['latest_manifest']['sequence']
    client.request('POST', f'/api/agents/{agent_id}/rescans', {}, expect=(202,))
    row = wait_agent(lambda row: row['latest_manifest']['sequence'] > sequence
                     and row['latest_manifest']['status'] == 'complete', 'the second rescan never reported', 120)
    assert [listed['id'] for listed in row['changes']] == [change['id']], row['changes']
    assert 'cache.php' not in json.dumps(fixture.request('GET', '/admin/state')['served_requests'])
    print('PASS a dropped PHP file is exactly one Server change with its bytes held, a second rescan adds none, and nothing requested it')

    # B07: Quarantine and Restore, each only after an Approval with the password on that request.
    # Triage is off, so the Operator opens the server_files Finding by hand on the Server change.
    opened = client.request('POST', '/api/findings', {
        'application_id': server['id'], 'source': 'server_files', 'title': 'A dropped PHP shell',
        'source_server_change_id': change['id']}, expect=(201,))
    named = [{'root': '/var/www/html', 'path': shell_path, 'sha256': sha}]
    assert (opened['source_ref'], opened['server_files'], opened['quarantine']['list']) == (
        f'web-{suffix}', named, named), opened
    quarantines = f'/api/findings/{opened["id"]}/quarantines'
    list_sha256 = opened['quarantine']['list_sha256']

    def shell_finding():
        return client.request('GET', f'/api/findings/{opened["id"]}')

    def wait_finding(ready, what, timeout=180):
        deadline = time.monotonic() + timeout
        while not ready(found := shell_finding()):
            assert time.monotonic() < deadline, f'{what}: {found}'
            time.sleep(1)
        return found

    def server_alerts():
        return [n for n in fixture.request('GET', '/admin/state')['notifications']
                if f'Application: Server fixture {suffix}' in n['content']]

    refused = client.request('POST', quarantines, {'password': 'wrong-' + suffix, 'list_sha256': list_sha256}, expect=(403,))
    assert refused['code'] == 'approval_refused' and shell_finding()['quarantine']['commands'] == [], refused
    command = client.request('POST', quarantines, {'password': password, 'list_sha256': list_sha256}, expect=(202,))
    found = wait_finding(lambda f: f['status'] == 'remediated' and f['quarantine']['commands'][0]['status'] == 'done',
                         'the Quarantine never remediated the Finding')
    (done,) = found['quarantine']['commands']
    (moved,) = done['files']
    assert (done['id'], moved['path'], moved['sha256'], moved['status']) == (command['id'], shell_path, sha, 'quarantined'), done
    assert found['cause']['by'] == 'manifest', found['cause']
    listing = fixture.request('GET', '/admin/state')['server']['quarantine']
    assert {f'{moved["quarantine_id"]}.bin', f'{moved["quarantine_id"]}.json'} <= set(listing), listing
    assert server_alerts() == []
    print('PASS Quarantine refuses a wrong password, then the real agent moves the named file into its Quarantine folder and the next manifest Remediates the Finding')

    client.request('POST', f'/api/findings/{opened["id"]}/restores', {
        'password': password, 'command_id': done['id'], 'entries_sha256': done['restore']['entries_sha256']}, expect=(202,))
    found = wait_finding(lambda f: f['status'] == 'confirmed' and any(
        c['name'] == 'restore' and c['status'] == 'done' for c in f['quarantine']['commands']),
        'the Restore never regressed the Finding')
    (restored,) = [c for c in found['quarantine']['commands'] if c['name'] == 'restore']
    assert restored['files'][0]['status'] == 'restored' and found['quarantine']['quarantined'] == [], found['quarantine']
    assert found['cause']['by'] == 'regression' and found['regressed_at'], found
    deadline = time.monotonic() + 60
    while not (alerts := server_alerts()):
        assert time.monotonic() < deadline, 'the regression Alert was never delivered'
        time.sleep(1)
    (alert,) = alerts
    assert alert['content'].startswith('Asset Monitor: Malicious change · regressed'), alert
    assert f'Source: web-{suffix}' in alert['content'] and 'cache.php' not in alert['content'], alert
    print('PASS Restore after a password Approval puts the file back, and the next manifest regresses the Finding to Confirmed with one Alert naming the agent and no path')

    # Revoke: the listener refuses the agent from its next request on, so it is never seen again.
    revoked = client.request('POST', f'/api/agents/{agent_id}/revocations', {})
    assert revoked['status'] == 'revoked', revoked
    time.sleep(6)  # a request stored just before the Revoke is refused by application code
    seen = agent_row()['last_seen_at']
    time.sleep(8)
    row = agent_row()
    assert (row['status'], row['last_seen_at']) == ('revoked', seen), row
    assert client.request('POST', quarantines, {'password': password, 'list_sha256': list_sha256}, expect=(409,))['code'] in (
        'agent_not_enrolled', 'quarantine_not_allowed')
    print('PASS a revoked agent is refused at its next request and takes no command')

    for application in [github, wordpress, own, node, advisory, served, pushed, server]:
        client.request('PATCH', f'/api/applications/{application["id"]}', {'archived': True, 'monitor_enabled': False})
    client.request('POST', '/api/auth/logout', {})
    client.request('GET', f'/api/findings/{finding["id"]}/download', expect=(401,), raw=True)
    print('PASS logout revokes artifact access; test Applications archived')
    print('JOURNEY PASSED')


if __name__ == '__main__':
    main()
