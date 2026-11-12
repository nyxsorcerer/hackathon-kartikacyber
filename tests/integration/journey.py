"""Observe the real Compose/API/worker/fixture journey without paid providers.

Run against the isolated asset-monitor-test project. Required provider protocol and
container execution cases live in the backend and runner suites; this journey
proves their application-facing integration, persistence, and human decision
boundaries using the HTTP/SVN/NVD/webhook fixture service.
"""

from __future__ import annotations

import argparse
from http.cookiejar import CookieJar
import io
import json
from pathlib import Path
import time
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener
import uuid
import zipfile


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
    session = client.request('POST', '/api/auth/login', {'username': 'admin', 'password': args.password_file.read_text().strip()})
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
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if fixture.request('GET', '/admin/state')['notifications']:
            break
        time.sleep(0.5)
    else:
        raise AssertionError('Candidate notification was not delivered to fixture webhook')
    assert not [job for job in items(client.request('GET', '/api/jobs')) if job.get('application_id') == github['id'] and job['kind'] == 'commit_analysis']
    client.request('POST', f'/api/commits/{candidate["id"]}/analyses', {}, expect=(409, 422))
    print('PASS captured Discord delivery and explicit analysis/profile prerequisite')

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
        'application_id': github['id'], 'kind': '0day', 'title': f'Fixture metadata boundary {suffix}',
        'status': 'open', 'source_commit_id': candidate['id'],
        'affected_versions': ['1.2.0'], 'fixed_versions': ['1.2.1'],
    }, expect=(200, 201))
    assert finding['status'] == 'open'
    assert finding['artifact_state']['status'] == 'draft'
    files = {
        'poc.py': b'import urllib.request\nprint(urllib.request.urlopen("http://lab:8080/").status)\n',
        'report.md': b'# Fixture metadata boundary\n\nControlled integration fixture, not a real finding.\n\nUpstream fixed: 1.2.1. Remote deployment status remains independent.\n',
        'vulnerable-app/Dockerfile': b'FROM python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c\nWORKDIR /app\nCMD ["python", "-m", "http.server", "8080"]\n',
        'vulnerable-app/compose.yaml': b'services:\n  app:\n    build: .\n    ports: ["127.0.0.1:18080:8080"]\n',
        'vulnerable-app/README.md': b'# Fixture app\nRun docker compose up --build. Version: 1.2.0.\n',
        'vulnerable-app/application.lock.json': json.dumps({'version': '1.2.0', 'fixture': True, 'local_inputs': {'Dockerfile': 'Controlled integration fixture'}, 'images': ['python:3.12.12-slim-bookworm@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c']}).encode(),
    }
    finding = client.upload(f'/api/findings/{finding["id"]}/artifacts', files)
    assert finding['artifact_state']['status'] == 'complete'
    archive_data = client.request('GET', f'/api/findings/{finding["id"]}/download', raw=True)
    with zipfile.ZipFile(io.BytesIO(archive_data)) as bundle:
        names = bundle.namelist()
        for required in ['poc.py', 'report.md', 'vulnerable-app/Dockerfile', 'manifest.json']:
            assert any(name.endswith(required) for name in names), required
    assert client.request('GET', f'/api/findings/{finding["id"]}')['status'] == 'open'
    print('PASS draft/completed finding bundle integrity and independent upstream status')

    for application in [github, wordpress]:
        client.request('PATCH', f'/api/applications/{application["id"]}', {'archived': True, 'monitor_enabled': False})
    client.request('POST', '/api/auth/logout', {})
    client.request('GET', f'/api/findings/{finding["id"]}/download', expect=(401,), raw=True)
    print('PASS logout revokes artifact access; test Applications archived')
    print('JOURNEY PASSED')


if __name__ == '__main__':
    main()
