"""Checks of the demo (A16) against a running demo project, through the public HTTP API and the
stand-in's routes only. scripts/test-demo.sh runs `smoke <stage>` on the isolated
asset-monitor-demo-test project with no model keys: `seed` after the seed has run twice, then each
demo step's stage after `./scripts/demo.sh step <stage>`, in run-sheet order. They check what needs
no agent: intake, Pre-filter, the Advisory check, Exposure of advisory matches, Served-content
checks, Baselines and merge detection. Only the `approve` stage approves, as a test: the demo
scripts never do.

`dry-run` (A16, brief 5(b)) runs the whole scenario on a fresh project seeded with placeholder model
keys, whose test-only overlay (compose.demo-test.yaml) replaces only the agent decisions with the
canned Verdicts of canned_broker.py: every demo step in run-sheet order, each through the demo's
own step command, with real Labs, yara Detection rules and served-content probes. It approves as the
Operator would in the dashboard, with the password, and checks each step's Findings, pending
Approvals, Proofs, Remediation PRs and Remediated states, ending with the last Remediation PR open.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
import os
import time
from urllib.parse import urlsplit

from demo import (FIXTURE_URL, GITHUB_READ, GITHUB_WRITE, NODE, OWN, PASSWORD, PHP, PHP_VERIFY, REACT,
                  demo_applications, login, served_check, step, upstream)
from journey import Client, items

R2S, NODE2SHELL = 'CVE-2025-55182', 'CVE-2026-111497'
AGENT_KINDS = ('commit_triage', 'commit_analysis', 'served_triage', 'served_analysis', 'patch_drafting', 'finding_artifacts')
CANNED_BROKER = 'http://canned-broker:8081'


def head(fixture: Client, repository: str) -> str:
    return fixture.request('GET', f'/repos/asset-monitor-demo/{repository}/git/ref/heads/main')['object']['sha']


def commits(client: Client, application: dict) -> list[dict]:
    return items(client.request('GET', f'/api/applications/{application["id"]}/commits?limit=200'))


def findings(client: Client, application: dict) -> list[dict]:
    return items(client.request('GET', f'/api/findings?application_id={application["id"]}&limit=200'))


def jobs(client: Client, application: dict, *kinds: str) -> list[dict]:
    """The Application's jobs of `kinds`, or all of them."""
    return [job for job in items(client.request('GET', f'/api/jobs?application_id={application["id"]}&limit=200'))
            if not kinds or job['kind'] in kinds]


def no_agent_run(client: Client, application: dict) -> None:
    assert jobs(client, application, *AGENT_KINDS) == [], jobs(client, application, *AGENT_KINDS)


def advisory_finding(client: Client, node: dict, vulnerability: str) -> dict:
    (finding,) = [f for f in findings(client, node) if (f['source'], f['source_ref']) == ('advisory', vulnerability)]
    return finding


def seed(client: Client, fixture: Client) -> None:
    # One of each after the second seed: same Applications, no duplicate account, link or page.
    names = [a['asset_name'] for a in items(client.request('GET', '/api/applications?limit=200'))]
    assert names.count(NODE) == names.count(PHP) == 1, names
    labels = [(a['label'], a['provider']) for a in items(client.request('GET', '/api/accounts'))]
    assert sorted(labels) == sorted([GITHUB_READ[:2], GITHUB_WRITE[:2]]), labels
    applications = demo_applications(client)
    node, php = applications[NODE], applications[PHP]
    assert node['config']['triage_mode'] == php['config']['triage_mode'] == 'disabled'
    print('PASS the seed ran twice: one Demo Node shop, one Demo PHP storefront, two stand-in GitHub accounts, Triage off')

    own, react = (next(r for r in node['repositories'] if r['role'] == role) for role in ('own', 'upstream'))
    assert len(node['repositories']) == 2, node['repositories']
    assert (own['source_url'], own['baseline_revision'], own['last_error']) == (OWN, head(fixture, 'shop'), None), own
    assert (react['source_url'], react['packages'], react['locked_version'], react['locked_version_source']) == (
        REACT, ['npm:react-server-dom-webpack'], '19.0.0', 'manifest'), react
    assert (react['enabled'], react['baseline_revision'], react['release_branch_status']) == (
        True, head(fixture, 'react'), 'unknown'), react
    dockerfile = fixture.request('GET', '/repos/asset-monitor-demo/shop/contents/Dockerfile?ref=main', raw=True)
    assert dockerfile.startswith(b'FROM node:20.11.1-alpine\n'), dockerfile
    # A Baseline imports no history.
    assert commits(client, node) == []
    print('PASS the Own repository locks react-server-dom-webpack 19.0.0 and pins node 20.11.1, and the derived React '
          'Upstream repository has its Baseline and an unknown Release branch')

    assert php['repositories'] == [], php['repositories']
    rows = served_check(client, php)
    states = [(page['url'], row['user_agent'], row['state']) for page, row in rows]
    # The homepage is the Asset URL, as stored.
    assert sorted({(page['url'], page['homepage']) for page, _ in rows}) == [(php['asset_url'], True), (PHP_VERIFY, False)], states
    assert len(rows) == 4 and {state for *_, state in states} == {'matches'}, states
    hosts = {urlsplit(r['url']).hostname for _, row in rows for r in row['latest']['resources']}
    assert hosts == {'toko-batik.test'}, hosts
    print('PASS the demo PHP Application has no Own repository, and its Asset stand-in matches its accepted Baselines as browser and Googlebot')

    for application in (node, php):
        assert findings(client, application) == []
        no_agent_run(client, application)
    assert items(client.request('GET', '/api/notifications')) == []
    state = fixture.request('GET', '/admin/state')
    assert (state['notifications'], state['writes'], state['demo_pulls'], state['published']) == ([], [], {}, []), state
    print('PASS the seed opened no Finding, sent no Alert, wrote nothing to the stand-ins and started no agent run')


def step_1(client: Client, fixture: Client) -> None:
    node = demo_applications(client)[NODE]
    sha = head(fixture, 'shop')
    (commit,) = commits(client, node)
    assert (commit['revision'], commit['triage_status'], commit['findings']) == (sha, 'disabled', []), commit
    assert next(r for r in node['repositories'] if r['role'] == 'own')['cursor'] == sha
    assert findings(client, node) == []
    no_agent_run(client, node)
    print('PASS step 1: Check now imported the pushed commit at the stand-in head, with Triage off and no Finding')


def step_3(client: Client, fixture: Client) -> None:
    node = demo_applications(client)[NODE]
    sha = head(fixture, 'shop')
    listed = commits(client, node)
    assert len(listed) == 2, listed
    commit = next(c for c in listed if c['revision'] == sha)
    assert commit['triage_status'] == 'disabled', commit
    rules = {flag['rule'] for flag in commit['prefilter']}
    assert {'dependency_manifest', 'package_scripts', 'minified_or_obfuscated'} <= rules, commit['prefilter']
    # The package.json change queued the Advisory check of its head (advisory:<id>:<head>); no
    # stand-in advisory is published yet, so it matches nothing.
    (check,) = jobs(client, node, 'advisory_check')
    assert (check['status'], check['result']['source_ref'], check['result']['matches'], check['result']['opened']) == (
        'succeeded', sha, 0, 0), check
    assert findings(client, node) == []
    no_agent_run(client, node)
    print('PASS step 3: the install hook commit is Pre-filtered (dependency_manifest, package_scripts, '
          'minified_or_obfuscated), and its pin-file change queued an Advisory check that matched nothing')


def step_4(client: Client, fixture: Client) -> None:
    node = demo_applications(client)[NODE]
    (finding,) = findings(client, node)
    assert (finding['source'], finding['source_ref'], finding['status'], finding['cause']['by']) == (
        'advisory', R2S, 'confirmed', 'advisory'), finding
    (match,) = finding['advisories']
    assert (match['vulnerability'], match['state']) == (R2S, 'exposed'), match
    (pin,) = match['pins']
    assert (pin['name'], pin['version'], pin['sources']) == ('react-server-dom-webpack', '19.0.0', ['package-lock.json']), pin
    (bump,) = finding['remediation_prs']
    assert (bump['action'], bump['status'], bump['subject'], sorted(bump['paths'])) == (
        'bump', 'ready', R2S, ['package-lock.json', 'package.json']), bump
    for line in ('-    "react-server-dom-webpack": "file:vendor/react-server-dom-webpack-19.0.0.tgz"\n',
                 '+    "react-server-dom-webpack": "19.0.1"\n', '+      "version": "19.0.1",\n'):
        assert line in bump['diff'], bump['diff']
    print('PASS step 4: the React2Shell advisory match opens one Finding, Confirmed and exposed at Locked version 19.0.0 '
          'from package-lock.json, with its bump Remediation PR to 19.0.1 ready')

    react = upstream(node)
    # The stand-in's history, newest first: Release 19.0.1 (the Baseline), the fix, Release 19.0.0.
    release, fix, _ = fixture.request('GET', '/repos/asset-monitor-demo/react/commits')
    assert 'GHSA-fv66-9v8q-g76r' in fix['commit']['message'], fix
    imported = {c['revision']: c for c in commits(client, node) if c['repository_id'] == react['repository_id']}
    assert set(imported) == {release['sha'], fix['sha']}, imported
    assert all(c['backfill'] and c['triage_status'] == 'disabled' for c in imported.values()), imported
    no_agent_run(client, node)
    print('PASS step 4: the Backfill on the React Upstream repository imported the stand-in fix commit below the Baseline')


def step_5(client: Client, fixture: Client) -> None:
    node = demo_applications(client)[NODE]
    finding = advisory_finding(client, node, NODE2SHELL)
    assert (finding['status'], finding['cause']['by']) == ('confirmed', 'advisory'), finding
    (match,) = finding['advisories']
    (pin,) = match['pins']
    assert (match['state'], pin['name'], pin['version'], pin['sources']) == ('exposed', 'node', '20.11.1', ['Dockerfile']), match
    (bump,) = finding['remediation_prs']
    assert (bump['action'], bump['status'], bump['subject']) == ('bump', 'ready', NODE2SHELL), bump
    assert '-FROM node:20.11.1-alpine\n' in bump['diff'] and '+FROM node:20.19.5-alpine\n' in bump['diff'], bump['diff']
    # AC-A09: the next Advisory check opens no duplicate.
    again = client.wait(client.request('POST', f'/api/applications/{node["id"]}/advisory-checks', {}, expect=(202,)))
    assert (again['result']['matches'], again['result']['opened']) == (2, 0), again['result']
    assert sorted(f['source_ref'] for f in findings(client, node)) == [R2S, NODE2SHELL]
    no_agent_run(client, node)
    print('PASS step 5: the Advisory check opens exactly one node2shell Finding for node 20.11.1 in the Dockerfile, with its '
          'runtime bump ready, and a second check opens no duplicate')


def approve(client: Client, fixture: Client) -> None:
    applications = demo_applications(client)
    # Before this test's own Approval, nothing was approved: the demo scripts never approve.
    for application in applications.values():
        for finding in findings(client, application):
            assert not [e for e in finding['events'] if e.get('action') == 'approved'], finding['events']
    print('PASS no Finding has an approved event: the demo steps approved nothing')
    node = applications[NODE]
    finding = advisory_finding(client, node, NODE2SHELL)
    (bump,) = finding['remediation_prs']
    client.wait(client.request('POST', f'/api/findings/{finding["id"]}/remediation-prs/{bump["id"]}/approvals',
                               {'password': PASSWORD.read_text().strip(), 'diff_sha256': bump['diff_sha256']}, expect=(202,)))
    (bump,) = advisory_finding(client, node, NODE2SHELL)['remediation_prs']
    state = fixture.request('GET', '/admin/state')
    (pull,) = state['demo_pulls']['shop']
    assert (bump['status'], bump['pull_number'], pull['state'], pull['draft']) == ('open', 1, 'open', True), (bump, pull)
    assert list(state['demo_pulls']) == ['shop'], state['demo_pulls']
    # Every stand-in write went to the Own repository, never to the React stand-in.
    assert state['writes'] and all(w['path'].startswith('/repos/asset-monitor-demo/shop/') for w in state['writes']), state['writes']
    print('PASS this test approves only the node2shell bump: one draft pull request opens on the stand-in Own repository')


def merge_bump(client: Client, fixture: Client) -> None:
    node = demo_applications(client)[NODE]
    (pull,) = fixture.request('GET', '/admin/state')['demo_pulls']['shop']
    assert pull['merged'] and pull['merge_commit_sha'] == head(fixture, 'shop'), pull
    assert pull['merge_commit_sha'] in {c['revision'] for c in commits(client, node)}
    finding = advisory_finding(client, node, NODE2SHELL)
    (bump,) = finding['remediation_prs']
    assert (bump['status'], bump['merge_commit_sha']) == ('merged', pull['merge_commit_sha']), bump
    assert (finding['status'], finding['cause']['by'], finding['cause']['merge_commit']) == (
        'remediated', 'remediation_pr', pull['merge_commit_sha']), finding
    # The merged Dockerfile change queued the Advisory check of the new head: node 20.19.5 is fixed.
    (match,) = finding['advisories']
    assert match['state'] == 'not_exposed', match
    assert advisory_finding(client, node, R2S)['status'] == 'confirmed'
    no_agent_run(client, node)
    print('PASS merge detection: Check now imports the squash merge commit, the bump Remediation PR is merged, its Finding '
          'Remediated by it, and the node2shell match is no longer exposed')


def served_rows(client: Client, php: dict) -> dict:
    """{(page url, user agent): row} as the last Served-content check left them."""
    pages = items(client.request('GET', f'/api/applications/{php["id"]}/watched-pages'))
    return {(page['url'], row['user_agent']): row for page in pages for row in page['user_agents']}


def php_inject(client: Client, fixture: Client) -> None:
    php = demo_applications(client)[PHP]
    rows = served_rows(client, php)
    home = php['asset_url']
    googlebot, browser = rows[home, 'googlebot'], rows[home, 'browser']
    assert googlebot['state'] == 'changed' and 'slot-gacor.test' in googlebot['diff']['link_hosts']['added'], googlebot
    assert (browser['state'], browser['diff']) == ('matches', {}), browser
    for agent in ('browser', 'googlebot'):
        row = rows[PHP_VERIFY, agent]
        assert row['state'] == 'changed' and 'cdn.clickfix-fixture.test' in row['diff']['script_hosts']['added'], row
    seen = fixture.request('GET', '/admin/state')['served_requests']
    assert '/served/executed' not in {r['path'] for r in seen}, seen
    # Triage is off, so the change starts no served Triage.
    no_agent_run(client, php)
    assert findings(client, php) == []
    print('PASS php-inject: gambling links served only to Googlebot change only its homepage fingerprint, the ClickFix '
          'loader host changes both on /served/verify, and nothing fetched ran')


def php_clean(client: Client, fixture: Client) -> None:
    php = demo_applications(client)[PHP]
    rows = served_rows(client, php)
    assert len(rows) == 4 and {row['state'] for row in rows.values()} == {'matches'}, rows
    print('PASS php-clean: every Watched page matches its Baseline again')
    print('DEMO SMOKE CHECKS PASSED')


STAGES = {'seed': seed, '1': step_1, '3': step_3, '4': step_4, '5': step_5, 'approve': approve, 'merge-bump': merge_bump,
          'php-inject': php_inject, 'php-clean': php_clean}


# The dry run (A16, brief 5(b)): the agents are canned, everything else is the demo's own.

def quiet(client: Client, application: dict, timeout: int = 1800) -> None:
    """Waits until none of the Application's jobs is queued or running, Triage, Analysis, Labs and
    Detection rules included, and fails on any failed one."""
    deadline = time.monotonic() + timeout
    while True:
        listed = jobs(client, application)
        failed = [(job['kind'], job['error']) for job in listed if job['status'] == 'failed']
        assert not failed, failed
        active = [job['kind'] for job in listed if job['status'] not in ('succeeded', 'cancelled')]
        if not active:
            return
        assert time.monotonic() < deadline, f'Jobs still active: {active}'
        time.sleep(1)


def run_step(client: Client, name: str, application: dict) -> None:
    step(name)
    quiet(client, application)


def finding(client: Client, found: dict) -> dict:
    return client.request('GET', f'/api/findings/{found["id"]}')


def remediation(found: dict, action: str) -> dict:
    (pr,) = [pr for pr in found['remediation_prs'] if pr['action'] == action]
    return pr


def start_lab(client: Client, found: dict) -> dict:
    """The Operator's Start Lab with the password, on a complete bundle no Lab has run yet: the run."""
    assert found['artifact_state']['status'] == 'complete' and found['lab_runs'] == [], found['artifact_state']
    assert {'step': 'proof', 'status': 'waiting_for_approval'} in found['playbook'], found['playbook']
    client.wait(client.request('POST', f'/api/findings/{found["id"]}/lab-runs', {'password': PASSWORD.read_text().strip()},
                               expect=(202,)), timeout=1800)
    (run,) = finding(client, found)['lab_runs']
    assert run['status'] == 'verified', run
    return run


def approve_pr(client: Client, fixture: Client, found: dict, action: str) -> dict:
    """The Operator's Approve of the Finding's ready `action` Remediation PR, with the password and
    the diff they reviewed: its draft pull request opens on the stand-in Own repository."""
    pr = remediation(found, action)
    assert pr['status'] == 'ready' and {'step': 'remediation_pr', 'status': 'ready'} in found['playbook'], (pr, found['playbook'])
    client.wait(client.request('POST', f'/api/findings/{found["id"]}/remediation-prs/{pr["id"]}/approvals',
                               {'password': PASSWORD.read_text().strip(), 'diff_sha256': pr['diff_sha256']}, expect=(202,)))
    pr = remediation(finding(client, found), action)
    pull = fixture.request('GET', '/admin/state')['demo_pulls']['shop'][pr['pull_number'] - 1]
    assert (pr['status'], pull['state'], pull['draft'], pull['head']['ref']) == ('open', 'open', True, pr['branch']), (pr, pull)
    return pr


def own_commit_finding(client: Client, node: dict, revision: str) -> dict:
    (commit,) = [c for c in commits(client, node) if c['revision'] == revision]
    (found,) = [f for f in findings(client, node) if f['source'] == 'commit' and f['source_commit_id'] == commit['id']]
    return found


def dry_seed(client: Client) -> None:
    key = os.environ['ANTHROPIC_API_KEY']
    accounts = client.request('GET', '/api/accounts')
    assert key not in json.dumps(accounts) and key == os.environ['DEEPSEEK_API_KEY']
    listed = {(a['label'], a['provider']): a for a in items(accounts)}
    for label, provider in (('DeepSeek (demo)', 'deepseek'), ('Anthropic (demo)', 'claude')):
        account = listed[label, provider]
        assert (account['status'], [m['name'] for m in account['models']]) == ('ready', ['Canned dry run, no agent']), account
    profiles = client.request('GET', '/api/settings')['default_profiles']
    agents = {operation: (profiles[operation]['agent'], profiles[operation]['model_id']) for operation in
              ('commit_triage', 'commit_analysis', 'patch_drafting', 'finding_artifacts')}
    assert agents == {'commit_triage': ('pi', 'canned-dry-run-no-agent'), **dict.fromkeys(
        ('commit_analysis', 'patch_drafting', 'finding_artifacts'), ('claude', 'canned-dry-run-no-agent'))}, agents
    assert {a['config']['triage_mode'] for a in demo_applications(client).values()} == {'pi'}
    print('PASS dry run seed: both Provider accounts are ready on the canned catalogue, the default profiles are set, '
          'Triage is on Pi, and no key value is shown')


def dry_step_1(client: Client, fixture: Client, node: dict) -> None:
    run_step(client, '1', node)
    revision = head(fixture, 'shop')
    found = own_commit_finding(client, node, revision)
    assert (found['status'], found['cause']['by'], found['cause']['verdict']) == ('open', 'verdict', 'Vulnerability introduced'), found
    assert remediation(found, 'patch')['status'] == 'ready'
    print('PASS dry run step 1: Vulnerability introduced opens a Finding with a complete bundle; its Lab Proof and its '
          'patch Remediation PR wait for Approval, and no Lab has run')
    run = start_lab(client, found)
    found = finding(client, found)
    assert (run['source_ref'], found['status'], found['cause']['by']) == (revision, 'confirmed', 'proof'), (run, found['cause'])
    pr = approve_pr(client, fixture, found, 'patch')
    assert pr['branch'] == f'asset-monitor/{revision[:7]}-patch', pr
    print('PASS dry run step 1: after Approval the Lab reproduces the traversal (Confirmed), and the approved patch opens '
          'a draft pull request on the stand-in')


def dry_step_2(client: Client, fixture: Client, node: dict) -> None:
    patched = next(f for f in findings(client, node) if f['source'] == 'commit')
    run_step(client, '2', node)
    found = finding(client, patched)
    pr = remediation(found, 'patch')
    assert (pr['status'], found['status'], found['cause']['by'], found['cause']['merge_commit']) == (
        'merged', 'remediated', 'remediation_pr', head(fixture, 'shop')), (pr, found['cause'])
    print('PASS dry run step 2: merging the patch in the stand-in Remediates its Finding')


def dry_step_3(client: Client, fixture: Client, node: dict) -> None:
    run_step(client, '3', node)
    revision = head(fixture, 'shop')
    found = own_commit_finding(client, node, revision)
    assert (found['status'], found['cause']['by'], found['malicious_change']) == ('confirmed', 'detection_rule', True), found
    assert (found['static_proof']['status'], found['artifact_state']['status']) == ('validated', 'complete'), found['static_proof']
    assert [f['path'] for f in found['static_proof']['indicators']['files']] == ['package.json', 'scripts/telemetry.js']
    report = found['cleanup_report']
    assert ([c['revision'] for c in report['commits']], report['secrets']) == ([revision], ['NPM_TOKEN', 'GITHUB_TOKEN']), report
    assert remediation(found, 'revert')['status'] == 'ready' and found['lab_runs'] == []
    refused = client.request('POST', f'/api/findings/{found["id"]}/lab-runs', {'password': PASSWORD.read_text().strip()},
                             expect=(409,))
    assert refused['code'] == 'lab_not_allowed', refused
    print('PASS dry run step 3: Malicious change, Confirmed by its validated Detection rule, with its cleanup report and '
          'a ready revert; a Lab is refused, so nothing runs the payload')
    approve_pr(client, fixture, found, 'revert')
    run_step(client, 'merge-revert', node)
    found = finding(client, found)
    assert (remediation(found, 'revert')['status'], found['status'], found['cause']['by']) == (
        'merged', 'remediated', 'remediation_pr'), found['cause']
    print('PASS dry run step 3: the Cure: approving the revert opens its pull request, and merging it Remediates the Finding')


def dry_step_4(client: Client, fixture: Client, node: dict) -> None:
    run_step(client, '4', node)
    node = demo_applications(client)[NODE]
    found = advisory_finding(client, node, R2S)
    react = upstream(node)
    (fix,) = [c for c in commits(client, node) if c['repository_id'] == react['repository_id'] and 'GHSA-fv66-9v8q-g76r' in c['message']]
    assert (found['status'], found['fix_commit_id']) == ('confirmed', fix['id']), found
    (exposure,) = [e for e in client.request('GET', f'/api/commits/{fix["id"]}')['exposures'] if e['application_id'] == node['id']]
    assert (exposure['verdict'], exposure['state'], exposure['reason'], exposure['target']['tag']) == (
        'Vulnerability fix', 'exposed', 'v19.0.0 does not contain the fix', 'v19.0.1'), exposure
    assert [f['source_ref'] for f in findings(client, node) if f['status'] in ('open', 'confirmed')] == [R2S]
    print('PASS dry run step 4: the Backfill reaches the fix commit, Vulnerability fix and exposed at v19.0.0, and it joins '
          'the React2Shell advisory Finding')
    run = start_lab(client, found)
    own = next(r for r in node['repositories'] if r['role'] == 'own')
    assert (run['packages'], run['locked_version'], run['own_ref']) == (['react-server-dom-webpack'], '19.0.0', own['cursor']), run
    assert len(finding(client, found)['remediation_prs']) == 1
    approve_pr(client, fixture, finding(client, found), 'bump')
    writes = fixture.request('GET', '/admin/state')['writes']
    assert not [w for w in writes if w['path'].startswith('/repos/asset-monitor-demo/react')], writes
    print('PASS dry run step 4: after Approval the n-day Proof reproduces on the Own head at Locked version 19.0.0, and '
          'its one bump opens on the stand-in Own repository, never on the React stand-in')


def dry_step_5(client: Client, fixture: Client, node: dict) -> None:
    run_step(client, '5', node)
    found = advisory_finding(client, node, NODE2SHELL)
    assert (found['status'], found['cause']['by'], found['lab_runs']) == ('confirmed', 'advisory', []), found
    pr = approve_pr(client, fixture, found, 'bump')
    assert '+FROM node:20.19.5-alpine\n' in pr['diff'], pr['diff']
    print('PASS dry run step 5: the Advisory check opens the node2shell Finding, and approving its runtime bump opens the '
          'last Remediation PR')


def dry_php(client: Client, fixture: Client, php: dict) -> None:
    run_step(client, 'php-inject', php)
    served = findings(client, php)
    assert len(served) == 3 and {f['source'] for f in served} == {'served_content'}, served
    for found in served:
        assert (found['status'], found['cause']['by'], found['static_proof']['status']) == (
            'confirmed', 'detection_rule', 'validated'), found
        assert (found['remediation_prs'], found['lab_runs']) == ([], []), found
        assert 'remediation_pr' not in {s['step'] for s in found['playbook']}, found['playbook']
    print('PASS dry run PHP: the injection opens 3 served-content Malicious change Findings, each Confirmed by a validated '
          'Detection rule, with no Remediation PR and no Lab')
    run_step(client, 'php-clean', php)
    assert {(f['status'], f['cause']['by']) for f in findings(client, php)} == {('remediated', 'baseline_match')}
    print('PASS dry run PHP: serving the Baselines again Remediates all 3')


def dry_run(client: Client, fixture: Client) -> None:
    dry_seed(client)
    applications = demo_applications(client)
    node, php = applications[NODE], applications[PHP]
    for check in (dry_step_1, dry_step_2, dry_step_3, dry_step_4, dry_step_5):
        check(client, fixture, node)
    dry_php(client, fixture, php)
    opened = [f['id'] for application in (node, php) for f in findings(client, application)]
    deadline = time.monotonic() + 60
    while len(alerts := fixture.request('GET', '/admin/state')['notifications']) < len(opened) and time.monotonic() < deadline:
        time.sleep(1)
    # The fixed template's last line links the Finding it opened.
    assert all(alert['content'].startswith('Asset Monitor: ') for alert in alerts), alerts
    linked = Counter(alert['content'].rsplit('/findings/', 1)[-1] for alert in alerts)
    assert linked == Counter(opened), (linked, opened)
    print(f'PASS dry run Alerts: one fixed-template Alert for each of the {len(opened)} opened Findings')
    broker = Client(CANNED_BROKER)
    state = broker.request('GET', '/state', headers={'X-Broker-Token': os.environ['NUMEN_BROKER_TOKEN']})
    assert {run['kind'] for run in state['canned']} == {'agent', 'capabilities'}, state
    assert {run['operation'] for run in state['canned'] if run['kind'] == 'agent'} == {
        'commit_triage', 'commit_analysis', 'patch_drafting', 'finding_artifacts'}, state
    assert set(state['forwarded']) == {'lab', 'probe', 'detection_rule'}, state
    print('PASS dry run: only agent and capabilities runs were canned; every Lab, probe and Detection rule run went to '
          'the runner-broker')
    print('DEMO DRY RUN PASSED')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['smoke', 'dry-run'])
    parser.add_argument('stage', nargs='?', choices=list(STAGES))
    args = parser.parse_args()
    if (args.mode == 'smoke') != (args.stage is not None):
        parser.error('smoke takes one stage, and dry-run none')
    (STAGES[args.stage] if args.stage else dry_run)(login(), Client(FIXTURE_URL))


if __name__ == '__main__':
    main()
