"""The demo driver (A16): seeds the demo Applications, runs the demo steps and reports their state.

Run it through ./scripts/demo.sh (`seed`, `step <name>`, `status`, or `run demo.py <command>`),
which starts it in the application image on the demo project's network. It uses only the public
HTTP API and the stand-in's /admin routes, never the database, and it never approves anything:
Approvals stay with the Operator in the dashboard, so nothing here requests /lab-runs or
/approvals. Model keys come from the Operator's environment, and no environment value is ever
printed.

`seed` is idempotent: it looks up every account, Application, repository link and Watched page
before creating one. Each `step` advances the stand-ins, runs Check now (or the Advisory check or
the Served-content check) and waits for the jobs that run no agent; Triage, Analysis and Labs go on
in the dashboard.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import time
from urllib.parse import quote

from journey import Client, check_now, items, wait_kind

APP_URL = 'http://app:8080'
FIXTURE_URL = 'http://fixtures:8090'
PASSWORD = Path('/run/secrets/demo-password')
NODE = 'Demo Node shop'
PHP = 'Demo PHP storefront'
OWN = 'https://github.com/asset-monitor-demo/shop'
REACT = 'https://github.com/asset-monitor-demo/react'
PHP_URL = 'http://toko-batik.test:8090/served/'
PHP_VERIFY = PHP_URL + 'verify'
# The GitHub stand-in accepts any token; these are not secrets.
GITHUB_READ = ('Stand-in GitHub read token', 'github', 'demo-stand-in-read-token')
GITHUB_WRITE = ('Stand-in GitHub write token', 'github_write', 'github_pat_demo-stand-in-write-token')
# Decision 11: Triage on Pi with DeepSeek, Analysis on Claude Code at high effort.
TRIAGE = ('DEEPSEEK_API_KEY', 'DeepSeek (demo)', 'deepseek', 'pi', 'DEMO_TRIAGE_MODEL', None, ('commit_triage',))
ANALYSIS = ('ANTHROPIC_API_KEY', 'Anthropic (demo)', 'claude', 'claude', 'DEMO_ANALYSIS_MODEL', 'high',
            ('commit_analysis', 'patch_drafting', 'finding_artifacts'))
NEEDS_KEYS = ('NEEDS MODEL KEYS: steps 1 to 4 and the PHP injection reach their Verdicts, Proofs and Remediation PRs '
              'only with DEEPSEEK_API_KEY (Triage) and ANTHROPIC_API_KEY (Analysis, Proofs and patch drafting) set '
              'before `make demo-up` or `./scripts/demo.sh seed`. Without them those steps still import, Pre-filter, '
              'run the Advisory check and the Served-content check, and step 5 (the Advisory check) needs no key.')


def login(base: str = APP_URL) -> Client:
    client = Client(base)
    # Each step signs in again, and the login throttle allows 10 attempts per address in 60 s; a
    # refused attempt is not counted, so waiting it out is safe.
    for _ in range(18):
        session = client.request('POST', '/api/auth/login', {'username': 'admin', 'password': PASSWORD.read_text().strip()},
                                 expect=(200, 429))
        if 'csrf_token' in session:
            break
        time.sleep(5)
    else:
        raise SystemExit(session['message'])
    client.csrf = session['csrf_token']
    return client


def account(client: Client, label: str, provider: str) -> dict | None:
    return next((a for a in items(client.request('GET', '/api/accounts')) if (a['label'], a['provider']) == (label, provider)), None)


def ensure_account(client: Client, label: str, provider: str, key: str) -> dict:
    found = account(client, label, provider)
    return found or client.request('POST', '/api/accounts', {'label': label, 'provider': provider, 'auth_type': 'api_key', 'api_key': key}, expect=(201,))


def model_profiles(client: Client) -> dict:
    """The default profiles of each model key present in the environment: its Provider account
    gets the key again (so a rotated key takes effect) and a fresh model catalogue."""
    profiles = {}
    for variable, label, provider, agent, model_variable, effort, operations in (TRIAGE, ANALYSIS):
        key = os.environ.get(variable)
        if not key:
            continue
        if found := account(client, label, provider):
            client.request('PATCH', f'/api/accounts/{found["id"]}', {'api_key': key})
        else:
            found = ensure_account(client, label, provider, key)
        try:
            client.wait(client.request('POST', f'/api/accounts/{found["id"]}/capabilities', {}, expect=(202,)), timeout=300)
        except AssertionError:
            print(f'NOT READY {label}: its capability check failed; check the key and the Accounts page.')
            continue
        found = account(client, label, provider)
        catalogue = found['agent_models'].get(agent) or found['models']
        wanted = os.environ.get(model_variable) or (catalogue[0]['id'] if catalogue else None)
        model = next((m for m in catalogue if m['id'] == wanted), None)
        if model is None:
            print(f'NOT READY {label}: {model_variable} names no model in its catalogue.')
            continue
        profile = {'agent': agent, 'connection_id': found['id'], 'model_id': model['id'],
                   'reasoning_effort': effort if effort in model.get('reasoning_efforts', []) else None}
        profiles.update({operation: profile for operation in operations})
        print(f'READY {label}: {", ".join(operations)} on {agent} with model {model["id"]}')
    return profiles


def ensure_application(client: Client, body: dict) -> dict:
    """The Application named body['asset_name'], created or brought back to `body`."""
    name = body['asset_name']
    found = next((a for a in items(client.request('GET', '/api/applications?q=' + quote(name))) if a['asset_name'] == name), None)
    if found is None:
        return client.request('POST', '/api/applications', body, expect=(201,))
    return client.request('PATCH', f'/api/applications/{found["id"]}', {**body, 'archived': False})


def demo_applications(client: Client) -> dict[str, dict]:
    return {a['asset_name']: a for a in items(client.request('GET', '/api/applications?limit=200')) if a['asset_name'] in (NODE, PHP)}


def served_check(client: Client, application: dict) -> list[tuple[dict, dict]]:
    """Check now for the Asset: [(Watched page, a user agent's row)] after one Served-content check."""
    client.wait(client.request('POST', f'/api/applications/{application["id"]}/served-content-checks', {}, expect=(202,)), timeout=300)
    pages = items(client.request('GET', f'/api/applications/{application["id"]}/watched-pages'))
    return [(page, row) for page in pages for row in page['user_agents']]


def seed() -> None:
    client = login()
    for label, provider, key in (GITHUB_READ, GITHUB_WRITE):
        ensure_account(client, label, provider, key)
    profiles = model_profiles(client)
    settings = client.request('GET', '/api/settings')
    webhook = os.environ.get('DISCORD_WEBHOOK_URL') or f'{FIXTURE_URL}/webhooks/demo'
    settings = client.request('PATCH', '/api/settings', {
        'default_profiles': {**settings['default_profiles'], **profiles},
        'dashboard_url': f'http://localhost:{os.environ.get("NUMEN_PORT", "8790")}',
        'webhook_url': webhook, 'webhook_enabled': True,
    })
    triage = 'pi' if 'commit_triage' in settings['default_profiles'] else 'disabled'
    common = {'monitor_interval_seconds': 300, 'monitor_enabled': False, 'config': {'triage_mode': triage}}

    node = ensure_application(client, {**common, 'asset_name': NODE, 'asset_url': 'https://shop.asset-monitor-demo.test/',
                                       'product_kind': 'Node application', 'product_name': 'Toko Batik shop'})
    if not [r for r in node['repositories'] if r['role'] == 'own' and r['removed_at'] is None]:
        client.request('POST', f'/api/applications/{node["id"]}/repositories',
                       {'role': 'own', 'source_kind': 'github', 'source_url': OWN, 'source_ref': 'main'}, expect=(201,))
    check_now(client, node)  # the Own repository's Baseline, which derives its Upstream repositories
    wait_kind(client, node, 'derive_upstreams')
    check_now(client, node)  # the derived React Upstream repository's Baseline
    node = client.request('GET', f'/api/applications/{node["id"]}')
    for link in node['repositories']:
        locked = f', locked at {link["locked_version"]}' if link['locked_version'] else ''
        print(f'READY {NODE}: {link["role"]} repository {link["source_url"]}{locked}, Baseline {(link["baseline_revision"] or "none")[:7]}')

    php = ensure_application(client, {**common, 'asset_name': PHP, 'asset_url': PHP_URL,
                                      'product_kind': 'PHP storefront', 'product_name': 'Toko Batik'})
    watched = f'/api/applications/{php["id"]}/watched-pages'
    if PHP_VERIFY not in {page['url'] for page in items(client.request('GET', watched))}:
        client.request('POST', watched, {'url': PHP_VERIFY}, expect=(201,))
    rows = served_check(client, php)
    if failed := [page['url'] for page, row in rows if row['state'] == 'failed']:
        raise SystemExit(f'The Served-content stand-in could not be fetched: {failed}')
    for page, row in rows:
        # The first Content fingerprint becomes the Baseline; this is not an Approval.
        if row['state'] == 'awaiting_baseline':
            client.request('POST', f'{watched}/{page["id"]}/baselines', {'fetch_id': row['latest']['id']})
    print(f'READY {PHP}: {len({page["id"] for page, _ in rows})} Watched pages with Baselines, no Own repository')
    print(f'READY Triage {"on" if triage != "disabled" else "off"}; Alerts go to '
          f'{"DISCORD_WEBHOOK_URL" if os.environ.get("DISCORD_WEBHOOK_URL") else "the stand-in webhook"}')
    if not {'commit_triage', 'commit_analysis'} <= set(settings['default_profiles']):
        print(NEEDS_KEYS)
    print('SEED DONE')


# The jobs a step waits for: none of them runs an agent. remediation_pr runs only after the
# Operator's Approval; a merge waits for it so the pull request is open first.
SETTLED = ('source_check', 'backfill', 'derive_upstreams', 'advisory_check', 'exposure_check', 'remediation_draft',
           'served_check', 'remediation_pr')


def settle(client: Client, application: dict) -> None:
    """Waits until none of the Application's jobs in SETTLED is queued or running, including the
    ones they queue in turn (a pin-file change's Advisory check, an advisory bump's draft)."""
    while active := [job for job in items(client.request('GET', f'/api/jobs?application_id={application["id"]}&limit=200'))
                     if job['kind'] in SETTLED and job['status'] not in ('succeeded', 'failed', 'cancelled')]:
        for job in active:
            client.wait({'job_id': job['id']}, timeout=300)


def checked(client: Client, application: dict) -> None:
    check_now(client, application)
    settle(client, application)


def advisory_check(client: Client, application: dict) -> dict:
    job = client.wait(client.request('POST', f'/api/applications/{application["id"]}/advisory-checks', {}, expect=(202,)))
    settle(client, application)
    return job


def upstream(application: dict) -> dict:
    """The demo Node Application's derived React Upstream repository link."""
    return next(link for link in application['repositories'] if link['role'] == 'upstream' and link['source_url'] == REACT
                and link['removed_at'] is None)


def merge(client: Client, fixture: Client, application: dict, action: str) -> None:
    """Merges each open `action` Remediation PR in the stand-in, as its maintainer would, then runs
    Check now so the poller sees the merge commit."""
    settle(client, application)
    pulls = [pr['pull_number'] for finding in items(client.request('GET', f'/api/findings?application_id={application["id"]}&limit=200'))
             for pr in finding['remediation_prs'] if pr['action'] == action and pr['status'] == 'open']
    if not pulls:
        raise SystemExit(f'No {action} Remediation PR is open: approve the {action} Remediation PR in the dashboard first.')
    for number in pulls:
        fixture.request('POST', '/admin/demo/merge', {'repository': 'shop', 'number': number})
        print(f'Merged stand-in pull request asset-monitor-demo/shop#{number}')
    checked(client, application)


# What the Operator clicks and the audience sees after each step (docs/demo.md has the full run sheet).
NEXT = {
    '1': 'Demo Node shop > Commits: "Let customers download their invoices". With model keys, Triage then Analysis give '
         'Vulnerability introduced and a Finding: Start Lab (password) for the Lab Proof, then Approve its patch '
         'Remediation PR. Then run STEP=2.',
    '2': 'The Finding is Remediated by its merged patch Remediation PR. Then run STEP=3.',
    '3': 'Demo Node shop > Commits: "Report anonymous install metrics", Pre-filtered for package.json scripts and '
         'obfuscation. With model keys, Analysis gives Malicious change: its static Proof, Detection rule and cleanup '
         'report, and its Cure, a revert Remediation PR to Approve. Then run STEP=merge-revert before any Lab of step 4.',
    'merge-revert': 'The Malicious change Finding is Remediated by its merged revert. Then run STEP=4.',
    '4': 'Demo Node shop > Findings: CVE-2025-55182 (React2Shell), Confirmed by the advisory match at Locked version '
         '19.0.0, with its bump Remediation PR ready. The Backfill imported the React fix commit; with model keys its '
         'Analysis (Vulnerability fix, exposed) joins this Finding: Start Lab for the n-day Proof, then Approve the '
         'bump. Then run STEP=5.',
    '5': 'Demo Node shop > Findings: CVE-2026-111497 (node2shell) for node 20.11.1 in the Dockerfile, with its runtime '
         'bump Remediation PR ready to Approve. Run STEP=merge-bump to merge the approved bumps.',
    'merge-bump': 'Each merged bump\'s Finding is Remediated, and its advisory match is no longer exposed.',
    'php-inject': 'Demo PHP storefront > Served content: Googlebot sees new gambling link hosts on the homepage, the '
                  'browser does not, and /served/verify gained the ClickFix loader host. Nothing ran. Then run '
                  'STEP=php-clean.',
    'php-clean': 'Demo PHP storefront > Served content: every row matches its Baseline again.',
}


def step(name: str) -> None:
    client, fixture = login(), Client(FIXTURE_URL)
    applications = demo_applications(client)
    node, php = applications[NODE], applications[PHP]
    if name in ('1', '3'):
        commit = {'1': '1-invoice-download', '3': '3-install-telemetry'}[name]
        sha = fixture.request('POST', '/admin/demo/push', {'repository': 'shop', 'commit': commit})['sha']
        print(f'Pushed {commit} to the stand-in Own repository as {sha[:7]}')
        checked(client, node)
    elif name in ('2', 'merge-revert', 'merge-bump'):
        merge(client, fixture, node, {'2': 'patch', 'merge-revert': 'revert', 'merge-bump': 'bump'}[name])
    elif name == '4':
        fixture.request('POST', '/admin/demo/publish', {'advisory': 'react2shell'})
        print('Published the stand-in React2Shell advisory (CVE-2025-55182)')
        advisory_check(client, node)
        # The Baseline is the stand-in's 'Release 19.0.1'; the fix commit is the one below it.
        react = upstream(node)
        client.wait(client.request('POST', f'/api/applications/{node["id"]}/repositories/{react["repository_id"]}/backfills',
                                   {'count': 2}, expect=(202,)))
        settle(client, node)
    elif name == '5':
        fixture.request('POST', '/admin/demo/publish', {'advisory': 'node2shell'})
        print('Published the stand-in node2shell advisory (CVE-2026-111497)')
        advisory_check(client, node)
    else:
        fixture.request('POST', '/admin/served', {'variants': ['judol', 'clickfix'] if name == 'php-inject' else []})
        served_check(client, php)
    print(f'STEP {name} DONE. {NEXT[name]}')


def status() -> None:
    client = login()
    fixture = Client(FIXTURE_URL)
    for name, application in sorted(demo_applications(client).items()):
        print(name)
        for link in application['repositories']:
            print(f'  {link["role"]} repository {link["source_url"]}: Baseline {(link["baseline_revision"] or "none")[:7]}, '
                  f'head {(link["cursor"] or "none")[:7]}')
        for finding in items(client.request('GET', f'/api/findings?application_id={application["id"]}&limit=200')):
            print(f'  Finding {finding["status"]}: {finding["title"]}')
            for pr in finding['remediation_prs']:
                pending = ', pending Approval (Approve)' if pr['status'] == 'ready' else ''
                print(f'    {pr["action"]} Remediation PR {pr["status"]}{pending}{": " + pr["pull_url"] if pr.get("pull_url") else ""}')
            if {'step': 'proof', 'status': 'waiting_for_approval'} in finding['playbook']:
                print('    Lab Proof pending Approval (Start Lab)')
    for repository, pulls in fixture.request('GET', '/admin/state')['demo_pulls'].items():
        for pull in pulls:
            state = 'merged' if pull.get('merged') else pull['state']
            print(f'  stand-in pull request {repository}#{pull["number"]} ({state}): {pull["title"]}')


STEPS = ('1', '2', '3', 'merge-revert', '4', '5', 'merge-bump', 'php-inject', 'php-clean')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['seed', 'status', 'step'])
    parser.add_argument('step', nargs='?', choices=STEPS)
    args = parser.parse_args()
    if args.command == 'step':
        if args.step is None:
            parser.error(f'step needs one of: {", ".join(STEPS)}')
        return step(args.step)
    if args.step is not None:
        parser.error(f'{args.command} takes no step')
    {'seed': seed, 'status': status}[args.command]()


if __name__ == '__main__':
    main()
