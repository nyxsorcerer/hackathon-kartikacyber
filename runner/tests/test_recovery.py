import json
import threading
import time

import pytest
from fastapi.testclient import TestClient

from numen_runner.broker import create_app
from numen_runner.engine import RuntimeFailure

TOKEN = 'protected-recovery-test-token'
HEADERS = {'X-Broker-Token': TOKEN}


def wait_state(client, run_id, wanted, seconds=4, error_code=None):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        state = client.get('/internal/runs/' + run_id, headers=HEADERS).json()
        if state['status'] == wanted and (error_code is None or state.get('error', {}).get('code') == error_code):
            return state
        time.sleep(.01)
    raise AssertionError(f'Expected {wanted}; last state was {state}')


class CleanupEngine:
    def __init__(self, result='success'):
        self.available = False
        self.result = result
        self.started = threading.Event()
        self.release = threading.Event()

    def cleanup(self, _run_id):
        if not self.available:
            raise RuntimeError('engine unavailable; the workload may still be alive')

    def run(self, _id, _request, cancelled, _event):
        self.started.set()
        if self.result == 'cancel':
            assert self.release.wait(3)
            assert cancelled()
            raise RuntimeFailure('cancelled', 'Workload cancellation requested.')
        if self.result == 'failure':
            raise RuntimeFailure('timeout', 'Workload deadline exceeded.')
        return {'result': {'observed': True}, 'outputs': [], 'execution': {'image_digest': 'sha256:observed'}}


def seed_running(tmp_path):
    value = {'run_id': 'interrupted-run', 'status': 'running', 'attempt_token': 'old-attempt',
             'fingerprint': 'original', 'progress': 20, 'events': [], 'outputs': [],
             'execution': {'image_digest': 'sha256:original'}}
    (tmp_path/'interrupted-run.json').write_text(json.dumps(value))


def test_restart_cleanup_failure_remains_nonterminal_and_blocks_replacement(tmp_path):
    seed_running(tmp_path)
    engine = CleanupEngine()
    # This public lifecycle assertion also fails on the former broker, which published failed.
    app = create_app(TOKEN, tmp_path, engine=engine, execute=False)
    with TestClient(app) as client:
        state = client.get('/internal/runs/interrupted-run', headers=HEADERS).json()
        assert state['status'] == 'cancelling' and state['error']['code'] == 'cleanup_pending'
        assert 'stopped' not in state['error']['message']
        assert state['execution']['image_digest'] == 'sha256:original'
        assert '_completion' not in state
        assert client.get('/health').status_code == 503
        known=client.get('/internal/attempts/old-attempt',headers=HEADERS).json()
        assert known=={'run_id':'interrupted-run','status':'cancelling','reconciled':False}
        assert client.get('/internal/attempts/unknown',headers=HEADERS).status_code==503
        assert client.post('/internal/runs', headers=HEADERS, json={'attempt_token':'replacement','kind':'probe'}).status_code == 503
        engine.available = True
        stopped = wait_state(client, 'interrupted-run', 'failed')
        assert stopped['error']['code'] == 'broker_restart'
        assert client.get('/health').status_code == 200
        assert client.get('/internal/attempts/unknown',headers=HEADERS).json()=={'run_id':None,'status':'absent','reconciled':True}
        assert client.get('/internal/attempts/old-attempt',headers=HEADERS).json()['reconciled'] is True
        assert client.post('/internal/runs', headers=HEADERS, json={'attempt_token':'replacement','kind':'probe'}).status_code == 202


@pytest.mark.parametrize('outcome,terminal', [('success','succeeded'),('failure','failed'),('cancel','cancelled')])
def test_normal_success_failure_and_cancel_wait_for_real_cleanup(tmp_path, outcome, terminal):
    engine = CleanupEngine(outcome)
    app = create_app(TOKEN, tmp_path, engine=engine, reconcile_interval=.02)
    with TestClient(app) as client:
        run_id = client.post('/internal/runs', headers=HEADERS, json={'attempt_token':outcome,'kind':'probe'}).json()['run_id']
        assert engine.started.wait(1)
        if outcome == 'cancel':
            state = client.post('/internal/runs/'+run_id+'/cancel', headers=HEADERS).json()
            assert state['status'] == 'cancelling'
            engine.release.set()
        state = wait_state(client, run_id, 'cancelling', error_code='cleanup_pending')
        assert state['error']['code'] == 'cleanup_pending'
        assert 'stopped' not in state['error']['message']
        assert client.post('/internal/runs', headers=HEADERS, json={'attempt_token':'replacement','kind':'probe'}).status_code == 503
        engine.available = True
        complete = wait_state(client, run_id, terminal)
        if outcome == 'success':
            assert complete['result'] == {'observed':True}
            assert complete['execution']['image_digest'] == 'sha256:observed'
        if outcome == 'failure':
            assert complete['error']['code'] == 'timeout'
        if outcome == 'cancel':
            assert complete['error']['code'] == 'cancelled'


def test_unreconciled_completion_survives_another_broker_restart(tmp_path):
    engine = CleanupEngine()
    with TestClient(create_app(TOKEN, tmp_path, engine=engine, reconcile_interval=.02)) as client:
        run_id = client.post('/internal/runs', headers=HEADERS, json={'attempt_token':'completed','kind':'probe'}).json()['run_id']
        state = wait_state(client, run_id, 'cancelling', error_code='cleanup_pending')
        assert state['error']['code'] == 'cleanup_pending'
    saved = json.loads((tmp_path/(run_id+'.json')).read_text())
    assert saved['status'] == 'cancelling' and saved['_completion']['result'] == {'observed':True}
    engine.available = True
    with TestClient(create_app(TOKEN, tmp_path, engine=engine, execute=False)) as client:
        complete = client.get('/internal/runs/'+run_id, headers=HEADERS).json()
        assert complete['status'] == 'succeeded' and complete['result'] == {'observed':True}
