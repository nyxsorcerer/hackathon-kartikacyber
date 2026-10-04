"""Real Engine handoff using a disposable synthetic native CLI; no identity login."""
import json
import os
import uuid
import time

import pytest

from numen_runner.contracts import RunRequest
from numen_runner.engine import DockerEngine, RuntimeFailure

pytestmark = pytest.mark.skipif(os.getenv('NUMEN_DOCKER_TESTS') != '1', reason='explicit Docker Engine verification only')

FIXTURE_CACHE = {'auth_json': {'tokens': {'access_token': 'synthetic-access-not-an-account', 'refresh_token': 'synthetic-refresh-not-an-account'}}}
FIXTURE_COMMAND = '''from numen_runner import workload
workload.execute=lambda _job:{"result":{"status":"ready","auth_type":"native_oauth"},"outputs":[],"credential":{"auth_json":{"tokens":{"access_token":"synthetic-access-not-an-account","refresh_token":"synthetic-refresh-not-an-account"}}}}
workload.main()
'''


class FixtureContainer:
    def __init__(self, container, trace):
        self.container = container
        self.trace = trace

    def __getattr__(self, name):
        return getattr(self.container, name)

    def exec_run(self, command, **kwargs):
        self.trace['stage'] = 'read_private_cache' if kwargs.get('stdout') else 'acknowledge_private_cache'
        return self.container.exec_run(command, **kwargs)

    def get_archive(self, path, **kwargs):
        self.trace['stage'] = 'read_private_cache'
        return self.container.get_archive(path, **kwargs)

    def put_archive(self, path, data):
        self.trace['stage'] = 'acknowledge_private_cache'
        return self.container.put_archive(path, data)


class FixtureContainers:
    def __init__(self, collection, trace):
        self.collection = collection
        self.trace = trace

    def __getattr__(self, name):
        return getattr(self.collection, name)

    def create(self, image, command=None, **kwargs):
        if image == 'numen-codex:0.1.0' and command == ['python', '-m', 'numen_runner.workload']:
            # Injection is confined to this test driver. The broker API has no image/command override.
            self.trace['stage'] = 'synthetic_native_login'
            container = self.collection.create(image, ['python', '-c', FIXTURE_COMMAND], **kwargs)
            self.trace['container_id'] = container.id
            return FixtureContainer(container, self.trace)
        return self.collection.create(image, command, **kwargs)


class FixtureClient:
    def __init__(self, client, trace):
        self.client = client
        self.containers = FixtureContainers(client.containers, trace)

    def __getattr__(self, name):
        return getattr(self.client, name)


def test_successful_synthetic_native_cache_handoff_on_real_engine():
    engine = DockerEngine()
    engine.ping()
    engine.instance = 'credential-ingress-' + str(uuid.uuid4())
    trace = {'stage': 'not_started'}
    events = []
    engine.client = FixtureClient(engine.client, trace)
    run_id = str(uuid.uuid4())
    request = RunRequest(attempt_token=run_id, kind='account_login',
                         profile={'agent':'codex', 'auth_type':'native_oauth', 'provider_id':'openai'},
                         limits={'timeout_seconds':20})
    try:
        try:
            result = engine.run(run_id, request, lambda:False, events.append)
        except Exception as error:
            pytest.fail(f"native handoff failed at {trace['stage']}: {type(error).__name__}", pytrace=False)
        assert 'synthetic-access-not-an-account' not in json.dumps(events)
        assert 'synthetic-refresh-not-an-account' not in json.dumps(events)
        assert result['credential'] == FIXTURE_CACHE
        assert result['credential_updated'] is True
        assert result['result'] == {'status':'ready', 'auth_type':'native_oauth'}
        container = engine.client.containers.get(trace['container_id'])
        logs = container.logs(stdout=True, stderr=True)
        assert b'synthetic-access-not-an-account' not in logs
        assert b'synthetic-refresh-not-an-account' not in logs
        envelopes = [json.loads(line) for line in logs.splitlines()]
        assert any(value.get('credential_ready') for value in envelopes)
        assert envelopes[-1]['credential_updated'] is True
        assert 'credential' not in envelopes[-1]['envelope']
    finally:
        engine.cleanup(run_id)


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'oversized', 'fifo', 'invalid_json'])
def test_private_cache_file_boundaries_fail_without_exposing_bytes(kind):
    engine= DockerEngine()
    engine.ping()
    engine.instance='credential-boundary-'+str(uuid.uuid4())
    run_id=str(uuid.uuid4())
    labels={'org.pruferva.numen.run':run_id, 'org.pruferva.numen.instance':engine.instance}
    network=engine.client.networks.create('numen-credential-boundary-'+run_id,internal=True,labels=labels)
    request=RunRequest(attempt_token=run_id,kind='probe',limits={'timeout_seconds':10})
    setup='''import os,time
from pathlib import Path
root=Path('/home/job');path=root/'credential-ingress.json'
kind=KIND
source=root/'fixture-source'
source.write_text('synthetic-sensitive-boundary-value')
if kind=='symlink':path.symlink_to(source)
elif kind=='hardlink':os.link(source,path)
elif kind=='oversized':path.write_bytes(b'x'*(256*1024+1))
elif kind=='fifo':os.mkfifo(path)
else:path.write_text('synthetic-sensitive-invalid-json')
print('fixture_ready',flush=True)
time.sleep(30)
'''.replace('KIND',repr(kind))
    try:
        container=engine.client.containers.create('numen-codex:0.1.0',['python','-c',setup],**engine.spec(request,network,labels))
        container.start()
        deadline=time.monotonic()+5
        while b'fixture_ready' not in container.logs():
            assert time.monotonic()<deadline
            time.sleep(.02)
        started=time.monotonic()
        with pytest.raises(RuntimeFailure) as rejected:
            engine.ingest_native_credential(container)
        assert time.monotonic()-started<5
        assert rejected.value.code=='credential_ingress_failed'
        assert 'synthetic-sensitive' not in str(rejected.value)
        assert b'synthetic-sensitive' not in container.logs(stdout=True,stderr=True)
    finally:
        engine.cleanup(run_id)


def test_login_code_reaches_private_home_through_exec_stdin_on_real_engine():
    engine=DockerEngine()
    engine.ping()
    engine.instance='login-input-'+str(uuid.uuid4())
    run_id=str(uuid.uuid4())
    labels={'org.pruferva.numen.run':run_id, 'org.pruferva.numen.instance':engine.instance}
    network=engine.client.networks.create('numen-login-input-'+run_id,internal=True,labels=labels)
    request=RunRequest(attempt_token=run_id,kind='probe',limits={'timeout_seconds':10})
    code='synthetic-authorization-code#synthetic-state'
    waiter='''import hashlib,os,time
from pathlib import Path
path=Path('/home/job/login-code')
print('fixture_ready',flush=True)
deadline=time.monotonic()+10
while not path.exists() and time.monotonic()<deadline:
    time.sleep(.02)
info=path.stat()
print(oct(info.st_mode&0o777),info.st_uid,hashlib.sha256(path.read_bytes()).hexdigest(),flush=True)
'''
    try:
        container=engine.client.containers.create('numen-claude:0.1.0',['python','-c',waiter],**engine.spec(request,network,labels))
        container.start()
        deadline=time.monotonic()+5
        while b'fixture_ready' not in container.logs():
            assert time.monotonic()<deadline
            time.sleep(.02)
        engine.deliver_login_code(container,code)
        container.wait(timeout=15)
        logs=container.logs(stdout=True,stderr=True).decode()
        import hashlib
        assert logs.split()[-3:]==['0o600','10001',hashlib.sha256(code.encode()).hexdigest()]
        assert 'synthetic-authorization-code' not in logs
        assert code not in json.dumps(container.attrs)
    finally:
        engine.cleanup(run_id)
