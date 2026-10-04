import json
from types import SimpleNamespace

import docker
import pytest

from numen_runner.engine import DockerEngine, RuntimeFailure


class TransportFixture:
    def __init__(self, read, ack):
        self.responses = iter([read, ack])
        self.calls = []

    def exec_run(self, command, **options):
        self.calls.append((command, options))
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response


def test_ack_failure_retains_received_cache_and_suppresses_raw_engine_error():
    secret = 'synthetic-private-rotation'
    cache = {'auth_json': {'tokens': {'access_token': secret}}}
    container = TransportFixture(SimpleNamespace(exit_code=0, output=json.dumps(cache).encode()),
                                 docker.errors.APIError('raw-engine-error-'+secret))
    with pytest.raises(RuntimeFailure) as error:
        DockerEngine(client=object()).ingest_native_credential(container)
    assert error.value.code == 'credential_ingress_failed'
    assert error.value.credential == cache
    assert secret not in str(error.value)
    assert all(secret not in json.dumps(command) for command, _ in container.calls)
    assert all(options['user'] == '10001:10001' and not options['privileged'] and not options['stderr'] for _, options in container.calls)


def test_read_transport_error_does_not_expose_raw_engine_message():
    secret = 'synthetic-private-transport-value'
    container = TransportFixture(docker.errors.APIError(secret), None)
    with pytest.raises(RuntimeFailure) as error:
        DockerEngine(client=object()).ingest_native_credential(container)
    assert error.value.code == 'credential_ingress_failed'
    assert secret not in str(error.value)
    assert not hasattr(error.value, 'credential')
