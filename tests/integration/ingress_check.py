"""The ingress listeners and roles, checked live (AC-B01).

Run by scripts/test-journey.sh inside an ingress service's own container (`compose run --no-deps
<service>`), so it reaches only that service's two networks and logs in with that service's
NUMEN_DATABASE_URL. `compose run` adds no service alias, so the service names resolve to the
running listeners.
  python ingress_check.py push
  python ingress_check.py agent <NUMEN_AGENT_TLS_PIN>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import ssl
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import serialization
import psycopg
from sqlalchemy import create_engine, exc, text


def check_role(role: str, reads=(), refused=('accounts',)):
    """The role reads each of `reads` and is refused SELECT on each of `refused`, so after a restore
    this proves its grants came back."""
    engine = create_engine(os.environ['NUMEN_DATABASE_URL'])
    with engine.connect() as connection:
        assert connection.scalar(text('SELECT current_user')) == role
        # Schema-qualified: a schema the role has no USAGE on drops out of its search_path, which
        # would turn the refusal into 'does not exist'. The refusal must be on the table: one on
        # the schema means a restore lost PUBLIC's USAGE on public, and every grant with it.
        for table in reads:
            connection.execute(text(f'SELECT 1 FROM public.{table} LIMIT 1'))
        for table in refused:
            try:
                connection.execute(text(f'SELECT 1 FROM public.{table}'))
            except exc.ProgrammingError as error:
                assert isinstance(error.orig, psycopg.errors.InsufficientPrivilege), error
                assert f'permission denied for table {table}' in str(error.orig), error
                connection.rollback()
            else:
                raise AssertionError(f'{role} read {table}')
    engine.dispose()
    print(f'PASS {role} logs in through its own network' + ''.join(f', reads {table}' for table in reads)
          + ' and cannot read ' + ' or '.join(refused))


def fetch(url: str, method='GET', context=None):
    try:
        response = urlopen(Request(url, data=b'{}' if method == 'POST' else None, method=method),
                           timeout=10, context=context)
    except HTTPError as error:
        response = error
    with response:
        return response.status, response.headers, response.read()


def expect(url: str, status: int, method='GET', context=None):
    got, headers, body = fetch(url, method, context)
    assert got == status, (method, url, got, body[:200])
    assert headers['Content-Security-Policy'], (url, 'no CSP header')
    assert 'Set-Cookie' not in headers, (url, 'set a cookie')
    return body


def push():
    check_role('asset_monitor_push', reads=('push_webhooks',), refused=('push_deliveries', 'accounts'))
    expect(f'http://ingress-push:8083/push/{uuid.uuid4().hex}', 404, 'POST')
    expect('http://ingress-push:8083/api/health', 404)
    print('PASS the push listener answers 404 to an unknown push id and does not serve /api')


def agent(pin: str):
    # B04: it reads signed messages, and may insert agent requests but never read them back.
    check_role('asset_monitor_agent', reads=('agent_messages',), refused=('agent_requests', 'accounts'))
    served = x509.load_pem_x509_certificate(ssl.get_server_certificate(('ingress-agent', 8084)).encode())
    spki = served.public_key().public_bytes(serialization.Encoding.DER,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
    assert pin and hashlib.sha256(spki).hexdigest() == pin, 'the served certificate does not match NUMEN_AGENT_TLS_PIN'
    print('PASS the agent listener serves TLS with a certificate whose key matches NUMEN_AGENT_TLS_PIN')
    # The pin, not a CA, proves the certificate; it was checked above.
    context = ssl._create_unverified_context()
    assert json.loads(expect('https://ingress-agent:8084/health', 200, context=context)) == {'status': 'ok'}
    expect('https://ingress-agent:8084/api/health', 404, context=context)
    print('PASS the agent listener answers GET /health and does not serve /api')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('listener', choices=['push', 'agent'])
    parser.add_argument('pin', nargs='?', default='')
    args = parser.parse_args()
    if args.listener == 'push':
        push()
    else:
        agent(args.pin)


if __name__ == '__main__':
    main()
