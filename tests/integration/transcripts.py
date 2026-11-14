"""A Finding's Transcripts survive a container rebuild and a backup and restore (AC-A14).

Run on the isolated asset-monitor-test project after journey.py, by scripts/test-journey.sh.
`seed` runs in the app container: it gives the newest 'Fixture Own change' Finding a Triage and
an Analysis Transcript and prints {finding_id, transcripts: {id: sha256 of its text}}. `check`
reads them back through the API.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import uuid

from journey import Client


def digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def seed():
    from sqlalchemy import select

    from numen import artifacts
    from numen.config import Config
    from numen.db import make_database
    from numen.models import Finding, Job, Transcript

    config = Config.from_env()
    _, factory = make_database(config)
    marker = f'Round-trip Transcript {uuid.uuid4().hex}'
    with factory.begin() as db:
        finding = db.scalars(select(Finding).where(Finding.title.like('Fixture Own change %'))
                             .order_by(Finding.created_at.desc())).first()
        job = db.scalars(select(Job).where(Job.application_id == finding.application_id)).first()
        subject = finding.data['source_commit_id']
        data = {'status': 'completed', 'prompt': marker, 'reply': '<script>alert(1)</script>'}
        triage = Transcript(kind='triage', job_id=job.id, subject_id=subject, data=data,
                            size=len(json.dumps(data).encode()))
        session = f'{marker}\n\n=== Latest terminal view ===\npi> done'
        ident = uuid.uuid4().hex
        revision, _ = artifacts.publish(db, config.artifact_root, 'transcript', ident,
                                        {'transcript.txt': session.encode()}, {'run_id': marker})
        analysis = Transcript(id=ident, kind='analysis', job_id=job.id, subject_id=subject,
                              data={'status': 'completed', 'run_id': marker, 'revision': revision},
                              size=len(session.encode()))
        db.add_all([triage, analysis])
        db.flush()
        # The texts GET /api/transcripts/{id} returns.
        expected = {triage.id: digest(json.dumps(data, indent=2, ensure_ascii=False)), ident: digest(session)}
    print(json.dumps({'finding_id': finding.id, 'transcripts': expected}))


def check(base_url: str, password_file: Path, expected: dict):
    client = Client(base_url)
    session = client.request('POST', '/api/auth/login', {'username': 'admin', 'password': password_file.read_text().strip()})
    client.csrf = session['csrf_token']
    finding = client.request('GET', f'/api/findings/{expected["finding_id"]}')
    listed = {t['id'] for t in finding['transcripts']}
    assert set(expected['transcripts']) <= listed, (expected, listed)
    for ident, sha256 in expected['transcripts'].items():
        assert digest(client.request('GET', f'/api/transcripts/{ident}')['text']) == sha256, ident
    print('PASS the Finding keeps its Triage and Analysis Transcripts with their ids and text')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['seed', 'check'])
    parser.add_argument('--base-url', default='http://localhost:18788')
    parser.add_argument('--password-file', type=Path, default=Path('.numen/bootstrap-password'))
    parser.add_argument('--expected', type=json.loads)
    args = parser.parse_args()
    if args.mode == 'seed':
        seed()
    else:
        check(args.base_url, args.password_file, args.expected)


if __name__ == '__main__':
    main()
