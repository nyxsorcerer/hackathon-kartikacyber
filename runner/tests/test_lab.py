import pytest
from numen_runner.engine import validate_dockerfile

def test_lab_requires_pinned_base_and_rejects_host_build_features():
    assert validate_dockerfile(b'FROM numen-lab:0.1.0\nCOPY app.py /app/app.py\nCMD ["python","/app/app.py"]') == ['numen-lab:0.1.0']
    for text in ['FROM python:latest', 'FROM numen-lab:0.1.0\nRUN --mount=type=secret echo secret', 'FROM numen-lab:0.1.0\nADD https://bad/ /app', 'FROM numen-lab:0.1.0\nVOLUME /var/run/docker.sock']:
        with pytest.raises(ValueError):
            validate_dockerfile(text.encode())
