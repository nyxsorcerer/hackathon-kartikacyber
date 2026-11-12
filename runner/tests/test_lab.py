import pytest
from numen_runner.engine import validate_dockerfile

def test_lab_accepts_a_real_build_but_never_a_host_path_or_a_floating_base():
    built = b"""FROM mariadb@sha256:""" + b"c" * 64 + b""" AS data
FROM python:3.12.12-slim-bookworm@sha256:""" + b"d" * 64 + b"""
RUN apt-get update && apt-get install -y --no-install-recommends \\
    mariadb-client && rm -rf /var/lib/apt/lists/*
COPY --from=data /usr/bin/mariadbd /usr/bin/mariadbd
COPY app/ /app/
ENTRYPOINT ["sh", "/app/start.sh"]
"""
    assert validate_dockerfile(built)
    for text in [
        "FROM python:latest",                                        # a floating base
        "FROM asset-monitor-lab:0.1.0\nRUN --mount=type=secret echo secret",  # a build mount
        "FROM asset-monitor-lab:0.1.0\nCOPY /etc/passwd /app/",               # a host path
        "FROM asset-monitor-lab:0.1.0\nCOPY ../outside /app/",                # an escape
        "FROM asset-monitor-lab:0.1.0\nCOPY --from=python:3.12 /x /y",        # a floating stage source
    ]:
        with pytest.raises(ValueError):
            validate_dockerfile(text.encode())


# Duplicated verbatim from backend/tests/test_artifacts.py: the backend mirrors these rules in
# artifacts.completeness(), and this asserts the authority still agrees with that mirror.
LAB_BASES = [
    ("asset-monitor-lab:0.1.0", True),
    ("scratch", True),
    ("python@sha256:" + "a" * 64, True),
    ("docker.io/library/php@sha256:" + "b" * 64, True),
    ("python:3.12.12-slim-bookworm@sha256:" + "d" * 64, True),
    # A vulnerable application needs its own database and toolchain images, pinned by digest.
    ("mariadb@sha256:" + "c" * 64, True),
    ("python:3.12", False),
    ("mysql:latest", False),
]


@pytest.mark.parametrize("base,accepted", LAB_BASES)
def test_validate_dockerfile_accepts_exactly_the_bases_the_backend_publishes(base, accepted):
    from numen_runner.engine import validate_dockerfile

    data = f"FROM {base}\nCOPY fixture /fixture\n".encode()
    if accepted:
        assert validate_dockerfile(data)
    else:
        with pytest.raises(ValueError):
            validate_dockerfile(data)
