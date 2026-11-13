import pytest
from numen_runner.engine import labelled, validate_dockerfile

def test_lab_accepts_a_real_build_but_never_a_host_path_or_a_floating_base():
    built = b"""FROM asset-monitor-lab:0.1.0 AS deps
WORKDIR /app
COPY package.json package-lock.json /app/
RUN npm ci --ignore-scripts && \\
    npm cache clean --force
FROM asset-monitor-lab:0.1.0
COPY --from=deps /app/node_modules /app/node_modules
COPY app/ /app/
ENTRYPOINT ["node", "/app/server.js"]
"""
    assert validate_dockerfile(built)
    for text in [
        "FROM python:latest",                                        # a floating base
        "FROM node@sha256:" + "a" * 64,                              # a digest base the Engine would pull
        "FROM asset-monitor-lab:0.1.0\nRUN --mount=type=secret echo secret",  # a build mount
        "FROM asset-monitor-lab:0.1.0\nCOPY /etc/passwd /app/",               # a host path
        "FROM asset-monitor-lab:0.1.0\nCOPY ../outside /app/",                # an escape
        "FROM asset-monitor-lab:0.1.0\nCOPY --from=python:3.12 /x /y",        # a floating stage source
        "FROM asset-monitor-lab:0.1.0\nCOPY --from=node@sha256:" + "a" * 64 + " /x /y",  # an image, not a stage
        "FROM asset-monitor-lab:0.1.0\nADD https://example.com/x /x",         # fetched outside --network none
        'FROM asset-monitor-lab:0.1.0\nCOPY ["http://example.com/x", "/x"]',
        # The Engine drops a comment before joining continuations, so this FROM is its own.
        "FROM asset-monitor-lab:0.1.0\n  # note \\\nFROM attacker.example/x:1",
        "FROM asset-monitor-lab:0.1.0\nARG U=https://example.com/x\nADD $U /x",  # expanded by the Engine
        "ARG B=python:3.12\nFROM $B",
        "# escape=`\nFROM asset-monitor-lab:0.1.0",  # a parser directive changes the continuation
    ]:
        with pytest.raises(ValueError):
            validate_dockerfile(text.encode())


# Duplicated verbatim from backend/tests/test_artifacts.py: the backend mirrors these rules in
# artifacts.completeness(), and this asserts the authority still agrees with that mirror.
LAB_BASES = [
    ("asset-monitor-lab:0.1.0", True),
    ("scratch", True),
    # The Engine would pull a digest base outside the offline build, and keep it after the run.
    ("python@sha256:" + "a" * 64, False),
    ("docker.io/library/php@sha256:" + "b" * 64, False),
    ("node:24.9.0-bookworm-slim@sha256:" + "d" * 64, False),
    ("python:3.12", False),
    ("mysql:latest", False),
]


@pytest.mark.parametrize("base,accepted", LAB_BASES)
def test_validate_dockerfile_accepts_exactly_the_bases_the_backend_publishes(base, accepted):
    data = f"FROM {base}\nCOPY fixture /fixture\n".encode()
    if accepted:
        assert validate_dockerfile(data)
    else:
        with pytest.raises(ValueError):
            validate_dockerfile(data)


def test_every_stage_of_a_lab_build_carries_the_run_label():
    """The cleanup finds a failed build's layers and step containers by the run label."""
    text = ("# note \\\nFROM asset-monitor-lab:0.1.0 AS deps\nRUN echo \\\n  # skipped\nFROM inside-a-run\n"
            "from \\\n  deps\nCMD [\"node\"]\n")
    label = 'LABEL "run"="r1" "instance"="i"'
    # The instructions as the Engine reads them: a comment never continues, and one inside a
    # continuation is skipped.
    assert labelled(text, {"run": "r1", "instance": "i"}).splitlines() == [
        "FROM asset-monitor-lab:0.1.0 AS deps", label, "RUN echo FROM inside-a-run", "from   deps", label,
        'CMD ["node"]']


def test_a_lab_refuses_a_bundle_that_is_not_node():
    """PRD A07: the first-release Lab stack is Node. Any other is refused before the Engine is used."""
    import base64
    from numen_runner.contracts import RunRequest
    from numen_runner.engine import DockerEngine, RuntimeFailure

    class Unused:
        def __getattr__(self, name):
            raise AssertionError("the Engine was used")

    bundle = {"vulnerable-app/Dockerfile": "FROM asset-monitor-lab:0.1.0\nCOPY . /app/\n",
              "vulnerable-app/composer.json": "{}", "poc.py": "", "report.md": "A PHP Proof."}
    request = RunRequest(attempt_token="t", kind="lab", inputs=[
        {"path": p, "content_base64": base64.b64encode(d.encode()).decode()} for p, d in bundle.items()])
    with pytest.raises(RuntimeFailure) as error:
        DockerEngine(client=Unused()).build_lab("r1", request, lambda: False, lambda _: None, None, {})
    assert (error.value.code, error.value.safe_message) == (
        "lab_stack_unsupported",
        "Labs run only Node applications in this release: the Proof bundle needs vulnerable-app/package.json.")
