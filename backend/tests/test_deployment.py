from pathlib import Path

import yaml

ROOT = Path(__file__).parents[2]


def compose(name):
    return yaml.safe_load((ROOT / name).read_text())


def test_every_published_port_is_bound_to_loopback():
    """A15: the dashboard and every other published port listen on 127.0.0.1 only."""
    published = {}
    for name in ("compose.yaml", "compose.test.yaml", "compose.demo.yaml", "compose.demo-test.yaml"):
        for service, spec in compose(name)["services"].items():
            for port in spec.get("ports", []):
                published.setdefault(service, []).append(port)
                if isinstance(port, dict):
                    assert port.get("host_ip") == "127.0.0.1", (name, service, port)
                else:
                    assert str(port).startswith("127.0.0.1:"), (name, service, port)
    assert "127.0.0.1:${NUMEN_PORT:-8788}:8080" in published["app"]


def test_the_served_content_fixture_network_is_opened_only_by_an_overlay():
    """A10: compose.yaml never opens the demo fixture's private range; the demo overlay opens its
    own project's served network, so it never reaches another project's network or data."""
    broker = compose("compose.yaml")["services"]["runner-broker"]["environment"]
    assert broker["NUMEN_SERVED_CONTENT_FIXTURE_NETWORK"] == "${NUMEN_SERVED_CONTENT_FIXTURE_NETWORK:-}"
    demo = compose("compose.demo.yaml")
    demo_broker = demo["services"]["runner-broker"]["environment"]
    assert demo_broker["NUMEN_SERVED_CONTENT_FIXTURE_NETWORK"] == "${COMPOSE_PROJECT_NAME}_served"
    # The project name comes from scripts/demo.sh's -p, and every network is the project's own.
    assert "name" not in demo
    assert all("name" not in (spec or {}) for spec in demo["networks"].values()), demo["networks"]
    assert demo["networks"]["served"]["internal"] is True


def test_the_canned_dry_run_broker_is_only_in_the_test_overlay():
    """A16, brief 5(b): the dry run's canned agent decisions come from a broker in the test-only
    overlay. The demo overlay itself never adds it or points a service at another broker, so a demo
    run's agents are always the real runner's."""
    demo = compose("compose.demo.yaml")["services"]
    assert "canned-broker" not in demo
    assert all("NUMEN_BROKER_URL" not in (spec.get("environment") or {}) for spec in demo.values()), demo
    canned = compose("compose.demo-test.yaml")["services"]
    assert canned["canned-broker"]["entrypoint"] == ["python", "/fixtures/canned_broker.py"]
    assert "ports" not in canned["canned-broker"]
    for service in ("app", "worker", "scheduler"):
        assert canned[service]["environment"]["NUMEN_BROKER_URL"] == "http://canned-broker:8081", service
