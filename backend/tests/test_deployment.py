from pathlib import Path

import yaml

ROOT = Path(__file__).parents[2]


def compose(name):
    return yaml.safe_load((ROOT / name).read_text())


def test_every_published_port_is_bound_to_loopback():
    """A15, AC-B01: the dashboard, both ingress listeners and every other published port listen on
    127.0.0.1 only."""
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
    assert "127.0.0.1:${NUMEN_PUSH_PORT:-8791}:8083" in published["ingress-push"]
    assert "127.0.0.1:${NUMEN_AGENT_PORT:-8792}:8084" in published["ingress-agent"]


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


INGRESS = {
    "ingress-push": {"networks": ["push-inbound", "push-db"], "role": "asset_monitor_push",
                     "password": "NUMEN_PUSH_DATABASE_PASSWORD", "key": "NUMEN_INGRESS_KEY"},
    "ingress-agent": {"networks": ["agent-inbound", "agent-db"], "role": "asset_monitor_agent",
                      "password": "NUMEN_AGENT_DATABASE_PASSWORD", "key": "NUMEN_AGENT_TLS_KEY"},
}
OVERLAYS = ("compose.test.yaml", "compose.demo.yaml", "compose.demo-test.yaml")


def overlay_ingress_specs():
    for name in OVERLAYS:
        for service in INGRESS:
            yield name, service, compose(name)["services"].get(service) or {}


def test_each_ingress_service_is_on_its_own_two_networks():
    """B01, ADR-0006 5: each ingress service joins its own bridge, which carries its port, and its
    own internal network that only it and db share. Neither is on application or control."""
    base = compose("compose.yaml")
    services, networks = base["services"], base["networks"]
    for service, expected in INGRESS.items():
        assert services[service]["networks"] == expected["networks"], service
        inbound, database = expected["networks"]
        assert not (networks[inbound] or {}).get("internal"), inbound
        assert networks[database]["internal"] is True, database
        on_database = {name for name, spec in services.items() if database in (spec.get("networks") or [])}
        assert on_database == {"db", service}, (database, on_database)
    assert all("name" not in (networks[name] or {}) for spec in INGRESS.values() for name in spec["networks"])
    for name, service, spec in overlay_ingress_specs():
        assert "networks" not in spec and "network_mode" not in spec, (name, service)


def test_each_ingress_service_holds_only_its_own_keys():
    """B01, ADR-0006 5: neither ingress service holds the vault key, the broker token or the owner's
    database URL. Only ingress-push, the app and the worker hold NUMEN_INGRESS_KEY, and only
    ingress-agent holds the TLS key."""
    services = compose("compose.yaml")["services"]
    for service, expected in INGRESS.items():
        environment = services[service]["environment"]
        assert set(environment) == {"NUMEN_DATABASE_URL", expected["key"]}, service
        assert environment["NUMEN_DATABASE_URL"] == (
            f"postgresql+psycopg://{expected['role']}:${{{expected['password']}:?Run setup first}}@db:5432/numen")
        assert environment[expected["key"]] == f"${{{expected['key']}:?Run setup first}}"
        other = next(spec["password"] for name, spec in INGRESS.items() if name != service)
        for value in environment.values():
            assert "POSTGRES_PASSWORD" not in value and other not in value, (service, value)
    holding = {key: {name for name, spec in services.items() if key in (spec.get("environment") or {})}
               for key in ("NUMEN_INGRESS_KEY", "NUMEN_AGENT_TLS_KEY")}
    assert holding == {"NUMEN_INGRESS_KEY": {"ingress-push", "app", "worker"},
                       "NUMEN_AGENT_TLS_KEY": {"ingress-agent"}}, holding
    for name, service, spec in overlay_ingress_specs():
        assert "environment" not in spec and "env_file" not in spec, (name, service)


def test_the_ingress_services_are_hardened():
    """B01: both ingress services run from the app image, off the x-app anchor, with a read-only
    root, no capabilities, no-new-privileges and user 10001, after migrate has set their roles."""
    services = compose("compose.yaml")["services"]
    for service in INGRESS:
        spec = services[service]
        assert spec["image"] == "asset-monitor-app:0.1.0" and "build" not in spec, service
        assert spec["read_only"] is True and spec["cap_drop"] == ["ALL"], service
        assert spec["security_opt"] == ["no-new-privileges:true"] and spec["user"] == "10001:10001", service
        assert "volumes" not in spec, service
        assert spec["command"] == ["python", "-m", "numen.ingress", service.removeprefix("ingress-")]
        assert spec["depends_on"]["migrate"]["condition"] == "service_completed_successfully", service
        assert spec["healthcheck"]["test"][0] == "CMD", service
    assert services["ingress-agent"]["tmpfs"] == ["/tmp:size=1m,uid=10001,gid=10001,mode=0700"]
    assert "tmpfs" not in services["ingress-push"]
    migrate = services["migrate"]
    assert migrate["command"] == ["sh", "-c", "alembic upgrade head && python -m numen.cli ingress-roles"]
    for spec in INGRESS.values():
        assert migrate["environment"][spec["password"]] == f"${{{spec['password']}:?Run setup first}}"


def test_every_external_base_image_is_pinned_by_digest():
    """Every image a build starts from is pinned by digest; a stage built from an earlier stage is not
    an external image."""
    for name in ("Dockerfile", "Dockerfile.runner"):
        stages = set()
        for line in (ROOT / name).read_text().splitlines():
            words = line.split()
            if not words or words[0].upper() != "FROM":
                continue
            image = next(word for word in words[1:] if not word.startswith("--"))
            assert image in stages or "@sha256:" in image, (name, line)
            if len(words) > 2 and words[-2].upper() == "AS":
                stages.add(words[-1])
        assert stages, name
