from pathlib import Path

import yaml

ROOT = Path(__file__).parents[2]


def test_every_published_port_is_bound_to_loopback():
    """A15: the dashboard and every other published port listen on 127.0.0.1 only."""
    published = {}
    for name in ("compose.yaml", "compose.test.yaml"):
        services = yaml.safe_load((ROOT / name).read_text())["services"]
        for service, spec in services.items():
            for port in spec.get("ports", []):
                published.setdefault(service, []).append(port)
                if isinstance(port, dict):
                    assert port.get("host_ip") == "127.0.0.1", (name, service, port)
                else:
                    assert str(port).startswith("127.0.0.1:"), (name, service, port)
    assert "127.0.0.1:${NUMEN_PORT:-8788}:8080" in published["app"]
