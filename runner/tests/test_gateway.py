from unittest.mock import patch
import pytest
from numen_runner.gateway import TargetFetcher, resolve, origin

def test_private_dns_and_rebinding_are_denied():
    answers = [(2, 1, 6, "", ("8.8.8.8", 443)), (2, 1, 6, "", ("127.0.0.1", 443))]
    with patch("socket.getaddrinfo", return_value=answers), pytest.raises(ValueError):
        resolve("public.example", 443)

def test_explicit_private_policy_still_denies_control_network():
    answers = [(2, 1, 6, "", ("172.20.0.8", 80))]
    with patch("socket.getaddrinfo", return_value=answers), pytest.raises(ValueError):
        resolve("private.example", 80, {"allowed_private_cidrs": ["172.20.0.0/16"], "blocked_cidrs": ["172.20.0.0/16"]})

def test_scope_and_methods_denied_before_network():
    fetcher = TargetFetcher({"origins": ["https://target.example"]})
    with pytest.raises(ValueError):
        fetcher.fetch("https://other.example")
    with pytest.raises(ValueError):
        fetcher.fetch("https://target.example", "POST")
    with pytest.raises(ValueError):
        origin("https://user:password@target.example")


def test_only_a_run_hosting_a_herdr_session_may_reach_herdr_dev():
    """Analysis in a Herdr session gets its provider's hosts plus herdr.dev; Triage never hosts a session."""
    from numen_runner.contracts import PROVIDERS, RunRequest
    from numen_runner.engine import DockerEngine, gateway_config
    engine = DockerEngine(client=object())
    engine.agent_backend = "herdr"
    profile = {"agent": "pi", "provider_id": "deepseek", "model_id": "m", "credential": {"api_key": "k"}}
    for operation, extra in (("commit_triage", []), ("commit_analysis", ["herdr.dev"])):
        request = RunRequest(attempt_token="t", kind="agent", profile={**profile, "operation": operation})
        hosts = gateway_config(request, request.profile.model_dump(), engine.hosts_session(request))
        assert hosts == {"provider_hosts": PROVIDERS["deepseek"] + extra}, operation
    engine.agent_backend = "native"  # Print mode: no session, so no herdr.dev for Analysis either.
    assert not engine.hosts_session(request)


def test_lab_fetch_gateway_reaches_only_the_registry(monkeypatch):
    """A Lab's dependency fetch reaches only the npm registry through the gateway, never a provider,
    though its default Profile names openai."""
    from numen_runner.contracts import RunRequest
    from numen_runner.engine import gateway_config
    request = RunRequest(attempt_token="t", kind="lab")
    profile = request.profile.model_dump()
    assert profile["provider_id"] == "openai"
    monkeypatch.delenv("NUMEN_NPM_REGISTRY_URL", raising=False)
    assert gateway_config(request, profile, False) == {"provider_hosts": ["registry.npmjs.org"]}
    monkeypatch.setenv("NUMEN_NPM_REGISTRY_URL", "https://npm.mirror.example/")
    assert gateway_config(request, profile, True) == {"provider_hosts": ["npm.mirror.example"]}


PUBLIC = "93.184.216.34"


def answer(host, port, *args, **kwargs):
    """getaddrinfo for a test: an address literal resolves to itself, any name to PUBLIC."""
    import ipaddress
    try:
        address = str(ipaddress.ip_address(host))
    except ValueError:
        address = PUBLIC
    return [(10 if ":" in address else 2, 1, 6, "", (address, port))]


class Response:
    def __init__(self, status, location=None, body=b"page"):
        self.status, self.location, self.body = status, location, body

    def getheader(self, name):
        return self.location if name == "Location" else None

    def getheaders(self):
        return [("Content-Type", "text/html")]

    def read(self, limit):
        return self.body[:limit]


def server(responses, opened):
    """A stand-in for PinnedHTTP that records each connection (host, pinned ip, request headers)
    and answers from `responses` in turn."""
    class Connection:
        def __init__(self, host, port, ip, secure):
            self.record = {"host": host, "ip": ip}
            opened.append(self.record)

        def request(self, method, path, headers):
            self.record["headers"] = headers

        def getresponse(self):
            return responses.pop(0)

        def close(self):
            pass
    return Connection


def test_served_content_policy_allows_any_public_origin_and_refuses_non_public_addresses():
    """A10: the served-content policy has no origin list, but every address it would connect to
    must be public: private, loopback, link-local, multicast, reserved and unspecified addresses,
    and an IPv4 one inside IPv6, are refused before any connection."""
    from numen_runner import gateway
    opened = []
    with patch("socket.getaddrinfo", side_effect=answer), patch.object(gateway, "PinnedHTTP", server([Response(200)], opened)):
        fetcher = TargetFetcher({"served_content": True})
        assert fetcher.fetch("https://any-shop.example/")["status"] == 200
        for address in ("10.0.0.1", "127.0.0.1", "169.254.169.254", "224.0.0.1", "240.0.0.1", "0.0.0.0",
                        "::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1"):
            with patch("socket.getaddrinfo", return_value=answer(address, 443)), pytest.raises(ValueError, match="not allowed"):
                fetcher.fetch("https://injected.example/")
        # Any origin, but still only an http(s) URL with no credentials or fragment, and GET or HEAD.
        for url in ("ftp://any-shop.example/", "https://user:pw@any-shop.example/", "https://any-shop.example/#x"):
            with pytest.raises(ValueError, match="invalid target URL"):
                fetcher.fetch(url)
        with pytest.raises(ValueError, match="method denied"):
            fetcher.fetch("https://any-shop.example/", "POST")
    assert [record["ip"] for record in opened] == [PUBLIC]


def test_served_content_private_range_is_only_the_allowed_one_and_blocked_still_wins():
    with patch("socket.getaddrinfo", return_value=answer("172.30.0.5", 80)):
        policy = {"served_content": True, "allowed_private_cidrs": ["172.30.0.0/24"]}
        assert resolve("judol-fixture", 80, policy) == "172.30.0.5"
        with pytest.raises(ValueError):
            resolve("judol-fixture", 80, {**policy, "blocked_cidrs": ["172.30.0.0/16"]})
    with patch("socket.getaddrinfo", return_value=answer("172.31.0.5", 80)), pytest.raises(ValueError):
        resolve("elsewhere", 80, policy)


def test_a_redirect_to_a_private_address_is_refused():
    """Every redirect hop is resolved and checked again before it is followed."""
    from numen_runner import gateway
    opened = []
    responses = [Response(302, "http://10.0.0.1/")]
    with patch("socket.getaddrinfo", side_effect=answer), patch.object(gateway, "PinnedHTTP", server(responses, opened)):
        with pytest.raises(ValueError, match="not allowed"):
            TargetFetcher({"served_content": True}).fetch("https://any-shop.example/")
    assert [(record["host"], record["ip"]) for record in opened] == [("any-shop.example", PUBLIC)]


def test_the_connection_is_pinned_to_the_resolved_address():
    """The connection goes to the address that was checked (no second lookup to rebind), and TLS
    is still verified against the hostname."""
    from unittest.mock import Mock
    import ssl
    from numen_runner import gateway
    seen = {}

    class Context:
        def wrap_socket(self, sock, server_hostname):
            seen["tls"] = server_hostname
            raise ssl.SSLError("stop before any request")

    def connect(address, timeout):
        seen["address"] = address
        return Mock()

    with patch("socket.getaddrinfo", side_effect=answer), patch.object(gateway.socket, "create_connection", connect), \
            patch.object(gateway.ssl, "create_default_context", return_value=Context()), pytest.raises(OSError):
        TargetFetcher({"served_content": True}).fetch("https://any-shop.example/")
    assert seen == {"address": (PUBLIC, 443), "tls": "any-shop.example"}


def test_the_user_agent_is_one_of_the_fixed_pair():
    """A10: the user agent is chosen per request from the fixed browser and Googlebot pair, and is
    sent on every redirect hop. A version recipe's fetch keeps its own."""
    from numen_runner import gateway
    opened = []
    responses = [Response(302, "/next"), Response(200), Response(200), Response(200)]
    with patch("socket.getaddrinfo", side_effect=answer), patch.object(gateway, "PinnedHTTP", server(responses, opened)):
        fetcher = TargetFetcher({"served_content": True})
        fetcher.fetch("https://any-shop.example/", user_agent="googlebot")
        fetcher.fetch("https://any-shop.example/", user_agent="browser")
        fetcher.fetch("https://any-shop.example/")
        with pytest.raises(ValueError, match="user agent denied"):
            fetcher.fetch("https://any-shop.example/", user_agent="Mozilla/5.0 (custom)")
    agents = [record["headers"]["User-Agent"] for record in opened]
    assert agents == [gateway.USER_AGENTS["googlebot"]] * 2 + [gateway.USER_AGENTS["browser"], "Numen-version-fetch/1"]
    assert "Googlebot/2.1" in gateway.USER_AGENTS["googlebot"] and "Chrome/" in gateway.USER_AGENTS["browser"]


def test_version_recipe_policy_stays_origin_scoped():
    """Without served_content the fetcher reaches only its origins, a redirect hop included."""
    from numen_runner import gateway
    opened = []
    responses = [Response(302, "https://elsewhere.example/")]
    with patch("socket.getaddrinfo", side_effect=answer), patch.object(gateway, "PinnedHTTP", server(responses, opened)):
        fetcher = TargetFetcher({"origins": ["https://target.example"], "served_content": False})
        with pytest.raises(ValueError, match="origin denied"):
            fetcher.fetch("https://any-shop.example/")
        with pytest.raises(ValueError, match="origin denied"):
            fetcher.fetch("https://target.example/")
    assert [record["host"] for record in opened] == ["target.example"]


def test_served_fixture_cidrs_are_empty_unless_the_broker_names_a_network(monkeypatch):
    """The demo fixture's private range comes only from the broker's setting, which names a Docker
    network (the demo VM's); it is empty by default and for a network that does not exist."""
    from types import SimpleNamespace
    import docker
    from numen_runner.engine import served_fixture_cidrs

    class Networks:
        def get(self, name):
            if name != "demo_fixtures":
                raise docker.errors.NotFound("no such network")
            return SimpleNamespace(attrs={"IPAM": {"Config": [{"Subnet": "172.30.0.0/24", "Gateway": "172.30.0.1"}, {}]}})

    client = SimpleNamespace(networks=Networks())
    monkeypatch.delenv("NUMEN_SERVED_CONTENT_FIXTURE_NETWORK", raising=False)
    assert served_fixture_cidrs(client) == []
    monkeypatch.setenv("NUMEN_SERVED_CONTENT_FIXTURE_NETWORK", "")
    assert served_fixture_cidrs(client) == []
    monkeypatch.setenv("NUMEN_SERVED_CONTENT_FIXTURE_NETWORK", "missing")
    assert served_fixture_cidrs(client) == []
    monkeypatch.setenv("NUMEN_SERVED_CONTENT_FIXTURE_NETWORK", "demo_fixtures")
    assert served_fixture_cidrs(client) == ["172.30.0.0/24"]
