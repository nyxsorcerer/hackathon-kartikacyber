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
