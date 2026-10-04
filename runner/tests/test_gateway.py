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
