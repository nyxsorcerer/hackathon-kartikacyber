"""Credential-free CONNECT proxy and capability-scoped target fetcher."""
import base64
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import select
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urljoin, urlsplit


def origin(url):
    p = urlsplit(url)
    if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password or p.fragment:
        raise ValueError("invalid target URL")
    return f"{p.scheme}://{p.hostname.lower()}:{p.port or (443 if p.scheme == 'https' else 80)}"


def resolve(host, port, policy=None):
    policy = policy or {}
    allowed = [ipaddress.ip_network(c) for c in policy.get("allowed_private_cidrs", [])]
    blocked = [ipaddress.ip_network(c) for c in policy.get("blocked_cidrs", [])]
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if any(ip in cidr for cidr in blocked) or (not ip.is_global and not any(ip in cidr for cidr in allowed)):
            raise ValueError("destination address is not allowed")
    if not addresses:
        raise ValueError("target DNS resolution failed")
    return addresses[0][4][0]


class PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, ip, secure):
        super().__init__(host, port, timeout=15)
        self.ip, self.secure = ip, secure

    def connect(self):
        self.sock = socket.create_connection((self.ip, self.port), self.timeout)
        if self.secure:
            self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=self.host)


class TargetFetcher:
    def __init__(self, policy):
        if len(policy.get("origins", [])) > 8:
            raise ValueError("too many target origins")
        self.policy = policy
        self.origins = {origin(url) for url in policy.get("origins", [])}
        self.max_requests = min(int(policy.get("request_budget", policy.get("max_requests", 20))), 100)
        self.max_bytes = min(int(policy.get("max_response_bytes", 2 * 1024 * 1024)), 8 * 1024 * 1024)
        self.remaining = self.max_requests
        self.bytes_remaining = min(int(policy.get("max_total_bytes", 16*1024*1024)), 32*1024*1024)
        self.lock = threading.Lock()
        self.expires = time.monotonic() + min(int(policy.get("expires_seconds", 1800)), 1800)

    def fetch(self, url, method="GET"):
        if method not in {"GET", "HEAD"} or method not in self.policy.get("methods", ["GET", "HEAD"]):
            raise ValueError("target method denied")
        for _ in range(6):
            if origin(url) not in self.origins:
                raise ValueError("target origin denied")
            with self.lock:
                if self.remaining <= 0 or time.monotonic() > self.expires:
                    raise ValueError("target capability expired or budget exhausted")
                self.remaining -= 1
            p = urlsplit(url)
            port = p.port or (443 if p.scheme == "https" else 80)
            ip = resolve(p.hostname, port, self.policy)
            conn = PinnedHTTP(p.hostname, port, ip, p.scheme == "https")
            try:
                conn.request(method, (p.path or "/") + ("?" + p.query if p.query else ""), headers={"User-Agent": "Numen-version-fetch/1", "Accept-Encoding": "identity"})
                response = conn.getresponse()
                if response.status in {301, 302, 303, 307, 308}:
                    location = response.getheader("Location")
                    if not location:
                        raise ValueError("redirect lacks location")
                    url = urljoin(url, location)
                    continue
                data = response.read(self.max_bytes + 1)
                if len(data) > self.max_bytes:
                    raise ValueError("target response exceeded byte limit")
                with self.lock:
                    self.bytes_remaining -= len(data)
                    if self.bytes_remaining < 0:
                        raise ValueError("target aggregate response budget exceeded")
                headers = {k.lower(): v for k, v in response.getheaders() if k.lower() not in {"set-cookie", "proxy-authenticate"}}
                return {"url": url, "status": response.status, "headers": headers, "content_base64": base64.b64encode(data).decode(), "sha256": hashlib.sha256(data).hexdigest()}
            finally:
                conn.close()
        raise ValueError("too many redirects")


class GatewayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *_):
        pass

    def do_CONNECT(self):
        upstream = None
        try:
            host, port = self.path.rsplit(":", 1)
            if host.lower() not in self.server.allowed_hosts or port != "443":
                raise ValueError("provider endpoint denied")
            ip = resolve(host, 443)
            upstream = socket.create_connection((ip, 443), timeout=15)
            self.send_response(200, "Connection Established")
            self.end_headers()
            self.connection.setblocking(False)
            upstream.setblocking(False)
            deadline = time.monotonic() + 1800
            transferred = 0
            while time.monotonic() < deadline and transferred < 64 * 1024 * 1024:
                ready, _, _ = select.select([self.connection, upstream], [], [], 10)
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    transferred += len(data)
                    destination = upstream if source is self.connection else self.connection
                    destination.setblocking(True)
                    destination.settimeout(15)
                    destination.sendall(data)
                    destination.setblocking(False)
        except (ValueError, OSError):
            if upstream is None:
                self.send_error(403, "provider endpoint denied")
        finally:
            if upstream:
                upstream.close()
            self.close_connection = True

    def do_POST(self):
        try:
            if self.path != "/fetch" or not self.server.fetcher:
                raise ValueError("fetch unavailable")
            if not hmac.compare_digest(self.headers.get("X-Fetch-Token", ""), self.server.fetch_token):
                raise ValueError("fetch capability denied")
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 16384:
                raise ValueError("invalid fetch request")
            request = json.loads(self.rfile.read(length))
            result = self.server.fetcher.fetch(request["url"], request.get("method", "GET"))
            data = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            self.send_error(403, "target request denied or unavailable")

    def do_GET(self):
        if self.path == "/health":
            data = b'{"status":"ready"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_error(405)


def main():
    # Sidecar configuration comes from the trusted broker, never from workload input.
    config = json.loads(os.environ.get("NUMEN_GATEWAY_CONFIG", "{}"))
    server = ThreadingHTTPServer(("0.0.0.0", 8082), GatewayHandler)
    server.allowed_hosts = set(config.get("provider_hosts", []))
    server.fetcher = TargetFetcher(config["target_policy"]) if config.get("target_policy") else None
    server.fetch_token = config.get("fetch_token", "")
    server.serve_forever()

if __name__ == "__main__":
    main()
