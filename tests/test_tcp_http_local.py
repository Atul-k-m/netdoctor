"""TCP states and HTTP/proxy behaviour against local sockets."""

import socket
import threading

from netdoctor.checks import http
from netdoctor.checks.http import (
    auth_schemes,
    generated_by_proxy,
    is_captive_redirect,
    parse_hsts,
    skew_seconds,
)
from netdoctor.checks.tcp import classify, tcp_connect
from netdoctor.context import Options, RunContext
from netdoctor.models import Status
from netdoctor.proxyconf import ProxyDecision
from netdoctor.target import parse_target


def test_open_and_refused():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    threading.Thread(target=lambda: srv.accept()[0].close(), daemon=True).start()
    res = tcp_connect("127.0.0.1", port, 3, teardown=True)
    assert res.state == "open" and res.close in ("fin", "rst")
    srv.close()
    assert tcp_connect("127.0.0.1", port, 4).state == "refused"


def test_classify():
    from netdoctor.checks.tcp import ConnectResult as C

    assert classify([C("open", 1), C("open", 1)]) == "open"
    assert classify([C("open", 1), C("filtered", 3000)]) == "intermittent"
    assert classify([C("refused", 1)]) == "refused"
    assert classify([C("filtered", 1), C("filtered", 1)]) == "filtered"


def test_header_helpers():
    assert parse_hsts("max-age=31536000; includeSubDomains; preload") == {
        "max_age": 31536000, "include_subdomains": True, "preload": True}
    assert parse_hsts(None) is None
    assert auth_schemes(['Basic realm="corp"', "NTLM, Negotiate"]) == ["Basic", "NTLM", "Negotiate"]
    assert is_captive_redirect("example.com", "http://portal.hotspot.net/login?url=x")
    assert is_captive_redirect("example.com", "http://10.0.0.1/")
    assert not is_captive_redirect("example.com", "https://www.example.com/")
    assert not is_captive_redirect("example.com", "/relative")
    assert abs(skew_seconds("Wed, 21 Oct 2015 07:28:00 GMT")) > 3600
    entry = {"status": 502, "headers": [("X-Squid-Error", "ERR_CONNECT_FAIL 111")]}
    assert "X-Squid-Error" in generated_by_proxy(entry, True)
    assert generated_by_proxy({"status": 502, "headers": [("Server", "nginx")]}, False) is None


class FakeProxy:
    """Answers every request with a fixed response, like a proxy demanding auth."""

    def __init__(self, response: bytes):
        self.response = response
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            try:
                c.recv(4096)
                c.sendall(self.response)
            finally:
                c.close()


def test_proxy_407_is_reported_with_schemes():
    proxy = FakeProxy(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Lab\"\r\n"
                      b"Proxy-Authenticate: Negotiate\r\nServer: squid/6.6\r\nContent-Length: 0\r\n\r\n")
    ctx = RunContext(parse_target("https://app.lab.test"), Options(captive_probes=[]))
    ctx.ip = "127.0.0.1"
    ctx.proxy = ProxyDecision(f"http://127.0.0.1:{proxy.port}", "environment")
    r = http.run(ctx)
    f = r.finding("http.proxy_auth_required")
    assert f is not None and "Basic" in f.message and "Negotiate" in f.message
    assert r.status == Status.FAIL
    proxy.sock.close()


def test_origin_502():
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response_only(502)
            self.send_header("Server", "nginx/1.25")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    ctx = RunContext(parse_target(f"http://127.0.0.1:{srv.server_port}/"), Options(captive_probes=[]))
    ctx.ip, ctx.addresses = "127.0.0.1", ["127.0.0.1"]
    r = http.run(ctx)
    srv.shutdown()
    f = r.finding("http.bad_gateway")
    assert f is not None and "backend" in f.message and "nginx" in f.message
