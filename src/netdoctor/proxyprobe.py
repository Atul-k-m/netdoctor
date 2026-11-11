"""Talk to an HTTP proxy by hand (raw CONNECT / absolute-URI GET) so we keep
everything libraries usually throw away: the exact status line, Proxy-Authenticate
schemes, Via and X-Squid-Error headers, and the body of a block page."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field

from . import __version__
from .proxyconf import ProxyDecision

USER_AGENT = f"NetDoctor/{__version__}"


@dataclass
class RawResponse:
    status: int
    reason: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    def header(self, name: str) -> str | None:
        name = name.lower()
        return next((v for k, v in self.headers if k.lower() == name), None)

    def all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]

    def to_dict(self) -> dict:
        return {"status": self.status, "reason": self.reason, "headers": self.headers,
                "body_snippet": self.body[:300].decode("latin-1", errors="replace")}


class ProxyTunnelError(Exception):
    def __init__(self, response: RawResponse) -> None:
        super().__init__(f"proxy answered {response.status} {response.reason}")
        self.response = response


def parse_head(data: bytes) -> RawResponse:
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1", errors="replace").split("\r\n")
    parts = lines[0].split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        raise ValueError(f"not an HTTP response: {lines[0][:80]!r}")
    headers = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append((k.strip(), v.strip()))
    return RawResponse(int(parts[1]), parts[2] if len(parts) > 2 else "", headers, body)


def _read_response(sock: socket.socket, want_body: bool, limit: int = 65536) -> RawResponse:
    data = b""
    while b"\r\n\r\n" not in data and len(data) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    resp = parse_head(data)
    if want_body:
        length = resp.header("content-length")
        target = int(length) if length and length.isdigit() else 16384
        try:
            while len(resp.body) < min(target, 16384):
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp.body += chunk
        except (TimeoutError, OSError):
            pass
    return resp


def _proxy_socket(proxy: ProxyDecision, timeout: float) -> socket.socket:
    hp = proxy.host_port
    if not hp or not (proxy.proxy_url or "").startswith("http://"):
        raise OSError(f"unsupported proxy {proxy.proxy_url} (only http:// proxies are probed)")
    return socket.create_connection(hp, timeout=timeout)


def connect_tunnel(proxy: ProxyDecision, host: str, port: int, timeout: float = 8.0) -> tuple[socket.socket, RawResponse]:
    """Open a CONNECT tunnel through the proxy. Raises ProxyTunnelError for a non-2xx answer."""
    sock = _proxy_socket(proxy, timeout)
    authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    try:
        sock.sendall(
            f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: {USER_AGENT}\r\n"
            "Proxy-Connection: Keep-Alive\r\n\r\n".encode()
        )
        resp = _read_response(sock, want_body=False)
    except BaseException:
        sock.close()
        raise
    if not 200 <= resp.status < 300:
        try:
            sock.settimeout(1.0)
            resp.body += sock.recv(8192)
        except OSError:
            pass
        sock.close()
        raise ProxyTunnelError(resp)
    return sock, resp


def proxy_get(proxy: ProxyDecision, url: str, timeout: float = 8.0) -> RawResponse:
    """Plain-HTTP request through the proxy using the absolute-URI form."""
    import urllib.parse

    host = urllib.parse.urlsplit(url).netloc
    with _proxy_socket(proxy, timeout) as sock:
        sock.sendall(
            f"GET {url} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\n"
            "Connection: close\r\n\r\n".encode()
        )
        return _read_response(sock, want_body=True)
