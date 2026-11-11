"""Turn whatever the customer pasted into the ticket (URL, host, host:port, IP) into a Target."""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass

DEFAULT_PORTS = {"http": 80, "https": 443}
# Ports where the service normally speaks TLS from the first byte.
TLS_PORTS = {443, 465, 563, 636, 853, 989, 990, 992, 993, 994, 995, 5061, 8443}
HTTP_PORTS = {80, 8000, 8080, 8008, 8888}


@dataclass(frozen=True)
class Target:
    raw: str
    scheme: str  # "http", "https" or "tcp"
    host: str  # hostname (lower case, no trailing dot) or IP literal without brackets
    port: int
    path: str = "/"

    @property
    def is_ip(self) -> bool:
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return False

    @property
    def is_web(self) -> bool:
        return self.scheme in DEFAULT_PORTS

    @property
    def uses_tls(self) -> bool:
        return self.scheme == "https" or (self.scheme == "tcp" and self.port in TLS_PORTS)

    @property
    def url_host(self) -> str:
        return f"[{self.host}]" if ":" in self.host else self.host

    @property
    def url(self) -> str | None:
        if not self.is_web:
            return None
        netloc = self.url_host if self.port == DEFAULT_PORTS[self.scheme] else f"{self.url_host}:{self.port}"
        return f"{self.scheme}://{netloc}{self.path}"

    @property
    def endpoint(self) -> str:
        return f"{self.url_host}:{self.port}"

    def to_dict(self) -> dict:
        return {
            "raw": self.raw,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": self.path,
            "url": self.url,
        }


def _scheme_for_port(port: int) -> str:
    if port in TLS_PORTS and port in (443, 8443):
        return "https"
    if port in HTTP_PORTS:
        return "http"
    return "tcp"


def parse_target(text: str, port: int | None = None) -> Target:
    """Parse `text` into a Target. `port` (from --port) overrides any port in the text.

    Examples: "https://example.com/login", "example.com", "example.com:22",
    "10.0.0.5", "[2001:db8::1]:443".  A bare host means HTTPS on 443, because
    most tickets are "this website doesn't load".
    """
    raw = text.strip()
    if not raw:
        raise ValueError("target is empty")

    if "://" in raw:
        parts = urllib.parse.urlsplit(raw)
        scheme = parts.scheme.lower()
        host = parts.hostname
        if not host:
            raise ValueError(f"no host in {raw!r}")
        try:
            url_port = parts.port
        except ValueError as exc:
            raise ValueError(f"bad port in {raw!r}") from exc
        final_port = port or url_port or DEFAULT_PORTS.get(scheme)
        if final_port is None:
            raise ValueError(f"unknown scheme {scheme!r}; give --port")
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        if scheme not in DEFAULT_PORTS:
            scheme = "tcp"
    else:
        rest, _, tail = raw.partition("/")
        path = "/" + tail if tail else "/"
        bracket = re.fullmatch(r"\[([^\]]+)\](?::(\d+))?", rest)
        if bracket:
            host, text_port = bracket.group(1), bracket.group(2)
        elif rest.count(":") == 1:
            host, text_port = rest.split(":")
        else:  # plain host, or a bare IPv6 literal
            host, text_port = rest, None
        if text_port is not None and not text_port.isdigit():
            raise ValueError(f"bad port in {raw!r}")
        final_port = port or (int(text_port) if text_port else None)
        if final_port is None:
            scheme, final_port = "https", 443
        else:
            scheme = _scheme_for_port(final_port)

    host = host.strip().rstrip(".").lower()
    if not host:
        raise ValueError(f"no host in {raw!r}")
    if not 0 < final_port < 65536:
        raise ValueError(f"port out of range: {final_port}")
    return Target(raw=raw, scheme=scheme, host=host, port=final_port, path=path)
