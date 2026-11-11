import struct

import pytest

from netdoctor import proxyconf
from netdoctor.proxyconf import (
    PacResult,
    ProxySetting,
    bypass_match,
    decide,
    no_proxy_match,
    parse_connection_blob,
    parse_pac_result,
    proxy_for_scheme,
)
from netdoctor.target import parse_target


def blob(flags: int, proxy: str = "", bypass: str = "", pac: str | None = None) -> bytes:
    out = struct.pack("<III", 0x46, 7, flags)
    for s in (proxy, bypass) + ((pac,) if pac is not None else ()):
        out += struct.pack("<I", len(s)) + s.encode("latin-1")
    return out + b"\x00" * 28


def test_blob_winhttp_direct():
    # The exact bytes `netsh winhttp reset proxy` leaves behind.
    raw = bytes.fromhex("1800000000000000010000000000000000000000")
    parsed = parse_connection_blob(raw)
    assert parsed["direct"] and not parsed["proxy_enabled"] and parsed["proxy"] == ""


def test_blob_with_proxy_and_pac():
    parsed = parse_connection_blob(blob(0x0F, "proxy.corp:8080", "<local>;*.corp", "http://pac.corp/proxy.pac"))
    assert parsed["proxy_enabled"] and parsed["auto_config"] and parsed["auto_detect"]
    assert parsed["proxy"] == "proxy.corp:8080"
    assert parsed["bypass"] == "<local>;*.corp"
    assert parsed["pac_url"] == "http://pac.corp/proxy.pac"


def test_blob_truncated_is_safe():
    assert parse_connection_blob(b"\x01\x02")["flags"] == 0
    assert parse_connection_blob(struct.pack("<IIII", 1, 1, 3, 500))["proxy"] == ""


@pytest.mark.parametrize("server, scheme, expected", [
    ("proxy:8080", "https", "http://proxy:8080"),
    ("http=p1:80;https=p2:443", "https", "http://p2:443"),
    ("http=p1:80;https=p2:443", "http", "http://p1:80"),
    ("socks=s:1080", "https", "socks5://s:1080"),
    ("ftp=f:21", "https", None),
    (None, "https", None),
])
def test_proxy_for_scheme(server, scheme, expected):
    assert proxy_for_scheme(server, scheme) == expected


def test_bypass_match():
    patterns = ["<local>", "*.corp.example", "10.*"]
    assert bypass_match("intranet", patterns)
    assert bypass_match("app.corp.example", patterns)
    assert bypass_match("10.1.2.3", patterns)
    assert not bypass_match("example.com", patterns)


@pytest.mark.parametrize("host, no_proxy, expected", [
    ("api.example.com", "example.com", True),
    ("api.example.com", ".example.com", True),
    ("example.com", "example.com", True),
    ("badexample.com", "example.com", False),
    ("10.1.2.3", "10.0.0.0/8", True),
    ("192.168.1.1", "10.0.0.0/8,localhost", False),
    ("anything", "*", True),
    ("host", "", False),
])
def test_no_proxy(host, no_proxy, expected):
    assert no_proxy_match(host, no_proxy) is expected


def test_parse_pac_result():
    assert parse_pac_result("PROXY 10.0.0.1:8080; DIRECT") == ("http://10.0.0.1:8080", "PROXY 10.0.0.1:8080")
    assert parse_pac_result("DIRECT") == (None, "DIRECT")
    assert parse_pac_result("SOCKS5 s:1080")[0] == "socks5://s:1080"
    assert parse_pac_result(None) == (None, "DIRECT")


def _env(**raw):
    return ProxySetting("env", "env", enabled=bool(raw.get("https_proxy") or raw.get("http_proxy")), raw=raw)


def test_decide_order():
    t = parse_target("https://example.com")
    wininet = ProxySetting("wininet", "w", enabled=True, server="sys:3128", bypass=["<local>"])
    assert decide(t, _env(), None, None, cli_no_proxy=True).proxy_url is None
    assert decide(t, _env(), None, None, cli_proxy="cli:1").proxy_url == "http://cli:1"
    assert decide(t, _env(https_proxy="http://env:3128"), wininet, None).source == "environment"
    assert decide(t, _env(https_proxy="http://env:3128", no_proxy="example.com"), wininet, None).proxy_url is None
    pac = PacResult(url="http://pac", fetched=True, result="PROXY pac:80; DIRECT")
    assert decide(t, _env(), wininet, pac).proxy_url == "http://pac:80"
    assert decide(t, _env(), wininet, None).proxy_url == "http://sys:3128"
    assert decide(parse_target("https://intranet"), _env(), wininet, None).proxy_url is None
    assert decide(parse_target("example.com:22"), _env(https_proxy="http://env:1"), None, None).proxy_url is None


def test_env_setting_reads_both_cases(monkeypatch):
    for k in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "no_proxy", "NO_PROXY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://squid:3128")
    monkeypatch.setenv("no_proxy", "localhost,.lab")
    s = proxyconf.env_setting()
    assert s.enabled and s.raw["https_proxy"] == "http://squid:3128"
    assert s.bypass == ["localhost", ".lab"]
