import pytest

from netdoctor.target import parse_target


@pytest.mark.parametrize(
    "text, scheme, host, port, path",
    [
        ("https://Example.COM/login?x=1", "https", "example.com", 443, "/login?x=1"),
        ("http://example.com:8080", "http", "example.com", 8080, "/"),
        ("example.com", "https", "example.com", 443, "/"),
        ("example.com.", "https", "example.com", 443, "/"),
        ("example.com:22", "tcp", "example.com", 22, "/"),
        ("example.com:80/status", "http", "example.com", 80, "/status"),
        ("10.0.0.5:443", "https", "10.0.0.5", 443, "/"),
        ("[2001:db8::1]:8443", "https", "2001:db8::1", 8443, "/"),
        ("2001:db8::1", "https", "2001:db8::1", 443, "/"),
        ("ssh://h:2222", "tcp", "h", 2222, "/"),
    ],
)
def test_parse(text, scheme, host, port, path):
    t = parse_target(text)
    assert (t.scheme, t.host, t.port, t.path) == (scheme, host, port, path)


def test_port_override_and_url():
    t = parse_target("https://example.com/a", port=8443)
    assert t.port == 8443
    assert t.url == "https://example.com:8443/a"
    assert parse_target("example.com").url == "https://example.com/"
    assert parse_target("[2001:db8::1]:443").url == "https://[2001:db8::1]/"


def test_flags():
    assert parse_target("1.2.3.4").is_ip
    assert not parse_target("example.com").is_ip
    assert parse_target("mail.example.com:993").uses_tls
    assert not parse_target("example.com:22").uses_tls
    assert not parse_target("example.com:22").is_web


@pytest.mark.parametrize("bad", ["", "   ", "https://", "example.com:99999", "example.com:abc", "gopher://x"])
def test_bad(bad):
    with pytest.raises(ValueError):
        parse_target(bad)
