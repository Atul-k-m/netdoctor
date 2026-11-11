"""Real TLS handshakes against local servers with crafted certificates.

The "OS trust store" is pointed at a test CA so we can play out every trust
scenario offline: private CA, an inspecting proxy's CA, untrusted, expired,
wrong host, self-signed, missing intermediate."""

import ssl

import pytest

from netdoctor.checks import tls
from netdoctor.checks.tls import detect_vendor, hostname_matches, wildcard_match
from netdoctor.context import Options, RunContext
from netdoctor.models import Status
from netdoctor.target import parse_target

from .certs import TLSServer, make_ca, make_leaf, pem

HOST = "app.lab.test"


@pytest.fixture
def run_tls(tmp_path, monkeypatch):
    servers = []

    def go(chain_builder, trusted_ca=None, host=HOST):
        leaf_key, chain = chain_builder()
        srv = TLSServer(tmp_path, leaf_key, chain, name=f"s{len(servers)}")
        servers.append(srv)
        original = tls.make_context
        if trusted_ca is not None:
            ca_file = tmp_path / f"ca{len(servers)}.pem"
            ca_file.write_bytes(pem(trusted_ca))

            def fake(kind):
                if kind == "system":
                    c = ssl.create_default_context(cafile=str(ca_file))
                    c.set_alpn_protocols(tls.ALPN)
                    return c
                return original(kind)

            monkeypatch.setattr(tls, "make_context", fake)
        else:
            monkeypatch.setattr(tls, "make_context", original)
        ctx = RunContext(parse_target(f"https://{host}:{srv.port}"), Options())
        ctx.ip = "127.0.0.1"
        return tls.run(ctx)

    yield go
    for s in servers:
        s.close()


def codes(result):
    return {f.code for f in result.findings}


def test_private_ca_trusted_locally(run_tls):
    ca = make_ca("Lab Root CA", "NetDoctor Lab")
    r = run_tls(lambda: (lambda k, c: (k, [c]))(*make_leaf([HOST], ca)), trusted_ca=ca[1])
    assert codes(r) == {"tls.private_ca", "tls.ok"}
    assert r.status == Status.INFO
    assert r.data["alpn"] in ("h2", "http/1.1") and r.data["version"].startswith("TLSv1.")
    assert len(r.data["verified_chain"]) == 2  # leaf + root from the "store"


def test_inspection_vendor_ca(run_tls):
    ca = make_ca("Zscaler Root CA", "Zscaler Inc.")
    r = run_tls(lambda: (lambda k, c: (k, [c]))(*make_leaf([HOST], ca)), trusted_ca=ca[1])
    assert "tls.intercepted" in codes(r) and r.status == Status.WARN


def test_inspection_vendor_untrusted(run_tls):
    ca = make_ca("mitmproxy", "mitmproxy")
    r = run_tls(lambda: (lambda k, c: (k, [c]))(*make_leaf([HOST], ca)))
    assert "tls.intercepted_untrusted" in codes(r) and r.status == Status.FAIL


def test_untrusted_ca(run_tls):
    ca = make_ca("Some Private CA")
    r = run_tls(lambda: (lambda k, c: (k, [c, ca[1]]))(*make_leaf([HOST], ca)))
    assert "tls.untrusted" in codes(r)


def test_incomplete_chain(run_tls):
    trusted_root = make_ca("Real Root")
    # leaf issued by an intermediate the server forgets to send (and the leaf has AIA, like public certs)
    inter = make_ca("Real Intermediate")
    r = run_tls(lambda: (lambda k, c: (k, [c]))(*make_leaf([HOST], inter, aia="http://ca.example/inter.crt")),
                trusted_ca=trusted_root[1])
    assert "tls.incomplete_chain" in codes(r)


def test_expired(run_tls):
    ca = make_ca("Lab Root CA")
    r = run_tls(lambda: (lambda k, c: (k, [c]))(*make_leaf([HOST], ca, days_valid=(-400, -5))), trusted_ca=ca[1])
    assert "tls.expired" in codes(r) and r.status == Status.FAIL


def test_not_yet_valid(run_tls):
    ca = make_ca("Lab Root CA")
    r = run_tls(lambda: (lambda k, c: (k, [c]))(*make_leaf([HOST], ca, days_valid=(5, 400))), trusted_ca=ca[1])
    assert "tls.not_yet_valid" in codes(r)


def test_hostname_mismatch(run_tls):
    ca = make_ca("Lab Root CA")
    r = run_tls(lambda: (lambda k, c: (k, [c]))(*make_leaf(["other.lab.test"], ca)), trusted_ca=ca[1])
    assert "tls.hostname_mismatch" in codes(r)


def test_self_signed(run_tls):
    r = run_tls(lambda: (lambda k, c: (k, [c]))(*make_leaf([HOST])))
    assert "tls.self_signed" in codes(r)


def test_not_tls(tmp_path):
    import socket
    import threading

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def answer():
        c, _ = srv.accept()
        c.recv(1024)
        c.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        c.close()

    threading.Thread(target=answer, daemon=True).start()
    ctx = RunContext(parse_target(f"https://{HOST}:{srv.getsockname()[1]}"), Options())
    ctx.ip = "127.0.0.1"
    r = tls.run(ctx)
    srv.close()
    assert r.status == Status.FAIL
    assert codes(r) & {"tls.not_tls", "tls.handshake_failed", "tls.eof", "tls.reset"}


def test_name_helpers():
    assert wildcard_match("*.example.com", "a.example.com")
    assert not wildcard_match("*.example.com", "a.b.example.com")
    assert not wildcard_match("*.example.com", "example.com")
    assert hostname_matches("10.0.0.1", {"san_dns": [], "san_ip": ["10.0.0.1"]})
    info = {"issuer": "CN=Zscaler Intermediate Root CA,O=Zscaler Inc.", "subject": "CN=x", "is_ca": False}
    assert detect_vendor([info])[0] == "Zscaler"
    public = {"issuer": "CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation", "subject": "CN=x", "is_ca": False}
    assert detect_vendor([public]) is None
