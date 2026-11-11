"""Generate throwaway CAs and server certificates for the local TLS tests."""

from __future__ import annotations

import datetime as dt
import ipaddress
import socket
import ssl
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NOW = dt.datetime.now(dt.timezone.utc)


def _name(cn: str, org: str | None = None) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    return x509.Name(attrs)


def make_ca(cn: str, org: str | None = None):
    key = ec.generate_private_key(ec.SECP256R1())
    name = _name(cn, org)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - dt.timedelta(days=30)).not_valid_after(NOW + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf(names: list[str], issuer=None, days_valid=(-10, 90), aia: str | None = None):
    """issuer=(key, cert) or None for self-signed."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = _name(names[0])
    issuer_key, issuer_cert = issuer if issuer else (key, None)
    sans = [x509.IPAddress(ipaddress.ip_address(n)) if n.replace(".", "").isdigit() else x509.DNSName(n) for n in names]
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW + dt.timedelta(days=days_valid[0]))
        .not_valid_after(NOW + dt.timedelta(days=days_valid[1]))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    )
    if issuer_cert is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    if aia:
        builder = builder.add_extension(x509.AuthorityInformationAccess([
            x509.AccessDescription(x509.oid.AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(aia))
        ]), critical=False)
    return key, builder.sign(issuer_key, hashes.SHA256())


def pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


class TLSServer:
    """Accepts connections on 127.0.0.1 and completes TLS handshakes with the given chain."""

    def __init__(self, tmp: Path, leaf_key, chain: list, name: str = "srv"):
        cert_file = tmp / f"{name}-chain.pem"
        key_file = tmp / f"{name}-key.pem"
        cert_file.write_bytes(b"".join(pem(c) for c in chain))
        key_file.write_bytes(key_pem(leaf_key))
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert_file, key_file)
        self.ctx.set_alpn_protocols(["h2", "http/1.1"])
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self) -> None:
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        conn.settimeout(5)
        try:
            with self.ctx.wrap_socket(conn, server_side=True) as tls:
                try:
                    tls.recv(1024)
                except (ssl.SSLError, OSError):
                    pass
        except (ssl.SSLError, OSError):
            conn.close()

    def close(self) -> None:
        self._stop = True
        self.sock.close()
