"""TLS: protocol version, cipher, ALPN, SNI, the full chain, expiry, hostname,
trust, and whether the certificate was re-signed by an inspecting proxy.

Up to three handshakes: (1) verified against the OS trust store (what most apps
do), (2) verified against Mozilla's public roots (certifi), and (3) unverified,
only when (1) failed, to still read the version, cipher and chain. Comparing (1)
and (2) tells "publicly trusted" from "trusted only because a private root is
installed on this device", which is how TLS inspection shows up."""

from __future__ import annotations

import re
import socket
import ssl
import time
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from ..context import RunContext
from ..models import CheckResult, Status, Table
from ..netutil import IS_WINDOWS, classify_ip, fmt_ms
from ..proxyprobe import ProxyTunnelError, connect_tunnel

ID = "tls"
LAYER = "L5-L6 TLS"
TITLE = "TLS handshake and certificate chain"

HANDSHAKE_TIMEOUT = 8.0
ALPN = ["h2", "http/1.1"]
ENCODING_DER = getattr(getattr(ssl, "_ssl", None), "ENCODING_DER", 2)

VERIFY_TEXT = {
    2: "unable to get issuer certificate",
    9: "certificate is not yet valid",
    10: "certificate has expired",
    18: "self-signed certificate",
    19: "self-signed certificate in certificate chain",
    20: "unable to get local issuer certificate",
    21: "unable to verify the first certificate",
    26: "unsupported certificate purpose",
    62: "hostname mismatch",
    64: "IP address mismatch",
    66: "EE certificate key too weak",
    67: "CA certificate key too weak",
    68: "CA signature digest algorithm too weak",
}
UNTRUSTED_CODES = {2, 18, 19, 20, 21}

# Issuer names used by TLS-inspection products. Specific on purpose: generic words
# like "Cloudflare" or "Cisco" also appear in real public CAs.
INSPECTION_VENDORS = [
    ("Zscaler", r"zscaler"),
    ("Netskope", r"netskope"),
    ("Palo Alto Networks", r"palo ?alto|pan-?os|globalprotect"),
    ("Fortinet FortiGate", r"fortinet|fortigate"),
    ("Cisco Umbrella", r"cisco umbrella|opendns"),
    ("Symantec/Broadcom (Blue Coat)", r"blue ?coat|proxysg|web security service"),
    ("Forcepoint", r"forcepoint|websense"),
    ("Sophos", r"sophos"),
    ("Check Point", r"check ?point"),
    ("Barracuda", r"barracuda"),
    ("Skyhigh/McAfee Web Gateway", r"skyhigh|mcafee web gateway"),
    ("iboss", r"iboss"),
    ("Menlo Security", r"menlo security"),
    ("Cloudflare Gateway", r"cloudflare for teams|gateway ca - cloudflare"),
    ("Kaspersky", r"kaspersky"),
    ("ESET", r"eset ssl filter"),
    ("Avast/AVG", r"avast|avg web"),
    ("Bitdefender", r"bitdefender"),
    ("mitmproxy", r"mitmproxy"),
    ("Fiddler", r"do_not_trust_fiddler|fiddler"),
    ("Burp Suite", r"portswigger"),
    ("Charles Proxy", r"charles proxy"),
]


@dataclass
class Handshake:
    label: str
    ok: bool = False
    kind: str | None = None  # verify | alert | reset | timeout | eof | not_tls | proxy | connect | other
    verify_code: int | None = None
    verify_message: str | None = None
    error: str | None = None
    version: str | None = None
    cipher: str | None = None
    bits: int | None = None
    alpn: str | None = None
    served: list[bytes] = field(default_factory=list)
    verified: list[bytes] = field(default_factory=list)
    ms: float | None = None
    path: str = "direct"
    proxy_response: dict | None = None

    def to_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k not in ("served", "verified")}
        d["served_count"] = len(self.served)
        d["verified_count"] = len(self.verified)
        return d


# ------------------------------------------------------------ certificate helpers


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _attr(name: x509.Name, oid) -> str | None:
    vals = name.get_attributes_for_oid(oid)
    return str(vals[0].value) if vals else None


def cert_info(der: bytes) -> dict:
    c = x509.load_der_x509_certificate(der)
    try:
        san = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        dns_names = san.get_values_for_type(x509.DNSName)
        ip_names = [str(i) for i in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        dns_names, ip_names = [], []
    try:
        is_ca = c.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    try:
        aia = c.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        ca_issuers = [d.access_location.value for d in aia if d.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS]
    except x509.ExtensionNotFound:
        ca_issuers = []
    key = c.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        key_desc = f"RSA {key.key_size}"
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key_desc = f"EC {key.curve.name}"
    elif isinstance(key, ed25519.Ed25519PublicKey):
        key_desc = "Ed25519"
    elif isinstance(key, ed448.Ed448PublicKey):
        key_desc = "Ed448"
    else:
        key_desc = type(key).__name__
    nb = _utc(getattr(c, "not_valid_before_utc", None) or c.not_valid_before)
    na = _utc(getattr(c, "not_valid_after_utc", None) or c.not_valid_after)
    return {
        "subject": c.subject.rfc4514_string(),
        "issuer": c.issuer.rfc4514_string(),
        "subject_cn": _attr(c.subject, NameOID.COMMON_NAME),
        "subject_o": _attr(c.subject, NameOID.ORGANIZATION_NAME),
        "issuer_cn": _attr(c.issuer, NameOID.COMMON_NAME),
        "issuer_o": _attr(c.issuer, NameOID.ORGANIZATION_NAME),
        "san_dns": dns_names,
        "san_ip": ip_names,
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "is_ca": is_ca,
        "self_issued": c.subject == c.issuer,
        "key": key_desc,
        "signature": c.signature_hash_algorithm.name if c.signature_hash_algorithm else "none",
        "serial": format(c.serial_number, "x"),
        "sha256": c.fingerprint(hashes.SHA256()).hex(),
        "ca_issuers": ca_issuers,
    }


def wildcard_match(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and "." not in host[: -len(suffix)] and len(host) > len(suffix)
    return pattern == host


def hostname_matches(host: str, info: dict) -> bool:
    if re.fullmatch(r"[\d.]+|[0-9a-fA-F:]+", host) and ("." in host or ":" in host):
        return host in info["san_ip"]
    return any(wildcard_match(p, host) for p in info["san_dns"])


def detect_vendor(infos: list[dict]) -> tuple[str, str] | None:
    """Return (vendor, matching name) if any certificate in the chain was issued by an inspection product."""
    for info in infos:
        for text in (info["issuer"], info["subject"] if info["is_ca"] else ""):
            for vendor, pattern in INSPECTION_VENDORS:
                if text and re.search(pattern, text, re.I):
                    return vendor, text
    return None


def _short(info: dict, which: str) -> str:
    cn, o = info[f"{which}_cn"], info[f"{which}_o"]
    if cn and o and o not in cn:
        return f"{cn} ({o})"
    return cn or o or info[which]


# ------------------------------------------------------------------- handshakes


def _chain(sock: ssl.SSLSocket, verified: bool) -> list[bytes]:
    name = "get_verified_chain" if verified else "get_unverified_chain"
    fn = getattr(sock, name, None) or getattr(getattr(sock, "_sslobj", None), name, None)
    if fn is None:
        leaf = sock.getpeercert(binary_form=True)
        return [leaf] if leaf and not verified else []
    out = []
    for item in fn() or []:
        out.append(bytes(item) if isinstance(item, (bytes, bytearray)) else item.public_bytes(ENCODING_DER))
    return out


def make_context(kind: str) -> ssl.SSLContext:
    if kind == "system":
        ctx = ssl.create_default_context()
    elif kind == "mozilla":
        ctx = ssl.create_default_context(cafile=certifi.where())
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:  # let the diagnostic handshake see servers stuck on TLS 1.0/1.1
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            pass
    ctx.set_alpn_protocols(ALPN)
    return ctx


def open_socket(ctx: RunContext, timeout: float, force_direct: bool = False) -> tuple[socket.socket, str, dict | None]:
    t = ctx.target
    if ctx.proxied and not force_direct and ctx.proxy is not None:
        sock, resp = connect_tunnel(ctx.proxy, t.host, t.port, timeout)
        return sock, f"CONNECT via {ctx.proxy.proxy_url}", resp.to_dict()
    sock = socket.create_connection((ctx.ip, t.port), timeout=timeout)
    return sock, "direct", None


def handshake(ctx: RunContext, kind: str, label: str, force_direct: bool = False) -> Handshake:
    hs = Handshake(label)
    try:
        raw, hs.path, hs.proxy_response = open_socket(ctx, HANDSHAKE_TIMEOUT, force_direct)
    except ProxyTunnelError as exc:
        hs.kind, hs.error, hs.proxy_response = "proxy", str(exc), exc.response.to_dict()
        return hs
    except OSError as exc:
        hs.kind, hs.error = "connect", f"TCP connect failed: {exc}"
        return hs
    sni = None if ctx.target.is_ip else ctx.target.host
    sslctx = make_context(kind)
    raw.settimeout(HANDSHAKE_TIMEOUT)
    started = time.perf_counter()
    try:
        with sslctx.wrap_socket(raw, server_hostname=sni or ctx.target.host) as s:
            hs.ms = (time.perf_counter() - started) * 1000.0
            hs.ok = True
            hs.version = s.version()
            cipher = s.cipher()
            if cipher:
                hs.cipher, hs.bits = cipher[0], cipher[2]
            hs.alpn = s.selected_alpn_protocol()
            hs.served = _chain(s, verified=False)
            if kind != "raw":
                hs.verified = _chain(s, verified=True)
    except ssl.SSLCertVerificationError as exc:
        hs.kind, hs.verify_code, hs.verify_message, hs.error = "verify", exc.verify_code, exc.verify_message, str(exc)
    except ssl.SSLEOFError as exc:
        hs.kind, hs.error = "eof", str(exc)
    except ssl.SSLError as exc:
        reason = (exc.reason or "").upper()
        hs.error = str(exc)
        if "WRONG_VERSION_NUMBER" in reason or "RECORD_LAYER" in reason or "PACKET_LENGTH_TOO_LONG" in reason or "HTTP_REQUEST" in reason:
            hs.kind = "not_tls"
        elif "ALERT" in reason or "UNSUPPORTED_PROTOCOL" in reason or "NO_PROTOCOLS" in reason:
            hs.kind = "alert"
        else:
            hs.kind = "other"
    except ConnectionResetError as exc:
        hs.kind, hs.error = "reset", str(exc)
    except TimeoutError:
        hs.kind, hs.error = "timeout", f"no ServerHello/Finished within {HANDSHAKE_TIMEOUT:.0f}s"
    except OSError as exc:
        hs.kind, hs.error = "other", str(exc)
    finally:
        try:
            raw.close()
        except OSError:
            pass
    if hs.ms is None:
        hs.ms = (time.perf_counter() - started) * 1000.0
    return hs


# ----------------------------------------------------------------------- check


def run(ctx: RunContext) -> CheckResult:
    r = CheckResult(ID, LAYER, TITLE)
    t = ctx.target
    proxy_flag = ""
    if ctx.proxied and ctx.proxy and ctx.proxy.host_port:
        proxy_flag = f" -proxy {ctx.proxy.host_port[0]}:{ctx.proxy.host_port[1]}"
    r.commands = [f"openssl s_client -connect {t.endpoint} -servername {t.host} -showcerts -alpn h2,http/1.1{proxy_flag}",
                  f"curl.exe -v {t.url or 'https://' + t.endpoint + '/'} -o NUL" if IS_WINDOWS
                  else f"curl -v {t.url or 'https://' + t.endpoint + '/'} -o /dev/null"]
    if not t.uses_tls:
        return r.skip(f"{t.scheme}://…:{t.port} does not use TLS")
    if not ctx.ip and not ctx.proxied:
        return r.skip("No IP address to connect to (DNS failed)")
    tcp = ctx.result("tcp")
    if tcp and not ctx.proxied and tcp.data.get("direct", {}).get("state") not in ("open", "intermittent", None):
        return r.skip(f"TCP port {t.port} is not open, so there is nothing to handshake with")

    sys_hs = handshake(ctx, "system", "OS trust store")
    if sys_hs.kind == "proxy":
        resp = sys_hs.proxy_response or {}
        r.add("tls.proxy_refused_connect", Status.FAIL if resp.get("status") != 407 else Status.WARN,
              f"The proxy refused to open a tunnel: {resp.get('status')} {resp.get('reason')}. See the HTTP check.")
        if ctx.ip:
            r.evidence.append("Testing TLS directly instead, bypassing the proxy.")
            sys_hs = handshake(ctx, "system", "OS trust store (direct)", force_direct=True)
        if sys_hs.kind in ("proxy", "connect"):
            r.summary = r.findings[-1].message
            r.data["handshakes"] = [sys_hs.to_dict()]
            return r
    force_direct = "direct" in sys_hs.label
    shake = [sys_hs]
    detail_hs = sys_hs
    moz_hs = None
    if not sys_hs.ok:
        detail_hs = handshake(ctx, "raw", "no verification (diagnostic)", force_direct)
        shake.append(detail_hs)
    if sys_hs.ok or sys_hs.kind == "verify":
        moz_hs = handshake(ctx, "mozilla", "Mozilla public roots (certifi)", force_direct)
        shake.append(moz_hs)
    r.data["handshakes"] = [h.to_dict() for h in shake]

    ht = Table("Handshakes", ["Trust store", "Path", "Result", "Time"])
    for h in shake:
        if h.ok:
            res = f"OK {h.version}"
        elif h.kind == "verify":
            res = f"verify error {h.verify_code}: {h.verify_message}"
        else:
            res = f"{h.kind}: {(h.error or '')[:80]}"
        ht.rows.append([h.label, h.path, res, fmt_ms(h.ms)])
    r.tables.append(ht)

    if not detail_hs.ok:
        _handshake_failure(ctx, r, sys_hs, detail_hs)
        r.summary = r.findings[-1].message if r.findings else "TLS handshake failed"
        return r
    # The normal handshake failed for a protocol reason (alert, reset...), but the
    # permissive diagnostic one worked: report the protocol problem, then still
    # describe the certificate the server sent.
    protocol_problem = not sys_hs.ok and sys_hs.kind != "verify"
    if protocol_problem:
        _handshake_failure(ctx, r, sys_hs, detail_hs)

    # We have a completed handshake: describe it.
    r.data.update({"version": detail_hs.version, "cipher": detail_hs.cipher, "bits": detail_hs.bits,
                   "alpn": detail_hs.alpn, "sni": None if t.is_ip else t.host})
    r.evidence.append(f"Negotiated {detail_hs.version}, cipher {detail_hs.cipher} ({detail_hs.bits}-bit), "
                      f"ALPN {detail_hs.alpn or 'none'}, SNI {'(none, IP target)' if t.is_ip else t.host}, "
                      f"handshake {fmt_ms(detail_hs.ms)}.")
    served = [cert_info(d) for d in detail_hs.served]
    verified = [cert_info(d) for d in sys_hs.verified] if sys_hs.ok else []
    r.data["served_chain"] = served
    r.data["verified_chain"] = verified
    chain_view = verified or served
    served_fps = {c["sha256"] for c in served}
    ct = Table("Certificate chain" + (" (as verified, root from the local store)" if verified else " (as served)"),
               ["#", "Subject", "Issuer", "Expires", "Key", "Source"])
    for i, c in enumerate(chain_view):
        ct.rows.append([str(i), _short(c, "subject"), _short(c, "issuer"), c["not_after"][:10], c["key"],
                        "served" if c["sha256"] in served_fps else "local store"])
    r.tables.append(ct)
    if not served:
        r.add("tls.no_certificate", Status.FAIL, "The server completed the handshake without a certificate.")
        r.summary = r.findings[-1].message
        return r

    leaf = served[0]
    now = datetime.now(timezone.utc)
    sans = leaf["san_dns"] + leaf["san_ip"]
    r.evidence.append(f"Leaf: {leaf['subject_cn'] or leaf['subject']}; SANs: {', '.join(sans[:8]) or 'none'}"
                      + (" …" if len(sans) > 8 else "") + f"; valid {leaf['not_before'][:10]} to {leaf['not_after'][:10]}.")

    # Validity dates
    for i, c in enumerate(served):
        na, nb = datetime.fromisoformat(c["not_after"]), datetime.fromisoformat(c["not_before"])
        who = "The server certificate" if i == 0 else f"Chain certificate #{i} ({_short(c, 'subject')})"
        if na < now:
            r.add("tls.expired", Status.FAIL, f"{who} expired on {c['not_after'][:10]} ({(now - na).days} days ago).")
        elif nb > now:
            r.add("tls.not_yet_valid", Status.FAIL,
                  f"{who} is not valid until {c['not_before'][:10]}: the server deployed it early, or this device's "
                  "clock is wrong (check the time first).")
    days_left = (datetime.fromisoformat(leaf["not_after"]) - now).days
    if 0 <= days_left < 14 and not r.has("tls.expired"):
        r.add("tls.expiring_soon", Status.WARN, f"The certificate expires in {days_left} days ({leaf['not_after'][:10]}).")

    # Hostname
    if not hostname_matches(t.host, leaf):
        r.add("tls.hostname_mismatch", Status.FAIL,
              f"Hostname mismatch: the certificate is for {', '.join(sans[:5]) or leaf['subject_cn']}, not {t.host}. "
              "Wrong certificate on the server/virtual host, missing SAN, or traffic landing on a different server "
              "(captive portal, wrong DNS answer, intercepting device).")

    if not protocol_problem:
        _trust(ctx, r, sys_hs, moz_hs, served, verified)

    if detail_hs.version in ("TLSv1", "TLSv1.1", "SSLv3") and not r.has("tls.old_protocol"):
        r.add("tls.old_version", Status.WARN, f"{detail_hs.version} negotiated: deprecated (RFC 8996); modern clients refuse it.")
    if not any(f.status in (Status.FAIL, Status.WARN) for f in r.findings):
        r.add("tls.ok", Status.PASS,
              f"{detail_hs.version} handshake OK; certificate valid for {t.host}, trusted, expires in {days_left} days.")
    r.summary = next((f.message for f in r.findings if f.status in (Status.FAIL, Status.WARN)),
                     next((f.message for f in r.findings if f.code == "tls.ok"), ""))
    return r


def _site_is_public(ctx: RunContext) -> bool:
    if ctx.public_answers:
        return True
    return bool(ctx.ip) and classify_ip(ctx.ip) == "public"


def _trust(ctx: RunContext, r: CheckResult, sys_hs: Handshake, moz_hs: Handshake | None,
           served: list[dict], verified: list[dict]) -> None:
    moz_ok = bool(moz_hs and moz_hs.ok)
    vendor = detect_vendor(served + verified)
    root = verified[-1] if verified else served[-1]
    code = sys_hs.verify_code
    r.data["trust"] = {"os_store": sys_hs.ok, "mozilla": moz_ok, "vendor": vendor[0] if vendor else None,
                       "os_verify_code": code}

    if sys_hs.ok:
        if vendor:
            r.add("tls.intercepted", Status.WARN,
                  f"TLS is intercepted and re-signed by {vendor[0]} ({vendor[1]}). This device trusts that root, so "
                  "browsers work, but apps with certificate pinning or their own trust store (Java, Python, Git, "
                  "Docker, Node) fail until the root is added to them or the domain is exempted from SSL inspection.")
        elif not moz_ok and _site_is_public(ctx):
            r.add("tls.private_root_public_site", Status.WARN,
                  f"This name resolves publicly, but its chain ends at {_short(root, 'subject')}, a root that is "
                  "installed on this device and is not a public CA: a proxy or security product is re-signing TLS "
                  "(or the site uses a private PKI).")
        elif not moz_ok:
            r.add("tls.private_ca", Status.INFO,
                  f"The chain ends at a private/enterprise root installed on this device ({_short(root, 'subject')}). "
                  "Normal for internal sites.")
        return

    if code in UNTRUSTED_CODES and moz_ok:
        r.add("tls.os_store_missing_root", Status.WARN,
              f"The chain is publicly trusted (Mozilla roots) but this OS trust store lacks its root "
              f"({_short(root, 'issuer')}). Windows downloads public roots on demand, so browsers work while "
              "Python/Java apps fail; run Windows Update or install the root.")
        return
    if code in UNTRUSTED_CODES:
        leaf = served[0]
        if vendor:
            r.add("tls.intercepted_untrusted", Status.FAIL,
                  f"TLS is intercepted and re-signed by {vendor[0]} ({vendor[1]}), but this device does not trust that "
                  f"root CA: install the {vendor[0]} root certificate on the device (or fix its certificate deployment).")
        elif code in (20, 21, 2) and len(served) == 1 and not leaf["self_issued"] and leaf["ca_issuers"]:
            # Public CAs always put an AIA "CA Issuers" URL in the leaf; a private or
            # intercepting CA usually doesn't. With AIA, a lone leaf = missing intermediate.
            r.add("tls.incomplete_chain", Status.FAIL,
                  f"The server sent only its own certificate, not the intermediate that signed it ({_short(leaf, 'issuer')}). "
                  "Browsers may fetch the missing intermediate (AIA) and work; curl, Python, Java and most apps fail. "
                  "Fix on the server: serve the full chain.")
        elif code == 18 or (len(served) == 1 and leaf["self_issued"]):
            r.add("tls.self_signed", Status.FAIL,
                  "The server presents a self-signed certificate that no trust store contains.")
        else:
            hint = (" This name resolves publicly, so a device between you and the server (an intercepting proxy or "
                    "a man in the middle) is probably re-signing the traffic." if _site_is_public(ctx) else "")
            r.add("tls.untrusted", Status.FAIL,
                  f"Untrusted issuer: the chain ends at {_short(root, 'subject')}, which neither this device nor the "
                  f"public root list trusts ({VERIFY_TEXT.get(code, sys_hs.verify_message)}).{hint}")
        return
    if code in (9, 10, 62, 64):
        return  # already reported from the certificate dates / names
    if code in (66, 67, 68):
        r.add("tls.weak_crypto", Status.FAIL,
              f"Rejected for weak cryptography: {VERIFY_TEXT[code]} (e.g. a SHA-1 signed intermediate or a short "
              "RSA key). Current clients refuse it; the site must reissue the chain.")
        return
    r.add("tls.verify_failed", Status.FAIL, f"Certificate verification failed: {sys_hs.verify_message} (code {code}).")


def _handshake_failure(ctx: RunContext, r: CheckResult, sys_hs: Handshake, raw_hs: Handshake) -> None:
    kind = sys_hs.kind if sys_hs.kind != "verify" else raw_hs.kind
    hs = raw_hs if sys_hs.kind == "verify" else sys_hs
    err = (hs.error or "")[:160]
    if raw_hs.ok and raw_hs.version in ("TLSv1", "TLSv1.1", "SSLv3"):
        r.add("tls.old_protocol", Status.FAIL,
              f"The server only speaks {raw_hs.version}, which current clients refuse (RFC 8996): our normal "
              f"handshake failed ({err}), a permissive one negotiated {raw_hs.version}. Upgrade the server.")
    elif kind == "timeout":
        r.add("tls.handshake_timeout", Status.FAIL,
              f"TCP connected but the TLS handshake never completed ({err}). Typical of an MTU black hole (the large "
              "ServerHello/Certificate packets are dropped) or a middlebox silently discarding TLS.")
    elif kind == "reset":
        r.add("tls.reset", Status.FAIL,
              "The connection was reset right after our ClientHello: a firewall/IPS blocking by SNI, or the server "
              "does not speak TLS on this port.")
    elif kind == "eof":
        r.add("tls.eof", Status.FAIL,
              "The other side closed the connection during the handshake without a TLS alert: often a middlebox "
              f"or a server that rejects the SNI/cipher offer ({err}).")
    elif kind == "not_tls":
        r.add("tls.not_tls", Status.FAIL,
              f"Port {ctx.target.port} answered, but not with TLS (plain HTTP on a TLS port?): {err}")
    elif kind == "alert":
        r.add("tls.alert", Status.FAIL, f"The server aborted the handshake with a TLS alert: {err}")
    elif kind == "connect":
        r.add("tls.connect_failed", Status.FAIL, err)
    else:
        r.add("tls.handshake_failed", Status.FAIL, f"TLS handshake failed: {err}")
