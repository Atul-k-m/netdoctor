"""Summarize a capture the way an engineer reads one in Wireshark: TCP handshakes and
their RTT, retransmissions, duplicate ACKs, zero windows, RSTs and who sent them;
TLS ClientHello/ServerHello and alerts; DNS errors and unanswered queries; ICMP
errors from routers.

Retransmission logic: per direction, every byte range already seen is recorded.
A segment whose range is entirely seen before is a retransmission; one that
lands below the highest byte seen but fills a gap is out-of-order. Keep-alives
(0-1 byte at next-expected-1) are ignored. This mirrors Wireshark's
tcp.analysis.retransmission / out_of_order / keep_alive / duplicate_ack /
zero_window flags closely enough for triage."""

from __future__ import annotations

import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from ..netutil import rtt_stats
from . import pcapfile
from .decode import TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, Decoded, decode

MASK = 0xFFFFFFFF
REASSEMBLY_LIMIT = 131072  # bytes kept per direction for TLS/HTTP parsing

TLS_VERSIONS = {0x0300: "SSLv3", 0x0301: "TLSv1.0", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2", 0x0304: "TLSv1.3"}
TLS_ALERTS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac", 21: "decryption_failed", 22: "record_overflow",
    40: "handshake_failure", 42: "bad_certificate", 43: "unsupported_certificate", 44: "certificate_revoked",
    45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter", 48: "unknown_ca",
    49: "access_denied", 50: "decode_error", 51: "decrypt_error", 70: "protocol_version", 71: "insufficient_security",
    80: "internal_error", 86: "inappropriate_fallback", 90: "user_canceled", 100: "no_renegotiation",
    109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name",
    113: "bad_certificate_status_response", 115: "unknown_psk_identity", 116: "certificate_required",
    120: "no_application_protocol",
}
CIPHERS = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256", 0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0xC02F: "ECDHE-RSA-AES128-GCM-SHA256", 0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305", 0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305",
    0x009C: "AES128-GCM-SHA256", 0x009D: "AES256-GCM-SHA384", 0x002F: "AES128-SHA", 0x0035: "AES256-SHA",
    0xC013: "ECDHE-RSA-AES128-SHA", 0xC014: "ECDHE-RSA-AES256-SHA", 0xC009: "ECDHE-ECDSA-AES128-SHA",
    0xC00A: "ECDHE-ECDSA-AES256-SHA",
}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}
HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


# ------------------------------------------------------------------ TCP state


class Intervals:
    """Merged half-open byte ranges [start, end)."""

    def __init__(self) -> None:
        self.ranges: list[list[int]] = []

    def covers(self, start: int, end: int) -> bool:
        return any(s <= start and end <= e for s, e in self.ranges)

    def overlaps(self, start: int, end: int) -> bool:
        return any(start < e and s < end for s, e in self.ranges)

    def add(self, start: int, end: int) -> None:
        merged = []
        for s, e in sorted(self.ranges + [[start, end]]):
            if merged and s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        self.ranges = merged


@dataclass
class Side:
    ip: str
    port: int
    base: int | None = None
    seen: Intervals = field(default_factory=Intervals)
    highest: int = 0
    chunks: dict[int, tuple[bytes, float]] = field(default_factory=dict)
    kept: int = 0
    data_bytes: int = 0
    data_segments: int = 0
    retrans: int = 0
    out_of_order: int = 0
    dup_acks: int = 0
    zero_window: int = 0
    last_ack: int | None = None
    last_win: int | None = None
    mss: int | None = None
    wscale: int | None = None
    fin: bool = False
    rst: list[float] = field(default_factory=list)
    max_segment: int = 0

    def rel(self, seq: int) -> int:
        return (seq - (self.base or 0)) & MASK


@dataclass
class Flow:
    client: Side
    server: Side
    first_ts: float
    last_ts: float
    packets: int = 0
    syn_count: int = 0
    synack_count: int = 0
    syn_ts: float | None = None
    synack_ts: float | None = None
    established_ts: float | None = None
    rst_to_syn: bool = False
    rst_after_established: list[str] = field(default_factory=list)  # who sent it
    retrans_events: list[float] = field(default_factory=list)
    app: dict = field(default_factory=dict)  # tls / http / proxy details after reassembly

    @property
    def name(self) -> str:
        return f"{self.client.ip}:{self.client.port} -> {self.server.ip}:{self.server.port}"

    @property
    def result(self) -> str:
        if self.established_ts is not None or (self.synack_count and self.client.data_bytes):
            return "established"
        if self.rst_to_syn:
            return "refused (RST)"
        if self.syn_count and not self.synack_count:
            return "no answer to SYN"
        if self.synack_count:
            return "SYN/ACK, no final ACK"
        return "mid-stream (no handshake seen)"


# --------------------------------------------------------------- the analyzer


class Analyzer:
    def __init__(self) -> None:
        self.flows: dict[tuple, Flow] = {}
        self.order: list[tuple] = []
        self.packets = 0
        self.decoded = 0
        self.bytes = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.linktypes: Counter = Counter()
        self.dns_queries: dict[tuple, dict] = {}
        self.dns_responses = 0
        self.dns_orphans = 0
        self.icmp_types: Counter = Counter()
        self.ttl_exceeded: Counter = Counter()
        self.frag_needed: list[dict] = []
        self.unreachable: list[dict] = []
        self.echo_requests: dict[tuple, float] = {}
        self.echo_replies = 0
        self.udp_packets = 0

    # -------------------------------------------------------------- feeding
    def feed(self, pkt: pcapfile.Packet) -> None:
        self.packets += 1
        self.bytes += pkt.orig_len
        self.linktypes[pkt.linktype] += 1
        if pkt.ts:
            self.first_ts = pkt.ts if self.first_ts is None else min(self.first_ts, pkt.ts)
            self.last_ts = pkt.ts if self.last_ts is None else max(self.last_ts, pkt.ts)
        d = decode(pkt)
        if d is None or d.fragment:
            return
        self.decoded += 1
        if d.tcp:
            self._tcp(d)
        elif d.udp:
            self.udp_packets += 1
            if 53 in (d.udp.sport, d.udp.dport):
                self._dns(d)
        elif d.icmp:
            self._icmp(d)

    def _tcp(self, d: Decoded) -> None:
        t = d.tcp
        assert t is not None
        a, b = (d.src, t.sport), (d.dst, t.dport)
        key = (a, b) if a < b else (b, a)
        flow = self.flows.get(key)
        if flow is None:
            if t.has(TCP_SYN) and not t.has(TCP_ACK):
                client = a
            elif t.has(TCP_SYN):
                client = b
            else:
                client = a if t.sport > t.dport else b
            server = b if client == a else a
            flow = Flow(Side(*client), Side(*server), d.ts, d.ts)
            self.flows[key] = flow
            self.order.append(key)
        flow.packets += 1
        flow.last_ts = d.ts
        from_client = (d.src, t.sport) == (flow.client.ip, flow.client.port)
        snd, rcv = (flow.client, flow.server) if from_client else (flow.server, flow.client)

        syn, ackf, fin, rst = t.has(TCP_SYN), t.has(TCP_ACK), t.has(TCP_FIN), t.has(TCP_RST)
        if syn and not ackf:
            flow.syn_count += 1
            flow.syn_ts = flow.syn_ts or d.ts
        if syn and ackf:
            flow.synack_count += 1
            flow.synack_ts = flow.synack_ts or d.ts
        if syn:
            snd.mss, snd.wscale = t.mss or snd.mss, t.wscale if t.wscale is not None else snd.wscale
        if snd.base is None:
            snd.base = t.seq if syn else (t.seq - 1) & MASK
        if (from_client and ackf and not syn and flow.synack_count and flow.established_ts is None
                and flow.server.base is not None and t.ack == (flow.server.base + 1) & MASK):
            flow.established_ts = d.ts
        if rst:
            snd.rst.append(d.ts)
            if not from_client and flow.synack_count == 0 and flow.syn_count:
                flow.rst_to_syn = True
            elif flow.established_ts is not None or flow.synack_count:
                flow.rst_after_established.append("client" if from_client else "server")
            return
        if fin:
            snd.fin = True

        payload = t.payload
        seglen = len(payload) + (1 if syn else 0) + (1 if fin else 0)
        rel = snd.rel(t.seq)
        if rel > 0x7FFFFFFF:  # sequence before our base (capture started mid-stream oddly)
            return
        if seglen:
            end = rel + seglen
            keepalive = len(payload) <= 1 and not syn and not fin and rel == snd.highest - 1
            if not keepalive:
                if snd.seen.covers(rel, end):
                    snd.retrans += 1
                    flow.retrans_events.append(d.ts)
                elif rel < snd.highest:
                    if snd.seen.overlaps(rel, end):
                        snd.retrans += 1
                        flow.retrans_events.append(d.ts)
                    else:
                        snd.out_of_order += 1
                else:
                    if payload:
                        snd.data_bytes += len(payload)
                        snd.data_segments += 1
                snd.seen.add(rel, end)
                snd.highest = max(snd.highest, end)
                if payload:
                    snd.max_segment = max(snd.max_segment, len(payload))
                    if rel not in snd.chunks and snd.kept < REASSEMBLY_LIMIT:
                        start = rel + (1 if syn else 0)
                        snd.chunks[start] = (payload, d.ts)
                        snd.kept += len(payload)
        elif ackf and not syn and rcv.base is not None:
            ack_rel = rcv.rel(t.ack)
            if snd.last_ack == t.ack and snd.last_win == t.window and ack_rel < rcv.highest:
                snd.dup_acks += 1
        if t.window == 0 and not (syn or fin or rst):
            snd.zero_window += 1
        if ackf:
            snd.last_ack, snd.last_win = t.ack, t.window

    def _dns(self, d: Decoded) -> None:
        u = d.udp
        assert u is not None
        msg = parse_dns(u.payload)
        if msg is None:
            return
        if not msg["qr"]:
            key = (d.src, u.sport, d.dst, msg["id"])
            self.dns_queries.setdefault(key, {"ts": d.ts, "name": msg["qname"], "type": msg["qtype"],
                                              "server": d.dst, "client": d.src, "response": None})
            return
        self.dns_responses += 1
        q = self.dns_queries.get((d.dst, u.dport, d.src, msg["id"]))
        if q is None:
            self.dns_orphans += 1
            return
        if q["response"] is None:
            q["response"] = {"ts": d.ts, "rcode": msg["rcode"], "answers": msg["answers"], "tc": msg["tc"],
                             "ms": (d.ts - q["ts"]) * 1000.0}

    def _icmp(self, d: Decoded) -> None:
        i = d.icmp
        assert i is not None
        self.icmp_types[(i.v6, i.type, i.code)] += 1
        echo_req, echo_rep = (128, 129) if i.v6 else (8, 0)
        if i.type == echo_req:
            self.echo_requests[(d.src, d.dst, *i.echo_id_seq)] = d.ts
        elif i.type == echo_rep:
            if (d.dst, d.src, *i.echo_id_seq) in self.echo_requests:
                self.echo_replies += 1
        elif (not i.v6 and i.type == 11) or (i.v6 and i.type == 3):
            self.ttl_exceeded[d.src] += 1
        elif (not i.v6 and i.type == 3 and i.code == 4) or (i.v6 and i.type == 2):
            self.frag_needed.append({"router": d.src, "mtu": i.next_hop_mtu, "for": i.orig_dst, "ts": d.ts})
        elif (not i.v6 and i.type == 3) or (i.v6 and i.type == 1):
            self.unreachable.append({"router": d.src, "code": i.code, "for": i.orig_dst, "proto": i.orig_proto,
                                     "port": i.orig_dport, "v6": i.v6, "ts": d.ts})

    # ------------------------------------------------------------- summary
    def summary(self, focus: list[tuple[str, int]] | None = None) -> dict:
        for flow in self.flows.values():
            flow.app = analyze_streams(flow)
        focus_set = {(ip, port) for ip, port in (focus or [])}
        flows = [self.flows[k] for k in self.order]
        primary = [f for f in flows if not focus_set or (f.server.ip, f.server.port) in focus_set]
        end = self.last_ts or 0
        dns_q = list(self.dns_queries.values())
        unreachable_codes = Counter(u["code"] for u in self.unreachable)
        return {
            "packets": self.packets,
            "decoded": self.decoded,
            "bytes": self.bytes,
            "first_ts": self.first_ts,
            "last_ts": self.last_ts,
            "duration_s": round((self.last_ts - self.first_ts), 3) if self.first_ts and self.last_ts else 0.0,
            "linktypes": dict(self.linktypes),
            "focus": [f"{ip}:{port}" for ip, port in sorted(focus_set)],
            "tcp": {
                "flows": len(flows),
                "focus_flows": len(primary),
                "all": _tcp_totals(flows),
                "focus_totals": _tcp_totals(primary),
                "flows_detail": [flow_dict(f) for f in primary[:40]],
            },
            "tls": _tls_totals(primary),
            "http": [dict(flow=f.name, **f.app["http"]) for f in primary if f.app.get("http")],
            "dns": {
                "queries": len(dns_q),
                "responses": self.dns_responses,
                "errors": [{"name": q["name"], "type": DNS_TYPES.get(q["type"], q["type"]), "server": q["server"],
                            "rcode": DNS_RCODES.get(q["response"]["rcode"], q["response"]["rcode"])}
                           for q in dns_q if q["response"] and q["response"]["rcode"] != 0],
                "unanswered": [{"name": q["name"], "type": DNS_TYPES.get(q["type"], q["type"]), "server": q["server"]}
                               for q in dns_q if q["response"] is None and end - q["ts"] > 2.0],
                "rtt_ms": rtt_stats([q["response"]["ms"] for q in dns_q if q["response"]]),
                "truncated": sum(1 for q in dns_q if q["response"] and q["response"]["tc"]),
            },
            "icmp": {
                "types": {_icmp_name(*k): v for k, v in self.icmp_types.items()},
                "echo_requests": len(self.echo_requests),
                "echo_replies": self.echo_replies,
                "ttl_exceeded_from": dict(self.ttl_exceeded.most_common(30)),
                "frag_needed": _dedupe(self.frag_needed, ("router", "mtu", "for")),
                "unreachable": _dedupe(self.unreachable, ("router", "code", "for", "port")),
                "unreachable_codes": {str(k): v for k, v in unreachable_codes.items()},
            },
        }


def _dedupe(items: list[dict], keys: tuple[str, ...]) -> list[dict]:
    seen: dict[tuple, dict] = {}
    for it in items:
        k = tuple(it.get(x) for x in keys)
        if k in seen:
            seen[k]["count"] += 1
        else:
            seen[k] = {**{x: it.get(x) for x in keys}, "count": 1}
    return list(seen.values())


def _icmp_name(v6: bool, type_: int, code: int) -> str:
    v4 = {(0, 0): "echo reply", (8, 0): "echo request", (11, 0): "time exceeded (TTL)", (3, 0): "net unreachable",
          (3, 1): "host unreachable", (3, 3): "port unreachable", (3, 4): "fragmentation needed",
          (3, 9): "net prohibited", (3, 10): "host prohibited", (3, 13): "admin prohibited"}
    v6n = {(128, 0): "echo request", (129, 0): "echo reply", (3, 0): "hop limit exceeded", (2, 0): "packet too big",
           (1, 4): "port unreachable", (1, 1): "admin prohibited", (1, 3): "address unreachable"}
    name = (v6n if v6 else v4).get((type_, code))
    return ("icmpv6 " if v6 else "") + (name or f"type {type_} code {code}")


def _tcp_totals(flows: list[Flow]) -> dict:
    rtts = [(f.synack_ts - f.syn_ts) * 1000.0 for f in flows if f.syn_ts and f.synack_ts and f.synack_ts >= f.syn_ts]
    return {
        "handshakes_completed": sum(1 for f in flows if f.result == "established" and f.syn_count),
        "refused": sum(1 for f in flows if f.rst_to_syn),
        "unanswered_syn": sum(1 for f in flows if f.syn_count and not f.synack_count and not f.rst_to_syn),
        "syn_retransmissions": sum(max(0, f.syn_count - 1) for f in flows),
        "handshake_rtt_ms": rtt_stats(rtts),
        "retransmissions": sum(f.client.retrans + f.server.retrans for f in flows),
        "out_of_order": sum(f.client.out_of_order + f.server.out_of_order for f in flows),
        "dup_acks": sum(f.client.dup_acks + f.server.dup_acks for f in flows),
        "zero_windows": sum(f.client.zero_window + f.server.zero_window for f in flows),
        "data_segments": sum(f.client.data_segments + f.server.data_segments for f in flows),
        "rsts": sum(len(f.client.rst) + len(f.server.rst) for f in flows),
        "rst_after_handshake_by_server": sum(f.rst_after_established.count("server") for f in flows),
        "rst_after_handshake_by_client": sum(f.rst_after_established.count("client") for f in flows),
    }


def flow_dict(f: Flow) -> dict:
    return {
        "flow": f.name,
        "result": f.result,
        "syn": f.syn_count,
        "synack": f.synack_count,
        "handshake_ms": round((f.synack_ts - f.syn_ts) * 1000.0, 2) if f.syn_ts and f.synack_ts else None,
        "mss_client": f.client.mss,
        "mss_server": f.server.mss,
        "wscale_client": f.client.wscale,
        "wscale_server": f.server.wscale,
        "bytes_c2s": f.client.data_bytes,
        "bytes_s2c": f.server.data_bytes,
        "max_segment_s2c": f.server.max_segment,
        "retrans_c2s": f.client.retrans,
        "retrans_s2c": f.server.retrans,
        "out_of_order": f.client.out_of_order + f.server.out_of_order,
        "dup_acks": f.client.dup_acks + f.server.dup_acks,
        "zero_window_client": f.client.zero_window,
        "zero_window_server": f.server.zero_window,
        "rst_client": len(f.client.rst),
        "rst_server": len(f.server.rst),
        "fin_client": f.client.fin,
        "fin_server": f.server.fin,
        "duration_ms": round((f.last_ts - f.first_ts) * 1000.0, 1),
        "app": f.app,
    }


def _tls_totals(flows: list[Flow]) -> dict:
    handshakes, alerts, stalled = [], [], []
    for f in flows:
        tls = f.app.get("tls")
        if not tls:
            continue
        ch, sh = tls.get("client_hello"), tls.get("server_hello")
        handshakes.append({"flow": f.name, "client_hello": bool(ch), "server_hello": bool(sh),
                           "sni": (ch or {}).get("sni"), "client_alpn": (ch or {}).get("alpn"),
                           "version": (sh or {}).get("version"), "cipher": (sh or {}).get("cipher"),
                           "alpn": (sh or {}).get("alpn"), "certificates": tls.get("certificates"),
                           "alerts": tls.get("alerts", [])})
        for a in tls.get("alerts", []):
            alerts.append({"flow": f.name, **a})
        if ch and not sh and not tls.get("alerts"):
            stalled.append({"flow": f.name, "sni": ch.get("sni"), "server_rst": bool(f.server.rst),
                            "server_bytes": f.server.data_bytes})
    return {
        "client_hellos": sum(1 for h in handshakes if h["client_hello"]),
        "server_hellos": sum(1 for h in handshakes if h["server_hello"]),
        "handshakes": handshakes[:40],
        "alerts": alerts,
        "stalled": stalled,
    }


# ----------------------------------------------------------- reassembly & L7


def assemble(side: Side) -> tuple[bytes, list[tuple[int, float]]]:
    """Contiguous bytes from the start of the stream, plus (offset, timestamp) marks."""
    out = bytearray()
    marks: list[tuple[int, float]] = []
    pos = 1
    for rel in sorted(side.chunks):
        chunk, ts = side.chunks[rel]
        if rel > pos:
            break
        if rel + len(chunk) <= pos:
            continue
        marks.append((len(out), ts))
        out += chunk[pos - rel :]
        pos = rel + len(chunk)
    return bytes(out), marks


def _ts_at(marks: list[tuple[int, float]], offset: int) -> float | None:
    ts = None
    for off, t in marks:
        if off <= offset:
            ts = t
        else:
            break
    return ts


def analyze_streams(flow: Flow) -> dict:
    c_stream, c_marks = assemble(flow.client)
    s_stream, s_marks = assemble(flow.server)
    app: dict = {}
    # An explicit proxy: CONNECT request and the proxy's answer come first.
    if c_stream.startswith(b"CONNECT "):
        head, _, rest = c_stream.partition(b"\r\n\r\n")
        app["proxy_connect"] = head.split(b"\r\n")[0].decode("latin-1")[:200]
        c_stream = rest
        if s_stream.startswith(b"HTTP/"):
            shead, _, srest = s_stream.partition(b"\r\n\r\n")
            status = shead.split(b"\r\n")[0].decode("latin-1")
            app["proxy_status"] = status[:200]
            app["proxy_headers"] = [h.decode("latin-1")[:200] for h in shead.split(b"\r\n")[1:]
                                    if h.lower().startswith((b"proxy-authenticate", b"via", b"server", b"x-squid-error"))]
            s_stream = srest
    elif c_stream.startswith(HTTP_METHODS):
        req = c_stream.split(b"\r\n", 1)[0].decode("latin-1")
        host = next((h.split(b":", 1)[1].strip().decode("latin-1") for h in c_stream.split(b"\r\n\r\n")[0].split(b"\r\n")
                     if h.lower().startswith(b"host:")), None)
        http: dict = {"request": req[:200], "host": host}
        if s_stream.startswith(b"HTTP/"):
            line = s_stream.split(b"\r\n", 1)[0].decode("latin-1")
            http["status_line"] = line[:200]
            parts = line.split(" ")
            http["status"] = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
            heads = s_stream.split(b"\r\n\r\n")[0].split(b"\r\n")[1:]
            http["location"] = next((h.split(b":", 1)[1].strip().decode("latin-1") for h in heads
                                     if h.lower().startswith(b"location:")), None)
        app["http"] = http
        return app
    if c_stream[:1] == b"\x16" and c_stream[1:2] == b"\x03":
        app["tls"] = parse_tls_flow(c_stream, c_marks, s_stream, s_marks)
    return app


def parse_tls_flow(c_stream: bytes, c_marks, s_stream: bytes, s_marks) -> dict:
    info: dict = {"alerts": []}
    for who, stream, marks in (("client", c_stream, c_marks), ("server", s_stream, s_marks)):
        encrypted = False
        hs_buf = b""
        off = 0
        while off + 5 <= len(stream):
            ctype, ver, length = stream[off], struct.unpack("!H", stream[off + 1 : off + 3])[0], struct.unpack(
                "!H", stream[off + 3 : off + 5])[0]
            if ctype not in (20, 21, 22, 23) or ver >> 8 != 3:
                break
            body = stream[off + 5 : off + 5 + length]
            if len(body) < length:
                info.setdefault("incomplete", []).append(who)
                break
            if ctype == 20:
                encrypted = True
            elif ctype == 21:
                if not encrypted and length == 2:
                    info["alerts"].append({"from": who, "level": "fatal" if body[0] == 2 else "warning",
                                           "description": TLS_ALERTS.get(body[1], str(body[1])), "encrypted": False,
                                           "ts": _ts_at(marks, off)})
                else:
                    info["alerts"].append({"from": who, "level": "?", "description": "encrypted alert",
                                           "encrypted": True, "ts": _ts_at(marks, off)})
            elif ctype == 22 and not encrypted:
                hs_buf += body
                hs_buf = _handshake_messages(hs_buf, who, info)
                if info.get("server_hello", {}).get("version") == "TLSv1.3" and who == "server":
                    encrypted = True  # everything after ServerHello is encrypted in TLS 1.3
            elif ctype == 23:
                info[f"app_records_{who}"] = info.get(f"app_records_{who}", 0) + 1
            off += 5 + length
    return info


def _handshake_messages(buf: bytes, who: str, info: dict) -> bytes:
    while len(buf) >= 4:
        mtype = buf[0]
        mlen = int.from_bytes(buf[1:4], "big")
        if len(buf) < 4 + mlen:
            return buf
        body = buf[4 : 4 + mlen]
        try:
            if mtype == 1 and who == "client":
                info["client_hello"] = _client_hello(body)
            elif mtype == 2 and who == "server":
                info["server_hello"] = _server_hello(body)
            elif mtype == 11 and who == "server":
                total = int.from_bytes(body[0:3], "big")
                count, pos = 0, 3
                while pos + 3 <= 3 + total and pos + 3 <= len(body):
                    clen = int.from_bytes(body[pos : pos + 3], "big")
                    pos += 3 + clen
                    count += 1
                info["certificates"] = count
        except (IndexError, struct.error):
            info.setdefault("parse_errors", 0)
            info["parse_errors"] += 1
        buf = buf[4 + mlen :]
    return buf


def _extensions(data: bytes) -> dict[int, bytes]:
    out, pos = {}, 0
    while pos + 4 <= len(data):
        etype, elen = struct.unpack("!HH", data[pos : pos + 4])
        out[etype] = data[pos + 4 : pos + 4 + elen]
        pos += 4 + elen
    return out


def _client_hello(b: bytes) -> dict:
    pos = 2 + 32
    sid = b[pos]
    pos += 1 + sid
    cs_len = struct.unpack("!H", b[pos : pos + 2])[0]
    ciphers = len(b[pos + 2 : pos + 2 + cs_len]) // 2
    pos += 2 + cs_len
    pos += 1 + b[pos]
    ext = _extensions(b[pos + 2 : pos + 2 + struct.unpack("!H", b[pos : pos + 2])[0]]) if pos + 2 <= len(b) else {}
    out: dict = {"legacy_version": TLS_VERSIONS.get(struct.unpack("!H", b[:2])[0]), "ciphers_offered": ciphers,
                 "sni": None, "alpn": [], "versions": []}
    if 0 in ext and len(ext[0]) >= 5:
        name_len = struct.unpack("!H", ext[0][3:5])[0]
        out["sni"] = ext[0][5 : 5 + name_len].decode("ascii", errors="replace")
    if 16 in ext:
        a, p = ext[16][2:], 0
        while p < len(a):
            n = a[p]
            out["alpn"].append(a[p + 1 : p + 1 + n].decode("ascii", errors="replace"))
            p += 1 + n
    if 43 in ext and ext[43]:
        vs = ext[43][1:]
        out["versions"] = [TLS_VERSIONS.get(struct.unpack("!H", vs[i : i + 2])[0], hex(struct.unpack("!H", vs[i : i + 2])[0]))
                           for i in range(0, len(vs) - 1, 2) if struct.unpack("!H", vs[i : i + 2])[0] in TLS_VERSIONS]
    return out


def _server_hello(b: bytes) -> dict:
    legacy = struct.unpack("!H", b[:2])[0]
    pos = 2 + 32
    pos += 1 + b[pos]
    cipher = struct.unpack("!H", b[pos : pos + 2])[0]
    pos += 3
    ext = _extensions(b[pos + 2 : pos + 2 + struct.unpack("!H", b[pos : pos + 2])[0]]) if pos + 2 <= len(b) else {}
    version = legacy
    if 43 in ext and len(ext[43]) == 2:
        version = struct.unpack("!H", ext[43])[0]
    alpn = None
    if 16 in ext and len(ext[16]) > 3:
        alpn = ext[16][3 : 3 + ext[16][2]].decode("ascii", errors="replace")
    return {"version": TLS_VERSIONS.get(version, hex(version)), "cipher": CIPHERS.get(cipher, f"0x{cipher:04X}"),
            "alpn": alpn}


# ------------------------------------------------------------------------ DNS


def _dns_name(msg: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    labels = []
    while pos < len(msg):
        n = msg[pos]
        if n == 0:
            return ".".join(labels), pos + 1
        if n & 0xC0 == 0xC0:
            if depth > 10 or pos + 1 >= len(msg):
                break
            ptr = ((n & 0x3F) << 8) | msg[pos + 1]
            name, _ = _dns_name(msg, ptr, depth + 1)
            return ".".join(labels + ([name] if name else [])), pos + 2
        labels.append(msg[pos + 1 : pos + 1 + n].decode("ascii", errors="replace"))
        pos += 1 + n
    return ".".join(labels), pos


def parse_dns(payload: bytes) -> dict | None:
    if len(payload) < 12:
        return None
    ident, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", payload[:12])
    if qd == 0:
        return None
    try:
        qname, pos = _dns_name(payload, 12)
        qtype = struct.unpack("!H", payload[pos : pos + 2])[0]
        pos += 4
        answers = []
        for _ in range(min(an, 32)):
            _name, pos = _dns_name(payload, pos)
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", payload[pos : pos + 10])
            rdata = payload[pos + 10 : pos + 10 + rdlen]
            pos += 10 + rdlen
            if rtype == 1 and rdlen == 4:
                answers.append(".".join(str(x) for x in rdata))
            elif rtype == 5:
                answers.append("CNAME " + _dns_name(payload, pos - rdlen)[0])
    except (struct.error, IndexError):
        return None
    return {"id": ident, "qr": bool(flags & 0x8000), "tc": bool(flags & 0x0200), "rcode": flags & 0x000F,
            "qname": qname, "qtype": qtype, "answers": answers}


# ------------------------------------------------------------------- entry


def summarize_file(path: str | Path, focus: list[tuple[str, int]] | None = None) -> dict:
    stats = pcapfile.ReadStats()
    an = Analyzer()
    for pkt in pcapfile.read_packets(path, stats):
        an.feed(pkt)
    out = an.summary(focus)
    out["file"] = str(path)
    out["format"] = stats.format
    out["truncated"] = stats.truncated
    return out


def group_by(items: list[dict], key: str) -> dict:
    out: dict = defaultdict(list)
    for it in items:
        out[it[key]].append(it)
    return dict(out)
