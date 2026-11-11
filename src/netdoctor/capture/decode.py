"""Decode just enough of each packet: link layer -> IPv4/IPv6 -> TCP/UDP/ICMP."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

from . import pcapfile as pf

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10

ETH_IPV4, ETH_IPV6, ETH_VLAN, ETH_QINQ = 0x0800, 0x86DD, 0x8100, 0x88A8


@dataclass
class TCP:
    sport: int
    dport: int
    seq: int
    ack: int
    flags: int
    window: int
    payload: bytes
    mss: int | None = None
    wscale: int | None = None
    sack_perm: bool = False

    def has(self, flag: int) -> bool:
        return bool(self.flags & flag)

    @property
    def flag_text(self) -> str:
        names = [(TCP_SYN, "SYN"), (TCP_ACK, "ACK"), (TCP_FIN, "FIN"), (TCP_RST, "RST"), (TCP_PSH, "PSH")]
        return ",".join(n for f, n in names if self.flags & f) or "-"


@dataclass
class UDP:
    sport: int
    dport: int
    payload: bytes


@dataclass
class ICMP:
    type: int
    code: int
    rest: bytes  # bytes 4..8 of the ICMP header
    body: bytes
    v6: bool = False
    # For errors: the packet that triggered it (from the embedded IP header).
    orig_src: str | None = None
    orig_dst: str | None = None
    orig_proto: int | None = None
    orig_sport: int | None = None
    orig_dport: int | None = None

    @property
    def echo_id_seq(self) -> tuple[int, int]:
        return struct.unpack("!HH", self.rest)

    @property
    def next_hop_mtu(self) -> int | None:
        if not self.v6 and self.type == 3 and self.code == 4:
            return struct.unpack("!H", self.rest[2:4])[0] or None
        if self.v6 and self.type == 2:
            return struct.unpack("!I", self.rest)[0]
        return None


@dataclass
class Decoded:
    ts: float
    src: str
    dst: str
    proto: int  # 6 tcp, 17 udp, 1 icmp, 58 icmpv6
    ttl: int
    length: int  # IP total length
    df: bool = False
    fragment: bool = False  # a non-first fragment: no transport header
    tcp: TCP | None = None
    udp: UDP | None = None
    icmp: ICMP | None = None
    extra: dict = field(default_factory=dict)


def link_payload(linktype: int, data: bytes) -> tuple[int, bytes] | None:
    """Return (ethertype, network-layer bytes) or None for non-IP frames."""
    if linktype == pf.LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        etype = struct.unpack("!H", data[12:14])[0]
        off = 14
        while etype in (ETH_VLAN, ETH_QINQ) and len(data) >= off + 4:
            etype = struct.unpack("!H", data[off + 2 : off + 4])[0]
            off += 4
        return etype, data[off:]
    if linktype == pf.LINKTYPE_LINUX_SLL:
        if len(data) < 16:
            return None
        return struct.unpack("!H", data[14:16])[0], data[16:]
    if linktype == pf.LINKTYPE_LINUX_SLL2:
        if len(data) < 20:
            return None
        return struct.unpack("!H", data[0:2])[0], data[20:]
    if linktype in (pf.LINKTYPE_NULL, pf.LINKTYPE_LOOP):
        if len(data) < 4:
            return None
        fam = struct.unpack("<I" if linktype == pf.LINKTYPE_NULL else "!I", data[:4])[0]
        if fam == 2:
            return ETH_IPV4, data[4:]
        if fam in (10, 23, 24, 28, 30):  # AF_INET6 on Linux, Windows, and the BSDs
            return ETH_IPV6, data[4:]
        return None
    if linktype in (pf.LINKTYPE_RAW, pf.LINKTYPE_IPV4, pf.LINKTYPE_IPV6):
        if not data:
            return None
        return (ETH_IPV4 if data[0] >> 4 == 4 else ETH_IPV6), data
    return None


def decode(pkt: pf.Packet) -> Decoded | None:
    lp = link_payload(pkt.linktype, pkt.data)
    if lp is None:
        return None
    etype, ip = lp
    if etype == ETH_IPV4:
        return _ipv4(pkt.ts, ip)
    if etype == ETH_IPV6:
        return _ipv6(pkt.ts, ip)
    return None


def _ipv4(ts: float, ip: bytes) -> Decoded | None:
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total = struct.unpack("!H", ip[2:4])[0]
    flags_frag = struct.unpack("!H", ip[6:8])[0]
    ttl, proto = ip[8], ip[9]
    src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    # Trim Ethernet padding: the IP total length is the truth.
    end = min(len(ip), total) if total >= ihl else len(ip)
    d = Decoded(ts, src, dst, proto, ttl, total, df=bool(flags_frag & 0x4000))
    if flags_frag & 0x1FFF:
        d.fragment = True
        return d
    _transport(d, proto, ip[ihl:end], v6=False)
    return d


def _ipv6(ts: float, ip: bytes) -> Decoded | None:
    if len(ip) < 40 or ip[0] >> 4 != 6:
        return None
    plen = struct.unpack("!H", ip[4:6])[0]
    nxt, hlim = ip[6], ip[7]
    src = socket.inet_ntop(socket.AF_INET6, ip[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, ip[24:40])
    body = ip[40 : 40 + plen]
    d = Decoded(ts, src, dst, nxt, hlim, 40 + plen)
    for _ in range(8):  # walk extension headers
        if nxt in (0, 43, 60) and len(body) >= 8:
            nxt, body = body[0], body[(body[1] + 1) * 8 :]
        elif nxt == 44 and len(body) >= 8:  # fragment header
            if struct.unpack("!H", body[2:4])[0] & 0xFFF8:
                d.fragment = True
                return d
            nxt, body = body[0], body[8:]
        else:
            break
    d.proto = nxt
    _transport(d, nxt, body, v6=True)
    return d


def _transport(d: Decoded, proto: int, seg: bytes, v6: bool) -> None:
    if proto == 6 and len(seg) >= 20:
        sport, dport, seq, ack, off_flags, window = struct.unpack("!HHIIHH", seg[:16])
        hlen = (off_flags >> 12) * 4
        t = TCP(sport, dport, seq, ack, off_flags & 0xFF, window, seg[hlen:] if hlen >= 20 else b"")
        _tcp_options(t, seg[20:hlen])
        d.tcp = t
    elif proto == 17 and len(seg) >= 8:
        sport, dport, length = struct.unpack("!HHH", seg[:6])
        d.udp = UDP(sport, dport, seg[8:length] if length >= 8 else seg[8:])
    elif proto in (1, 58) and len(seg) >= 8:
        icmp = ICMP(seg[0], seg[1], seg[4:8], seg[8:], v6=proto == 58)
        is_error = (not icmp.v6 and icmp.type in (3, 4, 5, 11, 12)) or (icmp.v6 and icmp.type in (1, 2, 3, 4))
        if is_error:
            _embedded(icmp)
        d.icmp = icmp


def _tcp_options(t: TCP, opts: bytes) -> None:
    i = 0
    while i < len(opts):
        kind = opts[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(opts):
            break
        length = opts[i + 1]
        if length < 2:
            break
        val = opts[i + 2 : i + length]
        if kind == 2 and len(val) == 2:
            t.mss = struct.unpack("!H", val)[0]
        elif kind == 3 and len(val) == 1:
            t.wscale = val[0]
        elif kind == 4:
            t.sack_perm = True
        i += length


def _embedded(icmp: ICMP) -> None:
    b = icmp.body
    if not icmp.v6 and len(b) >= 20 and b[0] >> 4 == 4:
        ihl = (b[0] & 0x0F) * 4
        icmp.orig_proto = b[9]
        icmp.orig_src, icmp.orig_dst = socket.inet_ntoa(b[12:16]), socket.inet_ntoa(b[16:20])
        tp = b[ihl:]
    elif icmp.v6 and len(b) >= 40 and b[0] >> 4 == 6:
        icmp.orig_proto = b[6]
        icmp.orig_src = socket.inet_ntop(socket.AF_INET6, b[8:24])
        icmp.orig_dst = socket.inet_ntop(socket.AF_INET6, b[24:40])
        tp = b[40:]
    else:
        return
    if icmp.orig_proto in (6, 17) and len(tp) >= 4:
        icmp.orig_sport, icmp.orig_dport = struct.unpack("!HH", tp[:4])
