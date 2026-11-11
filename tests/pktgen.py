"""Build real, checksummed Ethernet/IPv4/TCP/UDP/ICMP frames for capture tests.

The frames are valid enough for Wireshark to dissect, so the same files can be
cross-checked with tshark."""

from __future__ import annotations

import socket
import struct

from netdoctor.capture import pcapfile
from netdoctor.capture.pcapfile import Packet

CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def ipv4(src: str, dst: str, proto: int, payload: bytes, ttl: int = 64, df: bool = True, ident: int = 1) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, ident, 0x4000 if df else 0, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    hdr = hdr[:10] + struct.pack("!H", csum(hdr)) + hdr[12:]
    return hdr + payload


def ether(ip: bytes, src_mac: bytes = CLIENT_MAC, dst_mac: bytes = SERVER_MAC, vlan: int | None = None) -> bytes:
    if vlan is not None:
        return dst_mac + src_mac + struct.pack("!HHH", 0x8100, vlan, 0x0800) + ip
    frame = dst_mac + src_mac + b"\x08\x00" + ip
    return frame + b"\x00" * max(0, 60 - len(frame))  # Ethernet minimum frame padding


def tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: str, payload: bytes = b"",
        window: int = 64240, mss: int | None = None, wscale: int | None = None) -> bytes:
    bits = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10}
    fl = sum(bits[c] for c in flags)
    opts = b""
    if mss:
        opts += struct.pack("!BBH", 2, 4, mss)
    if wscale is not None:
        opts += struct.pack("!BBB", 1, 3, wscale)  # NOP + WS
    if len(opts) % 4:
        opts += b"\x01" * (4 - len(opts) % 4)
    off = (20 + len(opts)) // 4
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, off << 4, fl, window, 0, 0) + opts
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(hdr) + len(payload))
    c = csum(pseudo + hdr + payload)
    hdr = hdr[:16] + struct.pack("!H", c) + hdr[18:]
    return ipv4(src, dst, 6, hdr + payload)


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    hdr = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 17, 8 + len(payload))
    c = csum(pseudo + hdr + payload) or 0xFFFF
    return ipv4(src, dst, 17, hdr[:6] + struct.pack("!H", c) + payload)


def icmp(src: str, dst: str, type_: int, code: int, rest: bytes = b"\x00" * 4, body: bytes = b"", ttl: int = 64) -> bytes:
    msg = struct.pack("!BBH", type_, code, 0) + rest + body
    msg = msg[:2] + struct.pack("!H", csum(msg)) + msg[4:]
    return ipv4(src, dst, 1, msg, ttl=ttl, df=False)


def dns_query(qid: int, name: str, qtype: int = 1) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


def dns_response(qid: int, name: str, rcode: int = 0, answer_ip: str | None = None) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    an = 1 if answer_ip else 0
    msg = struct.pack("!HHHHHH", qid, 0x8180 | rcode, 1, an, 0, 0) + q + struct.pack("!HH", 1, 1)
    if answer_ip:
        msg += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton(answer_ip)
    return msg


def tls_record(ctype: int, body: bytes, version: int = 0x0303) -> bytes:
    return struct.pack("!BHH", ctype, version, len(body)) + body


def client_hello(sni: str, alpn: tuple[str, ...] = ("h2", "http/1.1")) -> bytes:
    name = sni.encode()
    sni_ext = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    alpn_list = b"".join(bytes([len(a)]) + a.encode() for a in alpn)
    alpn_ext = struct.pack("!H", len(alpn_list)) + alpn_list
    exts = struct.pack("!HH", 0, len(sni_ext)) + sni_ext + struct.pack("!HH", 16, len(alpn_ext)) + alpn_ext
    exts += struct.pack("!HHB", 43, 5, 4) + struct.pack("!HH", 0x0304, 0x0303)
    body = struct.pack("!H", 0x0303) + b"\x11" * 32 + b"\x00" + struct.pack("!H", 4) + struct.pack("!HH", 0x1301, 0xC02F)
    body += b"\x01\x00" + struct.pack("!H", len(exts)) + exts
    return tls_record(22, b"\x01" + len(body).to_bytes(3, "big") + body, version=0x0301)


def server_hello_12(cipher: int = 0xC02F, certs: int = 2) -> bytes:
    body = struct.pack("!H", 0x0303) + b"\x22" * 32 + b"\x00" + struct.pack("!H", cipher) + b"\x00"
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    cert_list = b"".join((300).to_bytes(3, "big") + b"\x30" * 300 for _ in range(certs))
    cert_body = len(cert_list).to_bytes(3, "big") + cert_list
    hs += b"\x0b" + len(cert_body).to_bytes(3, "big") + cert_body
    hs += b"\x0e\x00\x00\x00"  # ServerHelloDone
    return tls_record(22, hs)


def alert(level: int, desc: int) -> bytes:
    return tls_record(21, bytes([level, desc]))


class Conversation:
    """Builds a TCP conversation with correct sequence numbers."""

    def __init__(self, client: str, cport: int, server: str, sport: int, t0: float = 1_700_000_000.0):
        self.c, self.cp, self.s, self.sp = client, cport, server, sport
        self.cseq, self.sseq = 1000, 5000
        self.t = t0
        self.packets: list[Packet] = []

    def _emit(self, frame_ip: bytes, dt: float, from_client: bool) -> None:
        self.t += dt
        frame = ether(frame_ip, CLIENT_MAC if from_client else SERVER_MAC, SERVER_MAC if from_client else CLIENT_MAC)
        self.packets.append(Packet(self.t, pcapfile.LINKTYPE_ETHERNET, frame, len(frame)))

    def handshake(self, rtt: float = 0.02, mss=(1460, 1400)) -> Conversation:
        self._emit(tcp(self.c, self.s, self.cp, self.sp, self.cseq, 0, "S", mss=mss[0], wscale=8), 0.001, True)
        self._emit(tcp(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq + 1, "SA", mss=mss[1], wscale=7), rtt, False)
        self.cseq += 1
        self.sseq += 1
        self._emit(tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, "A"), 0.0005, True)
        return self

    def send(self, data: bytes, from_client: bool = True, dt: float = 0.001, window: int = 64240,
             advance: bool = True) -> Conversation:
        if from_client:
            self._emit(tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, "PA", data, window), dt, True)
            if advance:
                self.cseq += len(data)
        else:
            self._emit(tcp(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, "PA", data, window), dt, False)
            if advance:
                self.sseq += len(data)
        return self

    def ack(self, from_client: bool = True, dt: float = 0.001, window: int = 64240) -> Conversation:
        if from_client:
            self._emit(tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, "A", window=window), dt, True)
        else:
            self._emit(tcp(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, "A", window=window), dt, False)
        return self

    def fin(self) -> Conversation:
        self._emit(tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, "FA"), 0.001, True)
        self.cseq += 1
        self._emit(tcp(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, "FA"), 0.01, False)
        self.sseq += 1
        self._emit(tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, "A"), 0.001, True)
        return self

    def rst(self, from_client: bool = False) -> Conversation:
        if from_client:
            self._emit(tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, "RA"), 0.001, True)
        else:
            self._emit(tcp(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, "RA"), 0.001, False)
        return self

    def syn_only(self, tries: int = 3) -> Conversation:
        for i in range(tries):
            self._emit(tcp(self.c, self.s, self.cp, self.sp, self.cseq, 0, "S", mss=1460), 1.0 * (2**i), True)
        return self

    def syn_refused(self) -> Conversation:
        self._emit(tcp(self.c, self.s, self.cp, self.sp, self.cseq, 0, "S", mss=1460), 0.001, True)
        self._emit(tcp(self.s, self.c, self.sp, self.cp, 0, self.cseq + 1, "RA", window=0), 0.01, False)
        return self


def frame(ip: bytes, t: float, from_client: bool = True) -> Packet:
    f = ether(ip, CLIENT_MAC if from_client else SERVER_MAC, SERVER_MAC if from_client else CLIENT_MAC)
    return Packet(t, pcapfile.LINKTYPE_ETHERNET, f, len(f))
