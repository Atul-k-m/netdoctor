"""Linux ICMP prober using unprivileged ICMP datagram sockets.

socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) is allowed for any user whose group is
inside net.ipv4.ping_group_range (systemd and Docker both open it up by default).
The kernel fills in the echo identifier and routes replies back to our socket.

For traceroute and path-MTU work we also need the ICMP *errors* that routers send
back (time exceeded, fragmentation needed). With IP_RECVERR enabled the kernel
queues them on the socket's error queue: recvmsg(MSG_ERRQUEUE) returns the
packet we sent plus a `struct sock_extended_err` that says what happened, who
sent it (the offender address) and, for frag-needed, the next-hop MTU."""

from __future__ import annotations

import errno
import os
import random
import select
import socket
import struct
import time

from .base import Prober, ProbeReply, ProbeStatus

SOL_IP = 0
IP_TTL = 2
IP_MTU_DISCOVER = 10
IP_RECVERR = 11
IP_RECVTTL = 12
IP_PMTUDISC_DONT = 0
IP_PMTUDISC_PROBE = 3  # set DF but ignore the cached path MTU, so we really probe
MSG_ERRQUEUE = getattr(socket, "MSG_ERRQUEUE", 0x2000)

SO_EE_ORIGIN_LOCAL = 1
SO_EE_ORIGIN_ICMP = 2
# ee_errno values come from the Linux kernel, so compare with Linux numbers even
# when this module is imported elsewhere (unit tests on Windows).
LINUX_EMSGSIZE = 90

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
ICMP_DEST_UNREACH = 3
ICMP_TIME_EXCEEDED = 11
ICMP_FRAG_NEEDED = 4

UNREACH_TEXT = {
    0: "net unreachable",
    1: "host unreachable",
    2: "protocol unreachable",
    3: "port unreachable",
    4: "fragmentation needed and DF set",
    5: "source route failed",
    6: "destination network unknown",
    7: "destination host unknown",
    9: "network administratively prohibited",
    10: "host administratively prohibited",
    13: "communication administratively prohibited",
}

_EE = struct.Struct("=IBBBBII")  # struct sock_extended_err
_PATTERN = b"NETDOCTOR-PROBE-"


def socket_available() -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    except OSError:
        return False
    s.close()
    return True


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


def build_echo(seq: int, size: int, ident: int = 0) -> bytes:
    payload = (_PATTERN * (size // len(_PATTERN) + 1))[:size]
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq)
    csum = checksum(header + payload)
    return struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, csum, ident, seq) + payload


def parse_extended_err(data: bytes) -> dict:
    """Decode the IP_RECVERR control message: sock_extended_err + offender sockaddr_in."""
    ee_errno, origin, icmp_type, icmp_code, _pad, info, ee_data = _EE.unpack_from(data, 0)
    offender = None
    if len(data) >= _EE.size + 8:
        family = struct.unpack_from("=H", data, _EE.size)[0]
        if family == socket.AF_INET:
            offender = socket.inet_ntoa(data[_EE.size + 4 : _EE.size + 8])
    return {
        "errno": ee_errno,
        "origin": origin,
        "type": icmp_type,
        "code": icmp_code,
        "info": info,
        "data": ee_data,
        "offender": offender,
    }


def reply_from_error(ee: dict, rtt_ms: float) -> ProbeReply:
    """Map a sock_extended_err to a ProbeReply."""
    offender = ee.get("offender")
    if ee["origin"] == SO_EE_ORIGIN_ICMP:
        if ee["type"] == ICMP_TIME_EXCEEDED:
            return ProbeReply(ProbeStatus.TTL_EXCEEDED, rtt_ms, offender, code=ee["code"])
        if ee["type"] == ICMP_DEST_UNREACH and ee["code"] == ICMP_FRAG_NEEDED:
            return ProbeReply(ProbeStatus.FRAG_NEEDED, rtt_ms, offender, mtu=ee["info"] or None, code=4,
                              detail=UNREACH_TEXT[4])
        if ee["type"] == ICMP_DEST_UNREACH:
            return ProbeReply(ProbeStatus.UNREACHABLE, rtt_ms, offender, code=ee["code"],
                              detail=UNREACH_TEXT.get(ee["code"], f"code {ee['code']}"))
        return ProbeReply(ProbeStatus.ERROR, rtt_ms, offender, code=ee["code"], detail=f"ICMP type {ee['type']}")
    if ee["origin"] == SO_EE_ORIGIN_LOCAL and ee["errno"] == LINUX_EMSGSIZE:
        return ProbeReply(ProbeStatus.LOCAL_TOO_BIG, mtu=ee["info"] or None, detail="larger than the local path MTU")
    return ProbeReply(ProbeStatus.ERROR, rtt_ms, offender, detail=os.strerror(ee["errno"]) if ee["errno"] else "error")


class LinuxSocketProber(Prober):
    name = "linux ICMP datagram socket (IP_RECVERR)"

    def probe(self, dst: str, *, ttl: int = 64, size: int = 56, df: bool = False, timeout: float = 1.0) -> ProbeReply:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        except OSError as exc:
            return ProbeReply(ProbeStatus.ERROR, detail=f"cannot open ICMP socket: {exc}")
        try:
            sock.setsockopt(SOL_IP, IP_TTL, ttl)
            sock.setsockopt(SOL_IP, IP_MTU_DISCOVER, IP_PMTUDISC_PROBE if df else IP_PMTUDISC_DONT)
            sock.setsockopt(SOL_IP, IP_RECVERR, 1)
            sock.setsockopt(SOL_IP, IP_RECVTTL, 1)
            seq = random.randint(1, 0xFFFF)
            packet = build_echo(seq, size)
            started = time.perf_counter()
            try:
                sock.sendto(packet, (dst, 0))
            except OSError as exc:
                if exc.errno == errno.EMSGSIZE:
                    return ProbeReply(ProbeStatus.LOCAL_TOO_BIG, detail="larger than the local interface MTU")
                if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
                    return ProbeReply(ProbeStatus.UNREACHABLE, detail=f"local: {exc.strerror}")
                return ProbeReply(ProbeStatus.ERROR, detail=str(exc))

            poller = select.poll()
            poller.register(sock, select.POLLIN | select.POLLERR)
            deadline = started + timeout
            while True:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    return ProbeReply(ProbeStatus.TIMEOUT)
                events = poller.poll(max(1, int(remaining * 1000)))
                for _fd, event in events:
                    if event & select.POLLERR:
                        reply = self._read_error(sock, started)
                        if reply is not None:
                            return reply
                    if event & select.POLLIN:
                        reply = self._read_reply(sock, seq, started)
                        if reply is not None:
                            return reply
        finally:
            sock.close()

    @staticmethod
    def _read_error(sock: socket.socket, started: float) -> ProbeReply | None:
        try:
            _data, ancdata, _flags, _addr = sock.recvmsg(65535, 1024, MSG_ERRQUEUE | socket.MSG_DONTWAIT)
        except (BlockingIOError, InterruptedError):
            return None
        rtt = (time.perf_counter() - started) * 1000.0
        for level, ctype, cdata in ancdata:
            if level == SOL_IP and ctype == IP_RECVERR:
                return reply_from_error(parse_extended_err(cdata), rtt)
        return None

    @staticmethod
    def _read_reply(sock: socket.socket, seq: int, started: float) -> ProbeReply | None:
        try:
            data, ancdata, _flags, addr = sock.recvmsg(65535, 256, socket.MSG_DONTWAIT)
        except (BlockingIOError, InterruptedError):
            return None
        rtt = (time.perf_counter() - started) * 1000.0
        if len(data) < 8 or data[0] != ICMP_ECHO_REPLY:
            return None
        if struct.unpack_from("!H", data, 6)[0] != seq:
            return None
        reply_ttl = None
        for level, ctype, cdata in ancdata:
            if level == SOL_IP and ctype == IP_TTL and len(cdata) >= 4:
                reply_ttl = struct.unpack("=i", cdata[:4])[0]
        return ProbeReply(ProbeStatus.REPLY, rtt, addr[0], ttl=reply_ttl)
