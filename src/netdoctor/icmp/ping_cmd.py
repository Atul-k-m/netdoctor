"""Fallback prober that runs the iputils `ping` binary once per probe and parses it.

Used on Linux when ICMP datagram sockets are not allowed (ping_group_range
closed) but a setuid/cap_net_raw `ping` is installed."""

from __future__ import annotations

import math
import re
import time

from ..netutil import run_command
from .base import Prober, ProbeReply, ProbeStatus

RE_REPLY = re.compile(r"bytes from ([\d.]+):.*?ttl=(\d+).*?time[=<]([\d.]+)\s*ms", re.I)
RE_TTL = re.compile(r"From ([\d.]+)\S*.*?(Time to live exceeded|Time exceeded)", re.I)
RE_FRAG = re.compile(r"From ([\d.]+)\S*.*?Frag(?:mentation)? needed.*?mtu\s*=\s*(\d+)", re.I)
RE_LOCAL = re.compile(r"local error:.*?(?:message too long|too long).*?mtu\s*=\s*(\d+)", re.I)
RE_UNREACH = re.compile(
    r"From ([\d.]+)\S*.*?(Destination \w+ Unreachable|Packet filtered|Communication prohibited\S*|\w+ Prohibited)",
    re.I,
)


def parse_iputils(output: str, elapsed_ms: float | None = None) -> ProbeReply:
    m = RE_REPLY.search(output)
    if m:
        return ProbeReply(ProbeStatus.REPLY, float(m.group(3)), m.group(1), ttl=int(m.group(2)))
    m = RE_FRAG.search(output)
    if m:
        return ProbeReply(ProbeStatus.FRAG_NEEDED, elapsed_ms, m.group(1), mtu=int(m.group(2)))
    m = RE_LOCAL.search(output)
    if m:
        return ProbeReply(ProbeStatus.LOCAL_TOO_BIG, mtu=int(m.group(1)), detail="larger than the local path MTU")
    m = RE_TTL.search(output)
    if m:
        return ProbeReply(ProbeStatus.TTL_EXCEEDED, elapsed_ms, m.group(1))
    m = RE_UNREACH.search(output)
    if m:
        return ProbeReply(ProbeStatus.UNREACHABLE, elapsed_ms, m.group(1), detail=m.group(2))
    return ProbeReply(ProbeStatus.TIMEOUT)


class PingCommandProber(Prober):
    name = "iputils ping (subprocess)"

    def probe(self, dst: str, *, ttl: int = 64, size: int = 56, df: bool = False, timeout: float = 1.0) -> ProbeReply:
        wait = str(max(1, math.ceil(timeout)))
        cmd = ["ping", "-n", "-c", "1", "-W", wait, "-t", str(ttl), "-s", str(size), "-M", "do" if df else "dont", dst]
        started = time.perf_counter()
        rc, out = run_command(cmd, timeout=timeout + 3)
        elapsed = (time.perf_counter() - started) * 1000.0
        if rc in (126, 127):
            return ProbeReply(ProbeStatus.ERROR, detail="ping binary not usable")
        if "invalid option" in out.lower() or "unrecognized option" in out.lower():
            return ProbeReply(ProbeStatus.ERROR, detail="this ping does not support -M/-t (busybox?)")
        return parse_iputils(out, elapsed)
