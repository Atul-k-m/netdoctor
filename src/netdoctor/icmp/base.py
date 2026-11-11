"""The ICMP probe interface. One probe = one ICMP echo request with a chosen TTL,
payload size and DF bit, and whatever came back (echo reply, time exceeded,
fragmentation needed, unreachable, or nothing).

Ping, traceroute, MTR and the path-MTU sweep are all built from this one call."""

from __future__ import annotations

import enum
import threading
import time
from dataclasses import dataclass


class ProbeStatus(str, enum.Enum):
    REPLY = "reply"  # ICMP echo reply (type 0) from the destination
    TTL_EXCEEDED = "ttl_exceeded"  # ICMP time exceeded (type 11) from a router on the path
    FRAG_NEEDED = "frag_needed"  # ICMP type 3 code 4: too big and DF set (carries next-hop MTU)
    UNREACHABLE = "unreachable"  # other ICMP type 3: net/host/port unreachable, admin prohibited
    LOCAL_TOO_BIG = "local_too_big"  # our own stack refused: bigger than the interface MTU
    TIMEOUT = "timeout"  # nothing came back
    ERROR = "error"  # the probe could not be sent


@dataclass
class ProbeReply:
    status: ProbeStatus
    rtt_ms: float | None = None
    responder: str | None = None  # who answered (destination or router)
    ttl: int | None = None  # TTL of the reply packet, when known
    mtu: int | None = None  # next-hop MTU reported in frag-needed, when known
    code: int | None = None  # ICMP code or OS status code
    detail: str = ""

    @property
    def answered(self) -> bool:
        return self.status in (ProbeStatus.REPLY, ProbeStatus.TTL_EXCEEDED, ProbeStatus.FRAG_NEEDED, ProbeStatus.UNREACHABLE)

    def to_dict(self) -> dict:
        return {
            "status": self.status.value,
            "rtt_ms": None if self.rtt_ms is None else round(self.rtt_ms, 3),
            "responder": self.responder,
            "ttl": self.ttl,
            "mtu": self.mtu,
            "code": self.code,
            "detail": self.detail,
        }


class Prober:
    """Base class. Implementations must be safe to call from many threads at once."""

    name = "none"

    def probe(self, dst: str, *, ttl: int = 64, size: int = 56, df: bool = False, timeout: float = 1.0) -> ProbeReply:
        raise NotImplementedError


class NullProber(Prober):
    name = "unavailable"

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def probe(self, dst: str, *, ttl: int = 64, size: int = 56, df: bool = False, timeout: float = 1.0) -> ProbeReply:
        return ProbeReply(ProbeStatus.ERROR, detail=self.reason)


def paced_probes(
    prober: Prober,
    jobs: list[dict],
    interval: float,
    timeout: float,
) -> list[ProbeReply]:
    """Send probes like `ping` does: one every `interval` seconds, without waiting
    for the previous reply. Each job is a dict of probe() keyword args plus "dst".
    Returns replies in job order. Total time is about len(jobs)*interval + timeout."""
    results: list[ProbeReply | None] = [None] * len(jobs)
    threads: list[threading.Thread] = []
    start = time.perf_counter()

    def worker(i: int, job: dict) -> None:
        args = dict(job)
        dst = args.pop("dst")
        try:
            results[i] = prober.probe(dst, timeout=timeout, **args)
        except Exception as exc:  # noqa: BLE001 - one failed probe must not kill the run
            results[i] = ProbeReply(ProbeStatus.ERROR, detail=repr(exc))

    for i, job in enumerate(jobs):
        delay = start + i * interval - time.perf_counter()
        if delay > 0:
            time.sleep(delay)
        t = threading.Thread(target=worker, args=(i, job), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout + 5)
    return [r or ProbeReply(ProbeStatus.ERROR, detail="probe thread hung") for r in results]
