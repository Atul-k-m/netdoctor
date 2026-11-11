"""Pick the best ICMP prober for this OS."""

from __future__ import annotations

import shutil
import sys
import threading

from .base import NullProber, Prober, ProbeReply, ProbeStatus, paced_probes

__all__ = ["Prober", "ProbeReply", "ProbeStatus", "get_prober", "paced_probes"]

_lock = threading.Lock()
_cached: Prober | None = None


def get_prober() -> Prober:
    global _cached
    with _lock:
        if _cached is None:
            _cached = _select()
        return _cached


def _select() -> Prober:
    if sys.platform == "win32":
        from .windows import WindowsIcmpProber

        return WindowsIcmpProber()
    if sys.platform.startswith("linux"):
        from .linux import LinuxSocketProber, socket_available

        if socket_available():
            return LinuxSocketProber()
        if shutil.which("ping"):
            from .ping_cmd import PingCommandProber

            return PingCommandProber()
        return NullProber("no ICMP: ping sockets are disabled (net.ipv4.ping_group_range) and no ping binary")
    return NullProber(f"ICMP probing is not implemented for {sys.platform}")
