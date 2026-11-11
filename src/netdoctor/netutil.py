"""Small helpers shared by the checks: IP classification, timeouts, subprocesses, stats."""

from __future__ import annotations

import ipaddress
import socket
import statistics
import subprocess
import sys
import threading
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Any, TypeVar

T = TypeVar("T")
R = TypeVar("R")

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform.startswith("linux")

CGNAT = ipaddress.ip_network("100.64.0.0/10")


def classify_ip(ip: str) -> str:
    """public | private | cgnat | loopback | link-local | unspecified | multicast | reserved | invalid"""
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return "invalid"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.version == 4 and addr in CGNAT:
        return "cgnat"
    if addr.is_multicast:
        return "multicast"
    if addr.is_private:
        return "private"
    if addr.is_global:
        return "public"
    return "reserved"


def is_ipv4(ip: str | None) -> bool:
    try:
        return ip is not None and ipaddress.ip_address(ip).version == 4
    except ValueError:
        return False


_TWO_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu", "ne", "or", "go"}


def registrable_domain(host: str) -> str:
    """Approximate eTLD+1 ("www.bbc.co.uk" -> "bbc.co.uk"). Good enough to tell
    "same site" from "redirected somewhere else entirely"."""
    host = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _TWO_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def same_site(a: str, b: str) -> bool:
    return registrable_domain(a) == registrable_domain(b)


def call_with_timeout(fn: Callable[..., R], timeout: float, *args: Any) -> tuple[R | None, BaseException | None, bool]:
    """Run fn(*args) in a daemon thread. Returns (result, exception, timed_out).

    getaddrinfo() and gethostbyaddr() have no timeout parameter and can hang for
    10+ seconds when DNS is broken, which is exactly when we are running."""
    box: dict[str, Any] = {}

    def runner() -> None:
        try:
            box["result"] = fn(*args)
        except BaseException as exc:  # noqa: BLE001 - reported to the caller
            box["error"] = exc

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return None, None, True
    return box.get("result"), box.get("error"), False


def parallel_map(fn: Callable[[T], R], items: Iterable[T], workers: int = 32) -> list[R]:
    items = list(items)
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(items)))) as pool:
        return list(pool.map(fn, items))


def reverse_dns_many(ips: Iterable[str], timeout: float = 1.5) -> dict[str, str]:
    """PTR lookups in parallel, each capped by `timeout`."""

    def one(ip: str) -> tuple[str, str]:
        result, _err, _to = call_with_timeout(socket.gethostbyaddr, timeout, ip)
        return ip, result[0] if result else ""

    return dict(parallel_map(one, sorted(set(ips)), workers=16))


def run_command(cmd: list[str], timeout: float = 10.0) -> tuple[int, str]:
    """Run a native tool and return (returncode, combined output). Never raises.

    Windows console tools print in the OEM code page, so decode with it."""
    encoding = "oem" if IS_WINDOWS else "utf-8"
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except FileNotFoundError:
        return 127, ""
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"") + (exc.stderr or b"")
        return 124, out.decode(encoding, errors="replace")
    except OSError as exc:
        return 126, str(exc)
    out = (proc.stdout or b"") + (proc.stderr or b"")
    return proc.returncode, out.decode(encoding, errors="replace")


def source_ip_for(dst: str) -> str | None:
    """Ask the kernel which local address it would use to reach dst (no packet is sent)."""
    family = socket.AF_INET6 if ":" in dst else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.connect((dst, 9))
            return s.getsockname()[0]
    except OSError:
        return None


def rtt_stats(rtts: list[float]) -> dict[str, float | None]:
    """min/avg/max, population std-dev, and jitter = mean |RTT[i] - RTT[i-1]|.

    The jitter definition is the simple form of RFC 3550's interarrival jitter
    (without its 1/16 smoothing), which is what most ping/MTR tools report."""
    if not rtts:
        return {"min": None, "avg": None, "max": None, "stdev": None, "jitter": None}
    diffs = [abs(b - a) for a, b in zip(rtts, rtts[1:], strict=False)]
    return {
        "min": round(min(rtts), 2),
        "avg": round(statistics.fmean(rtts), 2),
        "max": round(max(rtts), 2),
        "stdev": round(statistics.pstdev(rtts), 2) if len(rtts) > 1 else 0.0,
        "jitter": round(statistics.fmean(diffs), 2) if diffs else 0.0,
    }


def fmt_ms(value: float | None) -> str:
    if value is None:
        return "-"
    if value < 1:
        return f"{value:.2f} ms"
    if value < 100:
        return f"{value:.1f} ms"
    return f"{value:.0f} ms"


def human_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 / 1024:.1f} MB"
