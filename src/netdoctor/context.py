"""Run options and the shared state that checks hand to each other."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .icmp import Prober, get_prober
from .models import CheckResult
from .target import Target

if TYPE_CHECKING:
    from .proxyconf import ProxyDecision

# (url, expected status, expected body substring). The OS vendors' own probes.
DEFAULT_CAPTIVE_PROBES = [
    ("http://connectivitycheck.gstatic.com/generate_204", 204, None),
    ("http://www.msftconnecttest.com/connecttest.txt", 200, "Microsoft Connect Test"),
]


def captive_probes_from_env() -> list[tuple[str, int, str | None]]:
    """NETDOCTOR_CAPTIVE_PROBES="url|status|body,url|status" overrides the defaults
    (enterprises and the lab point Windows NCSI at their own probe host too)."""
    raw = os.environ.get("NETDOCTOR_CAPTIVE_PROBES")
    if not raw:
        return list(DEFAULT_CAPTIVE_PROBES)
    probes = []
    for item in raw.split(","):
        parts = item.strip().split("|")
        if not parts[0]:
            continue
        status = int(parts[1]) if len(parts) > 1 and parts[1] else 204
        body = parts[2] if len(parts) > 2 and parts[2] else None
        probes.append((parts[0], status, body))
    return probes


@dataclass
class Options:
    count: int = 20  # echo requests for the ICMP check
    interval: float = 0.2  # seconds between echo requests
    probe_timeout: float = 1.5  # seconds to wait for one ICMP probe
    max_hops: int = 30
    mtr_rounds: int = 10
    rdns: bool = True
    scan: bool = True
    proxy: str | None = None
    no_proxy: bool = False
    latency_warn_ms: float = 150.0
    only: set[str] | None = None
    skip: set[str] = field(default_factory=set)
    captive_probes: list[tuple[str, int, str | None]] = field(default_factory=captive_probes_from_env)
    capture: bool = False  # the CLI turns it on by default; library callers opt in
    capture_tool: str = "auto"
    out_dir: Path | None = None  # run folder for capture.pcap (and reports)

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "interval": self.interval,
            "probe_timeout": self.probe_timeout,
            "max_hops": self.max_hops,
            "mtr_rounds": self.mtr_rounds,
            "scan": self.scan,
            "proxy": self.proxy,
            "no_proxy": self.no_proxy,
            "only": sorted(self.only) if self.only else None,
            "skip": sorted(self.skip),
            "capture": self.capture,
            "capture_tool": self.capture_tool,
            "out_dir": str(self.out_dir) if self.out_dir else None,
        }


@dataclass
class RunContext:
    target: Target
    opts: Options
    results: dict[str, CheckResult] = field(default_factory=dict)
    # Set by the DNS check (or quietly by the runner when DNS is not selected).
    addresses: list[str] = field(default_factory=list)
    ip: str | None = None
    ip_source: str = ""
    public_answers: list[str] = field(default_factory=list)
    # Set by the local check (or quietly by the runner).
    proxy: ProxyDecision | None = None
    # Set by the path check.
    egress: dict[str, Any] | None = None
    _prober: Prober | None = None

    @property
    def prober(self) -> Prober:
        if self._prober is None:
            self._prober = get_prober()
        return self._prober

    def result(self, check_id: str) -> CheckResult | None:
        return self.results.get(check_id)

    @property
    def proxied(self) -> bool:
        return bool(self.proxy and self.proxy.proxy_url and self.target.is_web)
