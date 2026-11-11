"""Run the checks in order and collect a Diagnosis."""

from __future__ import annotations

import platform
import socket
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import ModuleType
from typing import Any

from . import __version__
from .checks import CHECKS, local, path
from .context import Options, RunContext
from .models import CheckResult, Status, worst
from .netutil import call_with_timeout, is_ipv4
from .target import Target


@dataclass
class Diagnosis:
    target: Target
    options: Options
    started_at: str
    finished_at: str = ""
    duration_s: float = 0.0
    environment: dict[str, Any] = field(default_factory=dict)
    results: list[CheckResult] = field(default_factory=list)

    @property
    def status(self) -> Status:
        return worst(r.status for r in self.results)

    def result(self, check_id: str) -> CheckResult | None:
        return next((r for r in self.results if r.id == check_id), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "netdoctor",
            "version": __version__,
            "target": self.target.to_dict(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": self.duration_s,
            "status": self.status.value,
            "environment": self.environment,
            "options": self.options.to_dict(),
            "checks": [r.to_dict() for r in self.results],
        }


def environment(ctx: RunContext) -> dict[str, Any]:
    return {
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "python": platform.python_version(),
        "netdoctor": __version__,
        "icmp_engine": ctx.prober.name,
        "local_time": datetime.now().astimezone().isoformat(timespec="seconds"),
    }


def _prerequisite(ctx: RunContext, check_id: str) -> None:
    """When a check is not selected, still fill in what later checks need from it."""
    try:
        if check_id == "local" and ctx.proxy is None:
            local.resolve_proxy(ctx)
        elif check_id == "dns" and ctx.ip is None:
            if ctx.target.is_ip:
                ctx.ip, ctx.addresses = ctx.target.host, [ctx.target.host]
                return
            res, _err, _to = call_with_timeout(socket.getaddrinfo, 8.0, ctx.target.host, None, 0, socket.SOCK_STREAM)
            addrs = list(dict.fromkeys(ai[4][0] for ai in res or []))
            addrs.sort(key=lambda a: 0 if is_ipv4(a) else 1)
            ctx.addresses = addrs
            ctx.ip = addrs[0] if addrs else None
            ctx.ip_source = "system resolver"
        elif check_id == "path" and ctx.egress is None and ctx.ip and is_ipv4(ctx.ip):
            ctx.egress = path.egress_info(ctx.ip)
    except Exception:  # noqa: BLE001 - best effort only
        pass


def run_diagnosis(
    target: Target,
    opts: Options,
    on_start: Callable[[ModuleType], None] | None = None,
    on_done: Callable[[CheckResult], None] | None = None,
) -> Diagnosis:
    ctx = RunContext(target, opts)
    diag = Diagnosis(target, opts, started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    diag.environment = environment(ctx)
    t0 = time.perf_counter()
    for module in CHECKS:
        selected = (opts.only is None or module.ID in opts.only) and module.ID not in opts.skip
        if not selected:
            _prerequisite(ctx, module.ID)
            continue
        if on_start:
            on_start(module)
        started = time.perf_counter()
        try:
            result = module.run(ctx)
        except Exception as exc:  # noqa: BLE001 - one broken check must not hide the others
            result = CheckResult(module.ID, module.LAYER, module.TITLE)
            result.add(f"{module.ID}.crashed", Status.ERROR, f"The {module.ID} check crashed: {exc!r}")
            result.summary = result.findings[-1].message
            result.data["traceback"] = traceback.format_exc()
        result.duration_ms = (time.perf_counter() - started) * 1000.0
        ctx.results[module.ID] = result
        diag.results.append(result)
        if on_done:
            on_done(result)
    diag.duration_s = round(time.perf_counter() - t0, 1)
    diag.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    diag.environment["target_ip"] = ctx.ip
    diag.environment["target_ip_source"] = ctx.ip_source
    diag.environment["proxy"] = ctx.proxy.to_dict() if ctx.proxy else None
    diag.environment["egress"] = ctx.egress
    return diag
