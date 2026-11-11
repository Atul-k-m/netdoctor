"""Run the checks in order and collect a Diagnosis."""

from __future__ import annotations

import platform
import socket
import time
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
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


def _resolve_quick(host: str, timeout: float = 3.0) -> list[str]:
    res, _err, _to = call_with_timeout(socket.getaddrinfo, timeout, host, None, 0, socket.SOCK_STREAM)
    return list(dict.fromkeys(ai[4][0] for ai in res or []))


def capture_hosts(ctx: RunContext) -> list[str]:
    """IPs for the capture filter, known before DNS runs: the target (pre-resolved,
    falling back to 8.8.8.8 when the local resolver is broken), the public resolvers
    the DNS check asks, and the proxy."""
    t = ctx.target
    ips = [t.host] if t.is_ip else _resolve_quick(t.host)
    if not ips and not t.is_ip:
        try:
            import dns.message
            import dns.query
            import dns.rdatatype

            resp = dns.query.udp(dns.message.make_query(t.host, dns.rdatatype.A), "8.8.8.8", timeout=2.0)
            ips = [r.address for rrset in resp.answer if rrset.rdtype == dns.rdatatype.A for r in rrset]
        except Exception:  # noqa: BLE001 - best effort
            ips = []
    ips += ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
    if ctx.proxy and ctx.proxy.host_port:
        ips += _resolve_quick(ctx.proxy.host_port[0])
    return list(dict.fromkeys(ips))


def capture_focus(ctx: RunContext) -> list[tuple[str, int]]:
    """Server endpoints whose flows the capture summary should judge."""
    port = ctx.target.port
    focus = [(ip, port) for ip in dict.fromkeys([ctx.ip, *ctx.addresses]) if ip]
    if ctx.proxy and ctx.proxy.host_port:
        phost, pport = ctx.proxy.host_port
        focus += [(ip, pport) for ip in _resolve_quick(phost)]
    return focus


def _start_capture(ctx: RunContext, on_capture: Callable | None) -> tuple[Any, str | None]:
    from .capture import CaptureUnavailable, start_capture

    out = ctx.opts.out_dir or Path("runs")
    try:
        hosts = capture_hosts(ctx)
        # hosts[0] is the target (or 8.8.8.8 if it did not resolve): its route picks the interface.
        session = start_capture(out / "capture.pcap", hosts, ctx.opts.capture_tool, hosts[0] if hosts else None)
    except CaptureUnavailable as exc:
        if on_capture:
            on_capture(None, str(exc))
        return None, str(exc)
    except Exception as exc:  # noqa: BLE001 - capture must never break the diagnosis
        if on_capture:
            on_capture(None, repr(exc))
        return None, repr(exc)
    if on_capture:
        on_capture(session, None)
    return session, None


def _finish_capture(ctx: RunContext, session: Any, error: str | None) -> CheckResult:
    from .capture import build_result, summarize_file, unavailable

    if session is None:
        return unavailable(error or "not started")
    started = time.perf_counter()
    info = session.stop()
    try:
        summary = summarize_file(session.path, capture_focus(ctx))
    except Exception as exc:  # noqa: BLE001
        res = unavailable(f"capture saved to {session.path} but could not be analyzed: {exc!r}")
        res.data["traceback"] = traceback.format_exc()
        return res
    res = build_result(summary, info)
    res.duration_ms = (time.perf_counter() - started) * 1000.0
    return res


def run_diagnosis(
    target: Target,
    opts: Options,
    on_start: Callable[[ModuleType], None] | None = None,
    on_done: Callable[[CheckResult], None] | None = None,
    on_capture: Callable[[Any, str | None], None] | None = None,
) -> Diagnosis:
    ctx = RunContext(target, opts)
    diag = Diagnosis(target, opts, started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    diag.environment = environment(ctx)
    t0 = time.perf_counter()
    holder: dict[str, Any] = {}
    try:
        _run_checks(ctx, diag, on_start, on_done, on_capture, holder)
    finally:
        # Always stop the capture tool, even if the run is interrupted.
        if opts.capture:
            result = _finish_capture(ctx, holder.get("session"), holder.get("error"))
            ctx.results[result.id] = result
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


def _run_checks(ctx: RunContext, diag: Diagnosis, on_start, on_done, on_capture, holder: dict) -> None:
    opts = ctx.opts
    for module in CHECKS:
        selected = (opts.only is None or module.ID in opts.only) and module.ID not in opts.skip
        if not selected:
            _prerequisite(ctx, module.ID)
            if module.ID == "local" and opts.capture:
                holder["session"], holder["error"] = _start_capture(ctx, on_capture)
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
        if module.ID == "local" and opts.capture:
            holder["session"], holder["error"] = _start_capture(ctx, on_capture)
