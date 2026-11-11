"""Path MTU: DF-bit ping sweep to find the largest packet that crosses the path,
and tell a working PMTUD (routers send 'fragmentation needed') from a black hole
(big packets vanish and nothing comes back)."""

from __future__ import annotations

from collections.abc import Callable

from ..context import RunContext
from ..icmp import ProbeReply, ProbeStatus
from ..models import CheckResult, Status, Table
from ..netutil import IS_WINDOWS, is_ipv4, parallel_map

ID = "pmtu"
LAYER = "L3 Path MTU"
TITLE = "Path MTU (DF-bit sweep)"

OVERHEAD = 28  # IPv4 header 20 + ICMP header 8: packet size = payload + 28
BASE_PAYLOAD = 64
TRIES = 3  # concurrent probes per size; a size fails only if all of them fail
CONFIRM_TRIES = 6


def sweep(probe: Callable[[int], ProbeReply], max_payload: int, local_ips: set[str] | None = None) -> dict:
    """Find the largest DF payload that gets an echo reply. `probe(size)` sends one probe.

    Pure apart from `probe`, so tests can drive it with a simulated path."""
    local_ips = local_ips or set()
    log: list[tuple[int, ProbeReply]] = []

    def attempt(size: int, tries: int = TRIES) -> ProbeReply:
        replies = parallel_map(lambda _i: probe(size), range(tries), workers=tries)
        for rep in replies:
            if rep.status == ProbeStatus.FRAG_NEEDED and rep.responder in local_ips:
                rep.status = ProbeStatus.LOCAL_TOO_BIG
        best = next((x for x in replies if x.status == ProbeStatus.REPLY), None) \
            or next((x for x in replies if x.status == ProbeStatus.FRAG_NEEDED), None) \
            or next((x for x in replies if x.status == ProbeStatus.LOCAL_TOO_BIG), None) or replies[0]
        log.append((size, best))
        return best

    base = attempt(BASE_PAYLOAD)
    if base.status != ProbeStatus.REPLY:
        return {"outcome": "no_icmp", "pmtu": None, "log": log}
    top = attempt(max_payload)
    if top.status == ProbeStatus.REPLY:
        return {"outcome": "full", "pmtu": max_payload + OVERHEAD, "log": log}

    definite = (ProbeStatus.FRAG_NEEDED, ProbeStatus.LOCAL_TOO_BIG)
    good, bad = BASE_PAYLOAD, max_payload
    for _ in range(5):  # restarts only happen when packet loss fooled the search
        while bad - good > 1:
            mid = (good + bad) // 2
            rep = attempt(mid)
            if rep.status == ProbeStatus.REPLY:
                good = mid
            else:
                bad = mid
                if rep.status == ProbeStatus.FRAG_NEEDED and rep.mtu and good < rep.mtu - OVERHEAD < bad:
                    hint = attempt(rep.mtu - OVERHEAD)
                    if hint.status == ProbeStatus.REPLY:
                        good = rep.mtu - OVERHEAD
        # A boundary set by frag-needed / local refusal is certain. One set only by
        # silence might be random loss: re-test it harder before believing it.
        if any(r.status in definite for s, r in log if s == bad):
            break
        confirm = attempt(bad, CONFIRM_TRIES)
        if confirm.status != ProbeStatus.REPLY:
            break
        good = bad
        bad = min([s for s, r in log if s > good and r.status in definite] or [max_payload])
        if good >= max_payload:
            return {"outcome": "full", "pmtu": max_payload + OVERHEAD, "log": log}

    above = [r for s, r in log if s > good]
    frag = [r for r in above if r.status == ProbeStatus.FRAG_NEEDED]
    local = [r for r in above if r.status == ProbeStatus.LOCAL_TOO_BIG]
    if frag:
        outcome = "reduced"
    elif local:
        outcome = "local_limit"
    else:
        outcome = "blackhole"
    return {
        "outcome": outcome,
        "pmtu": good + OVERHEAD,
        "largest_ok_payload": good,
        "smallest_failed_payload": bad,
        "frag_from": frag[0].responder if frag else None,
        "reported_mtu": next((r.mtu for r in frag if r.mtu), None),
        "log": log,
    }


def _local_ips() -> set[str]:
    try:
        import psutil

        return {a.address for addrs in psutil.net_if_addrs().values() for a in addrs}
    except Exception:  # noqa: BLE001
        return set()


def _pick_target(ctx: RunContext) -> tuple[str | None, str]:
    icmp = ctx.result("icmp")
    if ctx.ip and (icmp is None or icmp.data.get("received", 0) > 0):
        return ctx.ip, "destination"
    path = ctx.result("path")
    if path and path.data.get("hops"):
        responding = [h for h in path.data["hops"] if h["received"] > 0 and h["host"]]
        if responding:
            h = responding[-1]
            return h["host"], f"hop {h['ttl']} (the destination does not answer ping)"
    return None, ""


def run(ctx: RunContext) -> CheckResult:
    r = CheckResult(ID, LAYER, TITLE)
    shown = ctx.ip or ctx.target.host
    r.commands = [f"ping -f -l 1472 {shown}", f"ping -f -l 1372 {shown}"] if IS_WINDOWS else [
        f"ping -M do -s 1472 -c 3 {shown}", f"tracepath -n {shown}"]
    if not ctx.ip:
        return r.skip("No IP address to probe (DNS failed)")
    if not is_ipv4(ctx.ip):
        return r.skip(f"{ctx.ip} is IPv6; the ICMP engine is IPv4-only for now")
    dst, label = _pick_target(ctx)
    if not dst:
        return r.skip("Neither the destination nor any hop answers ICMP echo, so a DF sweep is not possible")

    iface_mtu = (ctx.egress or {}).get("mtu") or 1500
    if iface_mtu > 9000 or iface_mtu < 576:
        iface_mtu = 1500
    max_payload = iface_mtu - OVERHEAD
    prober = ctx.prober
    result = sweep(lambda size: prober.probe(dst, size=size, df=True, ttl=64, timeout=1.0), max_payload, _local_ips())
    log = result.pop("log")
    r.data = {"target": dst, "target_label": label, "interface_mtu": iface_mtu, **result,
              "probes": [{"payload": s, "packet": s + OVERHEAD, **rep.to_dict()} for s, rep in log]}

    table = Table(f"DF probes to {dst} ({label})", ["Payload", "Packet", "Result", "From"])
    for size, rep in sorted(log, key=lambda x: x[0]):
        text = {"reply": "echo reply", "frag_needed": "frag needed" + (f" (MTU {rep.mtu})" if rep.mtu else ""),
                "local_too_big": "too big for local stack", "timeout": "no reply"}.get(rep.status.value, rep.status.value)
        table.rows.append([str(size), str(size + OVERHEAD), text, rep.responder or "-"])
    r.tables.append(table)

    outcome, pmtu = result["outcome"], result["pmtu"]
    if outcome == "no_icmp":
        return r.skip(f"{dst} stopped answering even small pings; cannot sweep")
    if outcome == "full":
        r.add("pmtu.ok", Status.PASS, f"Full {pmtu}-byte packets with DF set reach {dst}: no MTU limit below the "
              f"interface MTU ({iface_mtu}).")
    elif outcome == "reduced":
        src = result["frag_from"]
        r.add("pmtu.reduced", Status.INFO,
              f"Path MTU to {dst} is {pmtu} bytes (interface MTU {iface_mtu}). {src} answers bigger DF packets with "
              f"'fragmentation needed'" + (f" (next-hop MTU {result['reported_mtu']})" if result["reported_mtu"] else "")
              + f", so PMTUD works. TCP MSS on this path: {pmtu - 40}.")
    elif outcome == "local_limit":
        r.add("pmtu.reduced", Status.INFO,
              f"Path MTU to {dst} is {pmtu} bytes: the local stack refuses bigger DF packets (it has already learned "
              f"a smaller path MTU, or a tunnel adapter limits it). TCP MSS on this path: {pmtu - 40}.")
    else:
        r.add("pmtu.blackhole", Status.FAIL,
              f"PMTU black hole: DF packets up to {pmtu} bytes reach {dst}, bigger ones ({result['smallest_failed_payload'] + OVERHEAD}+) "
              "vanish and no ICMP 'fragmentation needed' comes back. Typical inside IPsec/GRE tunnels when a firewall "
              f"drops ICMP type 3 code 4. TCP connects but large transfers and TLS handshakes stall. Fix: allow "
              f"ICMP frag-needed, or clamp TCP MSS to {pmtu - 40} on the tunnel.")
    r.summary = r.findings[-1].message
    return r
