"""Path: egress interface and next hop, then a traceroute (TTL 1..N in parallel)
followed by MTR-style rounds that give per-hop loss and latency."""

from __future__ import annotations

import time
from collections import Counter

import psutil

from ..context import RunContext
from ..icmp import ProbeStatus, paced_probes
from ..models import CheckResult, Status, Table
from ..netutil import IS_WINDOWS, fmt_ms, is_ipv4, parallel_map, reverse_dns_many, rtt_stats, source_ip_for
from . import local

ID = "path"
LAYER = "L3 Path"
TITLE = "Traceroute and per-hop loss (MTR)"

ROUND_INTERVAL = 0.5  # seconds between MTR rounds (2 probes/s per hop)


def egress_info(ip: str) -> dict:
    src = source_ip_for(ip)
    info: dict = {"source_ip": src, "interface": None, "mtu": None, "gateway": None}
    if src:
        for name, addrs in psutil.net_if_addrs().items():
            if any(a.address == src for a in addrs):
                info["interface"] = name
                st = psutil.net_if_stats().get(name)
                info["mtu"] = st.mtu if st else None
                break
    route = local.lookup_route(local.get_routes(), ip)
    if route:
        info["gateway"] = route.gateway
        info["route"] = f"{route.destination}/{route.prefixlen}"
    return info


def hop_stats(ttl: int, replies: list) -> dict:
    answered = [p for p in replies if p.answered and p.rtt_ms is not None]
    responders = Counter(p.responder for p in answered if p.responder)
    rtts = [p.rtt_ms for p in answered]
    st = rtt_stats(rtts)
    sent = len(replies)
    return {
        "ttl": ttl,
        "responders": responders.most_common(),
        "host": responders.most_common(1)[0][0] if responders else None,
        "sent": sent,
        "received": len(answered),
        "loss_pct": round(100.0 * (sent - len(answered)) / sent, 1) if sent else 100.0,
        "last": round(rtts[-1], 2) if rtts else None,
        "avg": st["avg"],
        "best": st["min"],
        "worst": st["max"],
        "stdev": st["stdev"],
        "statuses": dict(Counter(p.status.value for p in replies)),
        "unreachable": next((p.detail or str(p.code) for p in replies if p.status == ProbeStatus.UNREACHABLE), None),
    }


def analyze_hops(hops: list[dict], dest_ip: str, reached: bool) -> list[tuple[str, Status, str]]:
    """Pure function: turn the hop table into findings, the way you would read an MTR."""
    out: list[tuple[str, Status, str]] = []
    responding = [h for h in hops if h["received"] > 0]
    if not responding:
        out.append(("path.silent", Status.WARN,
                    "No hop answered at all: ICMP time-exceeded is filtered right at the first hop or by a local firewall."))
        return out

    for h in hops:
        if h["unreachable"]:
            out.append(("path.unreachable", Status.FAIL,
                        f"Hop {h['ttl']} ({h['host']}) answers 'destination unreachable' ({h['unreachable']}): "
                        "a routing or ACL problem at that router."))
            break

    dest = hops[-1] if reached else None
    if reached and dest:
        out.insert(0, ("path.reached", Status.PASS,
                       f"Reached {dest_ip} in {dest['ttl']} hops, avg {fmt_ms(dest['avg'])} at the destination."))
    else:
        last = responding[-1]
        out.append(("path.stops", Status.WARN,
                    f"Nothing answers beyond hop {last['ttl']} ({last['host']}). Either the destination or a firewall "
                    "filters ICMP (common; the TCP check decides), or traffic is black-holed after this hop."))

    # Loop: the same router answering at TTL t and t+2 repeatedly.
    seq = [h["host"] for h in hops]
    repeats = sum(1 for i in range(len(seq) - 2) if seq[i] and seq[i] == seq[i + 2] and seq[i] != seq[i + 1])
    if repeats >= 2:
        out.append(("path.loop", Status.WARN, "The same routers repeat every other hop: a routing loop."))

    dest_loss = dest["loss_pct"] if dest else None
    # Real loss: starts at hop j and persists all the way to the destination.
    if dest is not None and dest_loss is not None and dest_loss >= 5:
        known = [h for h in hops if h["received"] > 0]
        start = dest
        for h in reversed(known):
            if h["loss_pct"] >= 0.5 * dest_loss:
                start = h
            else:
                break
        where = "at the first hop: the local link (Wi-Fi, cable) or the gateway" if start["ttl"] == 1 else \
            f"at hop {start['ttl']} ({start['host']})"
        out.append(("path.loss_from_hop", Status.FAIL if dest_loss >= 10 else Status.WARN,
                    f"{dest_loss:.0f}% loss at the destination, and it begins {where} and carries through every "
                    "later hop: real packet loss at or after that point."))

    # Rate limiting: loss at a hop that later hops don't show.
    floor = dest_loss if dest_loss is not None else min((h["loss_pct"] for h in responding[-1:]), default=0)
    for i, h in enumerate(hops[:-1]):
        later = [x for x in hops[i + 1 :] if x["received"] > 0]
        if 0 < h["received"] and h["loss_pct"] >= 20 and later and min(x["loss_pct"] for x in later) + 10 <= h["loss_pct"] \
                and h["loss_pct"] > floor + 10:
            out.append(("path.icmp_ratelimit", Status.INFO,
                        f"Hop {h['ttl']} ({h['host']}) shows {h['loss_pct']:.0f}% loss but later hops don't: that router "
                        "rate-limits ICMP replies to traceroute. Not real loss."))

    # Latency jump that persists.
    best_jump = None
    prev = None
    for h in responding:
        if prev is not None and h["avg"] is not None and prev["avg"] is not None:
            jump = h["avg"] - prev["avg"]
            persists = all(x["avg"] is None or x["avg"] >= h["avg"] - 25 for x in responding if x["ttl"] > h["ttl"])
            if jump > 50 and persists and (best_jump is None or jump > best_jump[0]):
                best_jump = (jump, h)
        prev = h
    if best_jump:
        jump, h = best_jump
        out.append(("path.latency_jump", Status.INFO,
                    f"Latency rises by {fmt_ms(jump)} at hop {h['ttl']} ({h['host']}) and stays up: a long-haul or "
                    "congested link, a slow tunnel, or a delay added there."))
    return out


def run(ctx: RunContext) -> CheckResult:
    r = CheckResult(ID, LAYER, TITLE)
    ip = ctx.ip
    target = ip or ctx.target.host
    r.commands = [f"tracert -d {target}", f"pathping -n {target}"] if IS_WINDOWS else [
        f"traceroute -n -I {target}", f"mtr -rwzbc 10 {target}", f"tracepath -n {target}"]
    if not ip:
        return r.skip("No IP address to trace (DNS failed)")
    if not is_ipv4(ip):
        return r.skip(f"{ip} is IPv6; the ICMP engine is IPv4-only for now")

    eg = egress_info(ip)
    ctx.egress = eg
    r.data["egress"] = eg
    if eg["source_ip"]:
        r.evidence.append(
            f"Leaves via {eg['interface'] or '?'} ({eg['source_ip']}), "
            + (f"next hop {eg['gateway']}" if eg.get("gateway") else "directly on-link")
            + (f", interface MTU {eg['mtu']}" if eg["mtu"] else "") + ".")
    else:
        r.add("path.no_route", Status.FAIL, f"The OS has no route to {ip}.")
        r.summary = r.findings[-1].message
        return r

    prober, timeout, max_hops = ctx.prober, ctx.opts.probe_timeout, ctx.opts.max_hops
    started = time.perf_counter()

    # Round 0: every TTL at once.
    first = parallel_map(lambda ttl: prober.probe(ip, ttl=ttl, size=32, timeout=timeout), range(1, max_hops + 1),
                         workers=max_hops)
    if all(p.status == ProbeStatus.ERROR for p in first):
        r.add("path.unavailable", Status.ERROR, f"Could not send ICMP probes: {first[0].detail}")
        r.summary = r.findings[-1].message
        return r
    dest_ttl = next((i + 1 for i, p in enumerate(first) if p.status == ProbeStatus.REPLY), None)
    reached = dest_ttl is not None
    if reached:
        n_hops = dest_ttl
    else:
        answered = [i + 1 for i, p in enumerate(first) if p.answered]
        n_hops = min(max_hops, (max(answered) + 2) if answered else 8)

    # MTR rounds: R x n_hops probes, spread evenly.
    rounds = max(0, ctx.opts.mtr_rounds)
    jobs = [{"dst": ip, "ttl": ttl, "size": 32} for _ in range(rounds) for ttl in range(1, n_hops + 1)]
    more = paced_probes(prober, jobs, ROUND_INTERVAL / max(1, n_hops), timeout) if jobs else []
    per_ttl: dict[int, list] = {ttl: [first[ttl - 1]] for ttl in range(1, n_hops + 1)}
    for job, reply in zip(jobs, more, strict=False):
        per_ttl[job["ttl"]].append(reply)
    hops = [hop_stats(ttl, per_ttl[ttl]) for ttl in range(1, n_hops + 1)]
    r.data.update({"reached": reached, "hops": hops, "rounds": rounds + 1, "prober": prober.name,
                   "elapsed_s": round(time.perf_counter() - started, 1)})

    names = reverse_dns_many([h["host"] for h in hops if h["host"]]) if ctx.opts.rdns else {}
    table = Table(f"Path to {ip} ({rounds + 1} probes per hop)",
                  ["Hop", "Host", "Loss%", "Snt", "Last", "Avg", "Best", "Wrst", "StDev"])
    for h in hops:
        if h["host"]:
            host = h["host"] + (f" ({names[h['host']]})" if names.get(h["host"]) else "")
            if len(h["responders"]) > 1:
                host += f" +{len(h['responders']) - 1} more"
        else:
            host = "* (no reply)"
        table.rows.append([str(h["ttl"]), host, f"{h['loss_pct']:.0f}%", str(h["sent"]), fmt_ms(h["last"]),
                           fmt_ms(h["avg"]), fmt_ms(h["best"]), fmt_ms(h["worst"]), fmt_ms(h["stdev"])])
    r.tables.append(table)

    for code, status, msg in analyze_hops(hops, ip, reached):
        r.add(code, status, msg)
    r.summary = next((f.message for f in r.findings if f.status in (Status.FAIL, Status.WARN)),
                     r.findings[0].message if r.findings else "")
    return r
