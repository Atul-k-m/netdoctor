"""ICMP echo: loss, RTT min/avg/max, jitter, reply TTL."""

from __future__ import annotations

from collections import Counter

from ..context import RunContext
from ..icmp import ProbeStatus, paced_probes
from ..models import CheckResult, Status, Table
from ..netutil import IS_WINDOWS, fmt_ms, is_ipv4, rtt_stats

ID = "icmp"
LAYER = "L3 ICMP"
TITLE = "Ping: loss, latency, jitter"


def guess_hops(reply_ttl: int | None) -> tuple[int, int] | None:
    """Reply TTL -> (initial TTL guess, hops). Hosts start at 64 (Linux/macOS),
    128 (Windows) or 255 (network gear)."""
    if not reply_ttl:
        return None
    for initial in (64, 128, 255):
        if reply_ttl <= initial:
            return initial, initial - reply_ttl
    return None


def summarize(replies: list, sent: int) -> dict:
    ok = [p for p in replies if p.status == ProbeStatus.REPLY and p.rtt_ms is not None]
    rtts = [p.rtt_ms for p in ok]
    stats = rtt_stats(rtts)
    stats.update({
        "sent": sent,
        "received": len(ok),
        "loss_pct": round(100.0 * (sent - len(ok)) / sent, 1) if sent else 0.0,
        "statuses": dict(Counter(p.status.value for p in replies)),
        "reply_ttl": Counter(p.ttl for p in ok if p.ttl).most_common(1)[0][0] if any(p.ttl for p in ok) else None,
    })
    return stats


def run(ctx: RunContext) -> CheckResult:
    r = CheckResult(ID, LAYER, TITLE)
    ip = ctx.ip
    r.commands = [f"ping -n {ctx.opts.count} {ip or ctx.target.host}"] if IS_WINDOWS else [
        f"ping -c {ctx.opts.count} -i {ctx.opts.interval} {ip or ctx.target.host}"]
    if not ip:
        return r.skip("No IP address to ping (DNS failed)")
    if not is_ipv4(ip):
        return r.skip(f"{ip} is IPv6; the ICMP engine is IPv4-only for now")

    count = ctx.opts.count
    jobs = [{"dst": ip, "size": 56, "ttl": 64} for _ in range(count)]
    replies = paced_probes(ctx.prober, jobs, ctx.opts.interval, ctx.opts.probe_timeout + 0.5)
    st = summarize(replies, count)
    r.data = {"target_ip": ip, "prober": ctx.prober.name, **st, "rtts": [p.rtt_ms for p in replies]}

    errors = [p for p in replies if p.status == ProbeStatus.ERROR]
    if len(errors) == count:
        r.add("icmp.unavailable", Status.ERROR, f"Could not send ICMP: {errors[0].detail}")
        r.summary = r.findings[-1].message
        return r

    table = Table(f"{count} echo requests to {ip}", ["Sent", "Received", "Loss", "Min", "Avg", "Max", "Jitter", "Reply TTL"])
    table.rows.append([str(count), str(st["received"]), f"{st['loss_pct']:.0f}%", fmt_ms(st["min"]), fmt_ms(st["avg"]),
                       fmt_ms(st["max"]), fmt_ms(st["jitter"]), str(st["reply_ttl"] or "-")])
    r.tables.append(table)

    unreachable = [p for p in replies if p.status == ProbeStatus.UNREACHABLE]
    if st["received"] == 0:
        if unreachable:
            u = unreachable[0]
            r.add("icmp.unreachable", Status.FAIL,
                  f"{u.responder or 'A router'} answers 'destination unreachable' ({u.detail or u.code}) for {ip}: "
                  "no route to it, or an ACL rejecting it.")
        else:
            r.add("icmp.no_reply", Status.WARN,
                  f"No echo replies from {ip} ({count}/{count} lost). ICMP is often filtered, so this alone does not "
                  "mean the host is down: the TCP check is the real test.")
    else:
        loss = st["loss_pct"]
        # One lost echo out of 20 (5%) is common on Wi-Fi and is not a fault on its own.
        if loss >= 10:
            r.add("icmp.loss", Status.FAIL, f"{loss:.0f}% packet loss to {ip} ({count - st['received']}/{count} lost).")
        elif loss > 0:
            r.add("icmp.loss", Status.WARN, f"{loss:.0f}% packet loss to {ip} ({count - st['received']}/{count} lost).")
        if st["avg"] is not None and st["avg"] > ctx.opts.latency_warn_ms:
            r.add("icmp.latency_high", Status.WARN,
                  f"High latency: average RTT {fmt_ms(st['avg'])} (min {fmt_ms(st['min'])}). Over ~150 ms voice, video "
                  "and chatty apps suffer.")
        if st["jitter"] is not None and st["jitter"] > 30:
            r.add("icmp.jitter_high", Status.WARN, f"High jitter: RTT varies by {fmt_ms(st['jitter'])} between packets.")
        if not r.findings:
            r.add("icmp.ok", Status.PASS, f"{ip} answers: 0% loss, avg {fmt_ms(st['avg'])}, jitter {fmt_ms(st['jitter'])}.")
        hops = guess_hops(st["reply_ttl"])
        if hops:
            r.evidence.append(f"Reply TTL {st['reply_ttl']}: probably a host that starts at {hops[0]}, about {hops[1]} hops away.")
    r.summary = next((f.message for f in r.findings if f.status != Status.PASS), r.findings[0].message)
    return r
