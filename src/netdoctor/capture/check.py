"""Turn a capture summary into a CheckResult: findings, tables and the Wireshark
display filters that show the same evidence."""

from __future__ import annotations

from ..models import CheckResult, Status, Table
from ..netutil import fmt_ms, human_bytes

ID = "capture"
LAYER = "L2-L7 Packets"
TITLE = "Packet capture summary"

WIRESHARK_FILTERS = [
    ("TCP handshakes", "tcp.flags.syn == 1"),
    ("Resets", "tcp.flags.reset == 1"),
    ("Retransmissions", "tcp.analysis.retransmission || tcp.analysis.fast_retransmission"),
    ("Duplicate ACKs", "tcp.analysis.duplicate_ack"),
    ("Zero windows", "tcp.analysis.zero_window"),
    ("TLS ClientHello / ServerHello", "tls.handshake.type == 1 || tls.handshake.type == 2"),
    ("TLS alerts", "tls.alert_message"),
    ("DNS errors", "dns.flags.rcode != 0"),
    ("DNS without answer", "dns.flags.response == 0 && !dns.response_in"),
    ("ICMP errors", "icmp.type == 3 || icmp.type == 11 || icmpv6.type <= 4"),
]


def build_result(summary: dict, info: dict | None = None) -> CheckResult:
    r = CheckResult(ID, LAYER, TITLE)
    info = info or {}
    r.data = {"capture": info, "summary": summary}
    f = summary["tcp"]["focus_totals"]
    a = summary["tcp"]["all"]
    focus = ", ".join(summary.get("focus") or []) or "all flows"

    head = Table("Capture", ["File", "Tool", "Interface", "Packets", "Duration"])
    head.rows.append([info.get("file") or summary.get("file", "-"), info.get("tool", "-"), info.get("interface", "-"),
                      f"{summary['packets']} ({human_bytes(summary['bytes'])})", f"{summary['duration_s']:.1f} s"])
    r.tables.append(head)
    if info.get("filter"):
        r.evidence.append(f"Capture filter: {info['filter']}")
    if summary.get("truncated"):
        r.evidence.append("The file ends mid-packet (the capture tool was stopped hard); the last packet is lost.")

    if summary["packets"] == 0:
        r.add("capture.empty", Status.WARN, "No packets were captured: wrong interface, or the filter matched nothing.")
        r.summary = r.findings[-1].message
        return r

    # ---------------------------------------------------------------- TCP
    rtt = f["handshake_rtt_ms"]
    if f["handshakes_completed"]:
        r.add("capture.handshakes", Status.PASS,
              f"{f['handshakes_completed']} TCP handshake(s) to {focus} completed; SYN to SYN/ACK "
              f"min/avg/max {fmt_ms(rtt['min'])} / {fmt_ms(rtt['avg'])} / {fmt_ms(rtt['max'])}.")
    if f["refused"]:
        r.add("capture.syn_rst", Status.INFO,
              f"{f['refused']} connection attempt(s) to {focus} were answered with RST: the port is closed or a "
              "firewall REJECTs it.")
    if f["unanswered_syn"]:
        r.add("capture.syn_unanswered", Status.WARN,
              f"{f['unanswered_syn']} connection attempt(s) to {focus} got no SYN/ACK at all "
              f"({f['syn_retransmissions']} SYN retransmissions): the SYNs are silently dropped.")
    if f["retransmissions"] or f["dup_acks"]:
        segs = max(1, f["data_segments"])
        pct = 100.0 * f["retransmissions"] / segs
        status = Status.WARN if f["retransmissions"] >= 3 or pct >= 2 else Status.INFO
        r.add("capture.retransmissions", status,
              f"{f['retransmissions']} TCP retransmission(s) ({pct:.1f}% of {f['data_segments']} data segments), "
              f"{f['dup_acks']} duplicate ACK(s), {f['out_of_order']} out-of-order: packets are being lost on the path.")
    if f["zero_windows"]:
        r.add("capture.zero_window", Status.WARN,
              f"{f['zero_windows']} zero-window advertisement(s): a receiver's buffer was full, so the sender had to "
              "stop (an application not reading fast enough, or an overloaded host).")
    if f["rst_after_handshake_by_server"]:
        r.add("capture.server_reset", Status.WARN,
              f"The server side reset {f['rst_after_handshake_by_server']} established connection(s) (RST after the "
              "handshake): an application abort, a load balancer idle timeout, or an IPS killing the flow.")
    if f["rst_after_handshake_by_client"]:
        r.evidence.append(f"{f['rst_after_handshake_by_client']} RST(s) came from this client after the handshake. "
                          "NetDoctor closes its test connections abruptly when the server still has unread data "
                          "(e.g. TLS session tickets), so these are expected.")
    scan = a["refused"] + a["unanswered_syn"] - f["refused"] - f["unanswered_syn"]
    if scan > 0:
        r.evidence.append(f"{scan} other refused/unanswered SYNs belong to the common-port scan and are not counted "
                          "above.")

    flows = summary["tcp"]["flows_detail"]
    if flows:
        ft = Table(f"TCP connections to {focus}", ["Flow", "Result", "SYN->SYN/ACK", "MSS c/s", "Retrans c/s",
                                                   "Dup ACK", "Zero win", "RST c/s", "Bytes c/s"])
        for fl in flows[:15]:
            ft.rows.append([fl["flow"], fl["result"], fmt_ms(fl["handshake_ms"]),
                            f"{fl['mss_client'] or '-'}/{fl['mss_server'] or '-'}",
                            f"{fl['retrans_c2s']}/{fl['retrans_s2c']}", str(fl["dup_acks"]),
                            str(fl["zero_window_client"] + fl["zero_window_server"]),
                            f"{fl['rst_client']}/{fl['rst_server']}",
                            f"{human_bytes(fl['bytes_c2s'])}/{human_bytes(fl['bytes_s2c'])}"])
        if len(flows) > 15:
            ft.rows.append([f"… {len(flows) - 15} more", "", "", "", "", "", "", "", ""])
        r.tables.append(ft)

    # ---------------------------------------------------------------- TLS
    tls = summary["tls"]
    if tls["handshakes"]:
        tt = Table("TLS handshakes", ["Flow", "SNI", "Version", "Cipher", "ALPN", "Certs", "Alerts"])
        for h in tls["handshakes"][:12]:
            alerts = ", ".join(f"{x['from']}: {x['description']}" for x in h["alerts"]) or "-"
            tt.rows.append([h["flow"], h["sni"] or "-", h["version"] or ("no ServerHello" if h["client_hello"] else "-"),
                            h["cipher"] or "-", h["alpn"] or "-", "-" if h["certificates"] is None else str(h["certificates"]),
                            alerts])
        r.tables.append(tt)
    fatal = [x for x in tls["alerts"] if not x["encrypted"] and x["description"] != "close_notify"]
    if fatal:
        parts = sorted({f"{x['description']} ({x['level']}, sent by the {x['from']})" for x in fatal})
        r.add("capture.tls_alert", Status.WARN, f"TLS alert(s) on the wire: {'; '.join(parts)}.")
    stalled = [s for s in tls["stalled"] if not s["server_rst"]]
    if stalled:
        r.add("capture.tls_no_server_hello", Status.WARN,
              f"{len(stalled)} TLS ClientHello(s) never got a ServerHello back: the server's (large) handshake "
              "packets did not arrive, which points at an MTU black hole or a middlebox dropping TLS.")
    reset_after_hello = [s for s in tls["stalled"] if s["server_rst"]]
    if reset_after_hello:
        r.add("capture.tls_reset", Status.WARN,
              f"{len(reset_after_hello)} connection(s) were reset right after the ClientHello: SNI-based blocking or "
              "a non-TLS service.")
    proxied = [fl for fl in flows if fl["app"].get("proxy_status")]
    for fl in proxied[:3]:
        r.evidence.append(f"Proxy answered '{fl['app']['proxy_status']}' to '{fl['app']['proxy_connect']}'"
                          + (f" ({'; '.join(fl['app']['proxy_headers'])})" if fl["app"].get("proxy_headers") else ""))
    for h in summary.get("http", [])[:3]:
        if h.get("status_line"):
            r.evidence.append(f"HTTP on the wire: '{h['request']}' -> '{h['status_line']}'"
                              + (f" (Location: {h['location']})" if h.get("location") else ""))

    # ---------------------------------------------------------------- DNS
    dns = summary["dns"]
    if dns["queries"]:
        r.evidence.append(f"DNS: {dns['queries']} queries, {dns['responses']} responses, average response time "
                          f"{fmt_ms(dns['rtt_ms']['avg'])}.")
    if dns["errors"]:
        errs = sorted({f"{e['name']} {e['type']} -> {e['rcode']} from {e['server']}" for e in dns["errors"]})
        r.add("capture.dns_errors", Status.INFO, "DNS error responses: " + "; ".join(errs[:6])
              + (" …" if len(errs) > 6 else ""))
    if dns["unanswered"]:
        un = sorted({f"{e['name']} {e['type']} to {e['server']}" for e in dns["unanswered"]})
        r.add("capture.dns_unanswered", Status.WARN, f"{len(dns['unanswered'])} DNS quer(ies) never answered: "
              + "; ".join(un[:6]) + (" …" if len(un) > 6 else ""))

    # --------------------------------------------------------------- ICMP
    icmp = summary["icmp"]
    if icmp["ttl_exceeded_from"]:
        r.evidence.append(f"ICMP time-exceeded from {len(icmp['ttl_exceeded_from'])} router(s) (the traceroute "
                          f"hops); echo {icmp['echo_requests']} sent, {icmp['echo_replies']} answered.")
    for fn in icmp["frag_needed"][:3]:
        r.add("capture.icmp_frag_needed", Status.INFO,
              f"Router {fn['router']} sent 'fragmentation needed' (next-hop MTU {fn['mtu'] or '?'}) for packets to "
              f"{fn['for']} ({fn['count']}x).")
    if icmp["unreachable"]:
        names = {0: "net", 1: "host", 3: "port", 9: "net prohibited", 10: "host prohibited", 13: "admin prohibited"}
        parts = sorted({f"{u['router']} says {names.get(u['code'], u['code'])} unreachable for {u['for']}"
                        + (f":{u['port']}" if u.get("port") else "") for u in icmp["unreachable"]})
        r.add("capture.icmp_unreachable", Status.INFO, "ICMP destination unreachable: " + "; ".join(parts[:5]))

    r.evidence.append("Wireshark filters: " + "  |  ".join(f"{n}: {flt}" for n, flt in WIRESHARK_FILTERS))
    problem = next((x for x in r.findings if x.status in (Status.FAIL, Status.WARN)), None)
    if problem:
        r.summary = problem.message
    else:
        r.summary = (f"{summary['packets']} packets captured; nothing abnormal in the TCP, TLS, DNS or ICMP traffic "
                     f"to {focus}.")
        if not r.findings:
            r.add("capture.clean", Status.PASS, r.summary)
    return r


def unavailable(reason: str) -> CheckResult:
    r = CheckResult(ID, LAYER, TITLE)
    r.data = {"capture": {"error": reason}}
    return r.skip(f"Packet capture not taken: {reason}")
