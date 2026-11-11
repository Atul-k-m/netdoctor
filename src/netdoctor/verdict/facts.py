"""Pull the handful of values the verdict and the report talk about out of the
evidence JSON (Diagnosis.to_dict()), so rules and templates never dig through it."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class SafeDict(dict):
    """str.format_map helper: a missing fact renders as '?' instead of raising."""

    def __missing__(self, key: str) -> str:
        return "?"


def checks_by_id(report: dict) -> dict[str, dict]:
    return {c["id"]: c for c in report.get("checks", [])}


def findings(report: dict) -> dict[str, dict]:
    """code -> {"check", "status", "message"} (first occurrence wins)."""
    out: dict[str, dict] = {}
    for c in report.get("checks", []):
        for f in c.get("findings", []):
            out.setdefault(f["code"], {"check": c["id"], "status": f["status"], "message": f["message"]})
    return out


def extract(report: dict) -> SafeDict:
    checks = checks_by_id(report)
    env = report.get("environment", {})
    tgt = report.get("target", {})
    f: dict[str, Any] = {
        "target": tgt.get("url") or f"{tgt.get('host')}:{tgt.get('port')}",
        "host": tgt.get("host"),
        "port": tgt.get("port"),
        "scheme": tgt.get("scheme"),
        "ip": env.get("target_ip"),
        "ip_source": env.get("target_ip_source"),
        "client": env.get("hostname"),
        "os": env.get("os"),
        "started_at": report.get("started_at"),
    }
    proxy = env.get("proxy") or {}
    f["proxy"] = proxy.get("proxy_url") or "DIRECT"
    f["proxy_source"] = proxy.get("source")
    egress = env.get("egress") or {}
    f["egress_if"] = egress.get("interface")
    f["egress_ip"] = egress.get("source_ip")
    f["gateway"] = egress.get("gateway")

    local = checks.get("local", {}).get("data", {})
    f["dns_servers"] = ", ".join(local.get("dns_servers") or []) or "?"
    gw = local.get("default_gateways") or []
    if gw and not f["gateway"]:
        f["gateway"] = gw[0].get("gateway")
    f["agents"] = ", ".join(label for _p, label in local.get("agents") or []) or "none detected"

    dns = checks.get("dns", {}).get("data", {})
    conf = dns.get("configured") or []
    f["dns_configured"] = ", ".join(a.get("server") or "?" for a in conf) or f["dns_servers"]
    pub = [ip for a in (dns.get("public") or []) + ([dns["doh"]] if dns.get("doh") else []) for ip in a.get("addresses", [])]
    f["public_answer"] = ", ".join(dict.fromkeys(pub)) or "none"
    f["system_answer"] = ", ".join((dns.get("system") or {}).get("addresses") or []) or "none"

    icmp = checks.get("icmp", {}).get("data", {})
    f["loss_pct"] = icmp.get("loss_pct")
    f["rtt_avg"] = icmp.get("avg")
    f["jitter"] = icmp.get("jitter")
    parts = []
    if icmp.get("loss_pct"):
        parts.append(f"{icmp['loss_pct']:.0f}% packet loss")
    if icmp.get("avg") is not None and icmp["avg"] > 150:
        parts.append(f"{icmp['avg']:.0f} ms average RTT")
    f["impairment"] = " and ".join(parts) or "packet loss / latency"

    tcp = checks.get("tcp", {}).get("data", {})
    f["tcp_state"] = (tcp.get("direct") or {}).get("state")

    pm = checks.get("pmtu", {}).get("data", {})
    f["pmtu"] = pm.get("pmtu")
    f["pmtu_mss"] = (pm["pmtu"] - 40) if pm.get("pmtu") else "?"
    f["pmtu_fail_size"] = (pm["smallest_failed_payload"] + 28) if pm.get("smallest_failed_payload") else "?"
    f["iface_mtu"] = pm.get("interface_mtu")

    tls = checks.get("tls", {}).get("data", {})
    leaf = (tls.get("served_chain") or [{}])[0] if tls.get("served_chain") else {}
    chain = tls.get("verified_chain") or tls.get("served_chain") or []
    f["tls_version"] = tls.get("version")
    f["cert_subject"] = leaf.get("subject_cn") or leaf.get("subject")
    f["cert_issuer"] = leaf.get("issuer_cn") or leaf.get("issuer")
    f["cert_root"] = (chain[-1].get("subject_cn") or chain[-1].get("subject")) if chain else "?"
    f["cert_sans"] = ", ".join((leaf.get("san_dns") or []) + (leaf.get("san_ip") or [])) or "?"
    f["cert_not_after"] = (leaf.get("not_after") or "?")[:10]
    f["cert_not_before"] = (leaf.get("not_before") or "?")[:10]
    if leaf.get("not_after"):
        try:
            days = (datetime.fromisoformat(leaf["not_after"]) - datetime.now(timezone.utc)).days
            f["cert_days_left"] = days
            f["cert_expired_days"] = -days
        except ValueError:
            pass
    f["tls_vendor"] = (tls.get("trust") or {}).get("vendor") or "an inspecting proxy"

    http = checks.get("http", {}).get("data", {})
    final = http.get("final") or {}
    f["http_status"] = final.get("status")
    f["http_reason"] = final.get("reason")
    f["http_server"] = final.get("server") or "unknown"
    f["http_by_proxy"] = final.get("generated_by_proxy")
    probe = http.get("proxy_probe") or {}
    f["proxy_status"] = f"{probe.get('status')} {probe.get('reason')}" if probe else "?"
    f["proxy_auth"] = ", ".join(v for k, v in probe.get("headers", []) if k.lower() == "proxy-authenticate") or "none"
    captive = http.get("captive") or {}
    f["captive_signals"] = "; ".join(captive.get("signals") or []) or "?"
    f["clock_skew_min"] = round(abs(http.get("clock_skew_s") or 0) / 60)
    f["clock_skew_s"] = http.get("clock_skew_s")

    cap = checks.get("capture", {}).get("data", {})
    summ = cap.get("summary") or {}
    f["pcap"] = (cap.get("capture") or {}).get("file")
    f["pcap_packets"] = summ.get("packets")
    f["retransmissions"] = ((summ.get("tcp") or {}).get("focus_totals") or {}).get("retransmissions")
    return SafeDict(f)
