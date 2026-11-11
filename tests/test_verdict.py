"""The verdict engine on synthetic evidence: each lab fault, and the interactions
between findings (one root cause explaining another, a second independent problem)."""

import json

import pytest

from netdoctor.verdict import RULES, SECTIONS, evaluate, render_markdown

LAYERS = {"local": "L1-L3 Local host", "dns": "L7 DNS", "icmp": "L3 ICMP", "path": "L3 Path", "tcp": "L4 TCP",
          "pmtu": "L3 Path MTU", "tls": "L5-L6 TLS", "http": "L7 HTTP", "capture": "L2-L7 Packets"}
RANK = {"skip": 0, "pass": 1, "info": 2, "warn": 3, "error": 3, "fail": 4}


def make(findings: dict, data: dict | None = None) -> dict:
    checks = []
    for cid, layer in LAYERS.items():
        fl = findings.get(cid, [])
        status = max((s for _c, s in fl), key=RANK.get, default="skip")
        checks.append({
            "id": cid, "layer": layer, "title": cid, "status": status,
            "summary": fl[0][0] + " message" if fl else "skipped", "evidence": [], "tables": [],
            "findings": [{"code": c, "status": s, "message": f"{c} message"} for c, s in fl],
            "commands": [f"cmd-{cid}"], "duration_ms": 12.0, "data": (data or {}).get(cid, {}),
        })
    return {
        "version": "0.1.0", "started_at": "2026-11-11T17:00:00+00:00", "duration_s": 9.9,
        "target": {"url": "https://app.lab.test/", "host": "app.lab.test", "port": 443, "scheme": "https"},
        "environment": {"hostname": "client", "os": "Linux", "target_ip": "10.20.0.10", "egress": {},
                        "proxy": {"proxy_url": None, "source": "direct"}},
        "checks": checks,
    }


UP = {"local": [("local.ok", "pass")], "dns": [("dns.ok", "pass")], "icmp": [("icmp.ok", "pass")],
      "path": [("path.reached", "pass")], "tcp": [("tcp.open", "pass")], "pmtu": [("pmtu.ok", "pass")],
      "tls": [("tls.ok", "pass")], "http": [("http.ok", "pass")]}


def scenario(**over):
    f = {k: list(v) for k, v in UP.items()}
    f.update(over)
    return f


LAB_FAULTS = {
    "dns_nxdomain": scenario(dns=[("dns.nxdomain", "fail"), ("dns.internal_name", "info")], icmp=[], path=[], tcp=[],
                             pmtu=[], tls=[], http=[], capture=[("capture.dns_errors", "info")]),
    "dns_timeout": scenario(dns=[("dns.timeout", "fail")], capture=[("capture.dns_unanswered", "warn")]),
    "tcp_refused": scenario(tcp=[("tcp.refused", "fail")], tls=[], http=[], capture=[("capture.syn_rst", "info")]),
    "tcp_filtered": scenario(tcp=[("tcp.filtered", "fail"), ("tcp.port_specific_drop", "info")], tls=[], http=[],
                             capture=[("capture.syn_unanswered", "warn")]),
    "path_loss_latency": scenario(icmp=[("icmp.loss", "fail"), ("icmp.latency_high", "warn")],
                                  path=[("path.reached", "pass"), ("path.loss_from_hop", "fail")],
                                  capture=[("capture.retransmissions", "warn")]),
    "pmtu_blackhole": scenario(pmtu=[("pmtu.blackhole", "fail")], tls=[("tls.handshake_timeout", "fail")],
                               http=[("http.timeout", "fail")], capture=[("capture.tls_no_server_hello", "warn")],
                               local=[("local.tunnel_adapter", "info")]),
    "tls_expired": scenario(tls=[("tls.expired", "fail")], capture=[("capture.tls_alert", "warn")]),
    "tls_hostname_mismatch": scenario(tls=[("tls.hostname_mismatch", "fail")]),
    "tls_untrusted_ca": scenario(tls=[("tls.intercepted_untrusted", "fail")]),
    "proxy_auth_required": scenario(tcp=[("tcp.filtered", "info"), ("tcp.proxy_ok", "pass")],
                                    tls=[("tls.proxy_refused_connect", "warn")],
                                    http=[("http.proxy_auth_required", "fail")]),
    "http_upstream_error": scenario(http=[("http.bad_gateway", "fail")]),
    "captive_portal": scenario(tls=[("tls.hostname_mismatch", "fail")], http=[("http.captive_portal", "fail")]),
}


@pytest.mark.parametrize("expected", sorted(LAB_FAULTS))
def test_each_lab_fault_names_its_root_cause(expected):
    v = evaluate(make(LAB_FAULTS[expected]))
    assert v["category"] == expected, (v["root_cause_id"], v["alternatives"])
    assert v["confidence"] >= 0.85 and v["confidence_label"] == "High"
    assert v["other_findings"] == [], v["other_findings"]  # everything else is explained by the root cause


def test_healthy_run_is_no_fault_and_filtered_icmp_is_a_note():
    v = evaluate(make(scenario(icmp=[("icmp.no_reply", "warn")], path=[("path.stops", "warn")],
                               http=[("http.ok", "pass"), ("http.no_hsts", "info")])))
    assert v["root_cause_id"] == "no_fault"
    assert v["other_findings"] == []
    assert {n["code"] for n in v["notes"]} == {"icmp.no_reply", "path.stops"}


def test_no_reply_without_reaching_service_is_not_benign():
    v = evaluate(make(scenario(icmp=[("icmp.no_reply", "warn")], tcp=[("tcp.filtered", "fail")], tls=[], http=[])))
    assert v["category"] == "tcp_filtered"
    assert v["contradicting"] and v["contradicting"][0]["code"] == "icmp.no_reply"


def test_variants_share_a_category():
    assert evaluate(make(scenario(dns=[("dns.no_dns", "fail")])))["category"] == "dns_timeout"
    assert evaluate(make(scenario(dns=[("dns.udp53_blocked", "fail")])))["category"] == "dns_timeout"
    assert evaluate(make(scenario(tls=[("tls.untrusted", "fail")])))["category"] == "tls_untrusted_ca"


def test_lower_layer_root_cause_explains_everything_above():
    v = evaluate(make(scenario(local=[("local.apipa", "fail")], dns=[("dns.no_dns", "fail")],
                               tcp=[("tcp.filtered", "fail")], tls=[], http=[])))
    assert v["root_cause_id"] == "local_dhcp_failed" and v["other_findings"] == []
    assert any(a["id"] == "dns_no_dns" and a["explained_by_root_cause"] for a in v["alternatives"])


def test_captive_portal_suppresses_tls_rule():
    v = evaluate(make(LAB_FAULTS["captive_portal"]))
    assert "tls_hostname_mismatch" not in {a["id"] for a in v["alternatives"]}


def test_blackhole_beats_tls_stall_and_stall_alone_is_medium():
    assert evaluate(make(LAB_FAULTS["pmtu_blackhole"]))["root_cause_id"] == "pmtu_blackhole"
    v = evaluate(make(scenario(tls=[("tls.handshake_timeout", "fail")], pmtu=[("pmtu.reduced", "info")])))
    assert v["root_cause_id"] == "tls_handshake_stall" and v["confidence_label"] == "Medium"


def test_hosts_override_pointing_at_wrong_server():
    v = evaluate(make(scenario(dns=[("dns.ok", "pass"), ("dns.hosts_override", "warn")], tcp=[("tcp.refused", "fail")],
                               tls=[], http=[])))
    assert v["root_cause_id"] == "dns_hosts_override"


def test_clock_skew_explains_certificate_dates():
    data = {"http": {"clock_skew_s": -86400 * 400}}
    v = evaluate(make(scenario(tls=[("tls.not_yet_valid", "fail")], http=[("http.ok", "pass"),
                                                                           ("http.clock_skew", "warn")]), data))
    assert v["root_cause_id"] == "client_clock_skew"


def test_proxy_generated_502_is_a_proxy_problem():
    data = {"http": {"final": {"status": 502, "generated_by_proxy": "X-Squid-Error: ERR_CONNECT_FAIL 111"}}}
    v = evaluate(make(LAB_FAULTS["http_upstream_error"], data))
    assert v["category"] == "proxy_upstream_error"


def test_second_independent_problem_stays_visible():
    v = evaluate(make(scenario(tls=[("tls.expired", "fail")], dns=[("dns.ok", "pass"), ("dns.slow", "warn")])))
    assert v["root_cause_id"] == "tls_expired"
    assert [o["code"] for o in v["other_findings"]] == ["dns.slow"]


def test_unclassified_and_weak_signals():
    v = evaluate(make(scenario(http=[("http.something_new", "fail")])))
    assert v["root_cause_id"] == "unclassified" and "http.something_new" in v["explanation"]
    v = evaluate(make(scenario(tls=[("tls.ok", "pass"), ("tls.intercepted", "warn")])))
    assert v["root_cause_id"] == "no_fault"  # inspection is noted, not blamed, when everything works
    assert any(a["id"] == "tls_inspection" for a in v["alternatives"])


def test_templates_fill_facts():
    data = {"tls": {"served_chain": [{"subject_cn": "app.lab.test", "issuer_cn": "Lab CA", "not_after":
                                      "2024-01-01T00:00:00+00:00", "not_before": "2023-01-01T00:00:00+00:00",
                                      "san_dns": ["app.lab.test"], "san_ip": []}]}}
    v = evaluate(make(LAB_FAULTS["tls_expired"], data))
    assert "expired on 2024-01-01" in v["explanation"] and "Lab CA" in v["explanation"]
    assert "{" not in v["explanation"] and "?" not in v["title"]


@pytest.mark.parametrize("name", ["tls_expired", "captive_portal", "dns_nxdomain"])
def test_markdown_has_every_kb_section(name):
    md = render_markdown(make(LAB_FAULTS[name]), evaluate(make(LAB_FAULTS[name])))
    for section in SECTIONS:
        assert f"## {section}" in md
    assert md.startswith("# ")


def test_markdown_healthy_and_notes():
    rep = make(scenario(icmp=[("icmp.no_reply", "warn")]))
    md = render_markdown(rep, evaluate(rep))
    assert "## Notes" in md and "No fault" in md.splitlines()[0]


def test_rule_table_is_consistent():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))
    for r in RULES:
        assert r.any_of and r.owner and r.resolution and r.explanation, r.id
        assert 0 < r.base < 1


def test_report_command_round_trip(tmp_path):
    from typer.testing import CliRunner

    from netdoctor.cli import app

    rep = make(LAB_FAULTS["tcp_refused"])
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"verdict": {}, "diagnosis": rep}), encoding="utf-8")
    result = CliRunner().invoke(app, ["report", str(path)])
    assert result.exit_code == 0, result.output
    assert "## Root cause" in (tmp_path / "report.md").read_text(encoding="utf-8")
