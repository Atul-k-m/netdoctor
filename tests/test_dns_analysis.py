"""The DNS disagreement patterns, fed synthetic resolver answers."""

from netdoctor.checks.dns import Answer, analyze, parse_hosts


def ok(name, *ips):
    return Answer(name, name, "UDP", "ok", addresses=list(ips), ms=20)


def bad(name, outcome):
    return Answer(name, name, "UDP", outcome, ms=2000 if outcome == "timeout" else 20)


def sysans(outcome="ok", *ips, ms=30):
    return Answer("System resolver", None, "OS", outcome, addresses=list(ips), ms=ms)


def codes(result):
    return [c for c, _s, _m in result.findings]


PUBLIC_OK = [ok("Google 8.8.8.8", "93.184.216.34"), ok("Cloudflare 1.1.1.1", "93.184.216.34")]
DOH_OK = ok("Cloudflare DoH", "93.184.216.34")


def test_healthy():
    a = analyze("example.com", sysans("ok", "93.184.216.34"), [ok("Configured DNS", "93.184.216.34")], PUBLIC_OK, DOH_OK, [])
    assert codes(a) == ["dns.ok"]
    assert a.ip == "93.184.216.34"


def test_nxdomain_everywhere():
    a = analyze("nope.example", sysans("nxdomain"), [bad("Configured", "nxdomain")],
                [bad("G", "nxdomain"), bad("C", "nxdomain")], bad("DoH", "nxdomain"), [])
    assert codes(a) == ["dns.nxdomain"]
    assert a.ip is None


def test_nxdomain_only_locally_keeps_testing_with_public_ip():
    a = analyze("blocked.example", sysans("nxdomain"), [bad("Configured", "nxdomain")], PUBLIC_OK, DOH_OK, [])
    assert codes(a) == ["dns.nxdomain_local"]
    assert a.ip == "93.184.216.34" and a.ip_source == "Google 8.8.8.8"


def test_local_server_timeout():
    a = analyze("example.com", sysans("tempfail"), [bad("Configured", "timeout")], PUBLIC_OK, DOH_OK, [])
    assert codes(a) == ["dns.timeout"]


def test_udp53_blocked_but_doh_works():
    a = analyze("example.com", sysans("timeout"), [bad("Configured", "timeout")],
                [bad("G", "timeout"), bad("C", "timeout")], DOH_OK, [])
    assert codes(a) == ["dns.udp53_blocked"]


def test_enterprise_blocks_public_udp53_only():
    a = analyze("example.com", sysans("ok", "93.184.216.34"), [ok("Configured", "93.184.216.34")],
                [bad("G", "timeout"), bad("C", "timeout")], DOH_OK, [])
    assert codes(a) == ["dns.ok", "dns.public_udp_blocked"]


def test_no_dns_at_all():
    a = analyze("example.com", sysans("timeout"), [bad("Configured", "timeout")],
                [bad("G", "timeout"), bad("C", "timeout")], bad("DoH", "timeout"), [])
    assert codes(a) == ["dns.no_dns"]


def test_servfail_local_vs_dnssec():
    a = analyze("example.com", sysans("servfail"), [bad("Configured", "servfail")], PUBLIC_OK, DOH_OK, [])
    assert codes(a) == ["dns.servfail_local"]
    sf = bad("G", "servfail")
    sf.cd_ok = True
    a = analyze("dnssec-failed.org", sysans("servfail"), [bad("Configured", "servfail")], [sf], bad("DoH", "servfail"), [])
    assert codes(a) == ["dns.dnssec_failure"]


def test_sinkhole_and_split_horizon_and_cgnat():
    a = analyze("ads.example", sysans("ok", "0.0.0.0"), [], PUBLIC_OK, DOH_OK, [])
    assert "dns.sinkhole" in codes(a)
    a = analyze("app.example", sysans("ok", "10.1.2.3"), [], PUBLIC_OK, DOH_OK, [])
    assert "dns.split_horizon" in codes(a)
    a = analyze("app.example", sysans("ok", "100.64.1.7"), [], PUBLIC_OK, DOH_OK, [])
    assert "dns.cgnat_answer" in codes(a)


def test_cdn_answers_differ_is_info_only():
    a = analyze("cdn.example", sysans("ok", "151.101.1.1"), [], PUBLIC_OK, DOH_OK, [])
    assert codes(a) == ["dns.ok", "dns.answers_differ"]


def test_internal_name_and_slow_and_hosts():
    a = analyze("intranet.corp", sysans("ok", "10.0.0.5", ms=1800), [],
                [bad("G", "nxdomain"), bad("C", "nxdomain")], bad("DoH", "nxdomain"), ["10.0.0.5"])
    assert set(codes(a)) == {"dns.ok", "dns.hosts_override", "dns.internal_name", "dns.slow"}


def test_parse_hosts():
    table = parse_hosts("127.0.0.1 localhost\n# comment\n10.0.0.9  app.lab  app   # trailing\n\n")
    assert table["app.lab"] == ["10.0.0.9"] and table["app"] == ["10.0.0.9"] and "comment" not in table
