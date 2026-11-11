"""The pcap reader and the analyzer, on captures built from scratch."""

import struct

import pytest

from netdoctor.capture import build_result, pcapfile, summarize_file
from netdoctor.capture.session import build_filter, parse_dumpcap_interfaces
from netdoctor.models import Status

from . import pktgen as g

C, S = "10.0.0.2", "93.184.216.34"


def write(tmp_path, packets, name="t.pcap"):
    p = tmp_path / name
    pcapfile.write_pcap(p, packets)
    return p


def codes(r):
    return {f.code for f in r.findings}


def test_clean_tls12_session(tmp_path):
    conv = g.Conversation(C, 50000, S, 443).handshake(rtt=0.025)
    conv.send(g.client_hello("app.example.com"))
    conv.send(g.server_hello_12(certs=3), from_client=False, dt=0.03)
    conv.ack()
    conv.send(g.tls_record(23, b"\x55" * 100)).send(g.tls_record(23, b"\x66" * 400), from_client=False).ack()
    conv.fin()
    s = summarize_file(write(tmp_path, conv.packets), [(S, 443)])
    t = s["tcp"]["focus_totals"]
    assert t["handshakes_completed"] == 1 and t["retransmissions"] == 0 and t["rsts"] == 0
    assert 24 < t["handshake_rtt_ms"]["avg"] < 26
    hs = s["tls"]["handshakes"][0]
    assert hs["sni"] == "app.example.com" and hs["version"] == "TLSv1.2" and hs["cipher"] == "ECDHE-RSA-AES128-GCM-SHA256"
    assert hs["certificates"] == 3 and hs["client_alpn"] == ["h2", "http/1.1"]
    flow = s["tcp"]["flows_detail"][0]
    assert flow["mss_client"] == 1460 and flow["mss_server"] == 1400 and flow["fin_client"] and flow["fin_server"]
    r = build_result(s, {"tool": "test"})
    assert r.status == Status.PASS and "capture.handshakes" in codes(r)


def test_retransmission_and_dup_acks(tmp_path):
    conv = g.Conversation(C, 50001, S, 443).handshake()
    conv.send(b"A" * 1000)
    first_end = conv.cseq
    conv.send(b"B" * 1000)  # lost on the way to the server
    conv.send(b"C" * 1000)
    end = conv.cseq
    conv.cseq = first_end
    for _ in range(3):  # the server keeps acknowledging only the first segment
        conv.ack(from_client=False)
    conv.send(b"B" * 1000, dt=0.2, advance=False)  # the same bytes again = retransmission
    conv.cseq = end
    s = summarize_file(write(tmp_path, conv.packets), [(S, 443)])
    t = s["tcp"]["focus_totals"]
    assert t["retransmissions"] == 1
    assert t["dup_acks"] == 2  # the first ACK is new, the next two repeat it
    assert "capture.retransmissions" in codes(build_result(s))


def test_out_of_order_is_not_retransmission(tmp_path):
    conv = g.Conversation(C, 50002, S, 443).handshake()
    base = conv.cseq
    conv.cseq = base + 100
    conv.send(b"2" * 100)  # arrives first
    conv.cseq = base
    conv.send(b"1" * 100, advance=False)  # fills the gap
    s = summarize_file(write(tmp_path, conv.packets), [(S, 443)])
    t = s["tcp"]["focus_totals"]
    assert t["out_of_order"] == 1 and t["retransmissions"] == 0


def test_refused_and_unanswered_syn(tmp_path):
    refused = g.Conversation(C, 50003, S, 443).syn_refused()
    silent = g.Conversation(C, 50004, S, 443, t0=1_700_000_100.0).syn_only(tries=3)
    scan = g.Conversation(C, 50005, S, 23, t0=1_700_000_200.0).syn_only(tries=1)
    s = summarize_file(write(tmp_path, refused.packets + silent.packets + scan.packets), [(S, 443)])
    t = s["tcp"]["focus_totals"]
    assert t["refused"] == 1 and t["unanswered_syn"] == 1 and t["syn_retransmissions"] == 2
    assert s["tcp"]["all"]["unanswered_syn"] == 2  # the scan flow counts only overall
    r = build_result(s)
    assert {"capture.syn_rst", "capture.syn_unanswered"} <= codes(r)
    assert any("port scan" in e for e in r.evidence)


def test_zero_window_and_server_reset(tmp_path):
    conv = g.Conversation(C, 50006, S, 443).handshake()
    conv.send(b"x" * 500, from_client=False).ack(window=0).ack(window=0).ack(window=8000)
    conv.rst(from_client=False)
    s = summarize_file(write(tmp_path, conv.packets), [(S, 443)])
    t = s["tcp"]["focus_totals"]
    assert t["zero_windows"] == 2 and t["rst_after_handshake_by_server"] == 1
    assert {"capture.zero_window", "capture.server_reset"} <= codes(build_result(s))


def test_tls_alert_and_split_record_reassembly(tmp_path):
    conv = g.Conversation(C, 50007, S, 443).handshake()
    hello = g.client_hello("expired.example")
    conv.send(hello[:40]).send(hello[40:])  # ClientHello split across two segments
    conv.send(g.server_hello_12(), from_client=False)
    conv.send(g.alert(2, 45))  # client: fatal certificate_expired
    s = summarize_file(write(tmp_path, conv.packets), [(S, 443)])
    hs = s["tls"]["handshakes"][0]
    assert hs["sni"] == "expired.example"
    assert s["tls"]["alerts"][0]["description"] == "certificate_expired" and s["tls"]["alerts"][0]["from"] == "client"
    r = build_result(s)
    assert "capture.tls_alert" in codes(r)
    assert "certificate_expired" in r.finding("capture.tls_alert").message


def test_tls_stall_points_at_blackhole(tmp_path):
    conv = g.Conversation(C, 50008, S, 443).handshake()
    conv.send(g.client_hello("vpn.example"))
    conv.ack(from_client=False)  # server ACKs but its big ServerHello never arrives
    s = summarize_file(write(tmp_path, conv.packets), [(S, 443)])
    assert s["tls"]["stalled"] and "capture.tls_no_server_hello" in codes(build_result(s))


def test_proxy_407_seen_on_the_wire(tmp_path):
    conv = g.Conversation(C, 50009, "10.0.0.3", 3128).handshake()
    conv.send(b"CONNECT app.example.com:443 HTTP/1.1\r\nHost: app.example.com:443\r\n\r\n")
    conv.send(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"x\"\r\n\r\n",
              from_client=False)
    s = summarize_file(write(tmp_path, conv.packets), [("10.0.0.3", 3128)])
    app = s["tcp"]["flows_detail"][0]["app"]
    assert app["proxy_status"].startswith("HTTP/1.1 407") and "Proxy-Authenticate" in app["proxy_headers"][0]
    assert any("407" in e for e in build_result(s).evidence)


def test_http_status_on_the_wire(tmp_path):
    conv = g.Conversation(C, 50010, S, 80).handshake()
    conv.send(b"GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n")
    conv.send(b"HTTP/1.1 502 Bad Gateway\r\nServer: nginx\r\nContent-Length: 0\r\n\r\n", from_client=False)
    s = summarize_file(write(tmp_path, conv.packets), [(S, 80)])
    assert s["http"][0]["status"] == 502 and s["http"][0]["host"] == "app.example.com"


def test_dns_errors_and_unanswered(tmp_path):
    t = 1_700_000_000.0
    pk = [
        g.frame(g.udp(C, "10.0.0.53", 40000, 53, g.dns_query(1, "nope.example")), t),
        g.frame(g.udp("10.0.0.53", C, 53, 40000, g.dns_response(1, "nope.example", rcode=3)), t + 0.01, False),
        g.frame(g.udp(C, "10.0.0.53", 40001, 53, g.dns_query(2, "ok.example")), t + 0.1),
        g.frame(g.udp("10.0.0.53", C, 53, 40001, g.dns_response(2, "ok.example", answer_ip="1.2.3.4")), t + 0.12, False),
        g.frame(g.udp(C, "10.0.0.53", 40002, 53, g.dns_query(3, "slow.example")), t + 0.2),
        g.frame(g.icmp(C, "10.0.0.99", 8, 0, struct.pack("!HH", 7, 1)), t + 5.0),  # keeps the capture going 5 s
    ]
    s = summarize_file(write(tmp_path, pk))
    assert s["dns"]["queries"] == 3 and s["dns"]["responses"] == 2
    assert s["dns"]["errors"] == [{"name": "nope.example", "type": "A", "server": "10.0.0.53", "rcode": "NXDOMAIN"}]
    assert s["dns"]["unanswered"][0]["name"] == "slow.example"
    assert {"capture.dns_errors", "capture.dns_unanswered"} <= codes(build_result(s))


def test_icmp_errors(tmp_path):
    t = 1_700_000_000.0
    orig = g.ipv4(C, S, 1, struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"\x00" * 1372)[:28]
    pk = [
        g.frame(g.icmp("10.9.0.1", C, 11, 0, body=orig), t, False),
        g.frame(g.icmp("172.16.0.1", C, 3, 4, struct.pack("!HH", 0, 1400), orig), t + 0.1, False),
        g.frame(g.icmp("10.9.0.2", C, 3, 13, body=orig), t + 0.2, False),
    ]
    s = summarize_file(write(tmp_path, pk))
    assert s["icmp"]["ttl_exceeded_from"] == {"10.9.0.1": 1}
    assert s["icmp"]["frag_needed"][0]["mtu"] == 1400 and s["icmp"]["frag_needed"][0]["for"] == S
    assert s["icmp"]["unreachable"][0]["code"] == 13
    assert {"capture.icmp_frag_needed", "capture.icmp_unreachable"} <= codes(build_result(s))


def _pcapng(packets, linktype, tsresol=None, big_endian=False):
    e = ">" if big_endian else "<"

    def block(btype, body):
        body += b"\x00" * (-len(body) % 4)
        total = len(body) + 12
        return struct.pack(e + "II", btype, total) + body + struct.pack(e + "I", total)

    out = block(0x0A0D0D0A, struct.pack(e + "IHHq", 0x1A2B3C4D, 1, 0, -1))
    opts = b""
    if tsresol is not None:
        opts = struct.pack(e + "HH", 9, 1) + bytes([tsresol]) + b"\x00" * 3 + struct.pack(e + "HH", 0, 0)
    out += block(1, struct.pack(e + "HHI", linktype, 0, 65535) + opts)
    tick = 10.0 ** -(tsresol if tsresol is not None else 6)
    for p in packets:
        ts = int(round(p.ts / tick))
        out += block(6, struct.pack(e + "IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(p.data), len(p.data)) + p.data)
    return out


@pytest.mark.parametrize("big_endian", [False, True])
def test_pcapng_and_nanosecond_resolution(tmp_path, big_endian):
    conv = g.Conversation(C, 50011, S, 443).handshake(rtt=0.0123)
    p = tmp_path / "t.pcapng"
    p.write_bytes(_pcapng(conv.packets, pcapfile.LINKTYPE_ETHERNET, tsresol=9, big_endian=big_endian))
    s = summarize_file(p, [(S, 443)])
    assert s["format"] == "pcapng" and s["tcp"]["focus_totals"]["handshakes_completed"] == 1
    assert abs(s["tcp"]["focus_totals"]["handshake_rtt_ms"]["avg"] - 12.3) < 0.01


def test_linux_cooked_sll2_and_vlan(tmp_path):
    ip = g.tcp(C, S, 50012, 443, 1, 0, "S", mss=1460)
    sll2 = struct.pack("!HHIHBB8s", 0x0800, 0, 2, 1, 0, 6, b"\x02" * 8) + ip
    vlan = g.ether(g.tcp(S, C, 443, 50012, 9, 2, "SA", mss=1400), g.SERVER_MAC, g.CLIENT_MAC, vlan=100)
    p1 = write(tmp_path, [pcapfile.Packet(1.0, pcapfile.LINKTYPE_LINUX_SLL2, sll2, len(sll2))], "a.pcap")
    p2 = write(tmp_path, [pcapfile.Packet(1.5, pcapfile.LINKTYPE_ETHERNET, vlan, len(vlan))], "b.pcap")
    assert summarize_file(p1)["tcp"]["flows_detail"][0]["mss_client"] == 1460
    assert summarize_file(p2)["tcp"]["flows_detail"][0]["mss_server"] == 1400


def test_truncated_file_is_tolerated(tmp_path):
    conv = g.Conversation(C, 50013, S, 443).handshake()
    p = write(tmp_path, conv.packets)
    data = p.read_bytes()
    p.write_bytes(data[:-10])  # the capture tool was killed mid-write
    s = summarize_file(p)
    assert s["truncated"] and s["packets"] == 2


def test_not_a_capture(tmp_path):
    p = tmp_path / "x.pcap"
    p.write_bytes(b"hello world, definitely not a pcap")
    with pytest.raises(pcapfile.PcapError):
        summarize_file(p)


def test_empty_capture(tmp_path):
    s = summarize_file(write(tmp_path, []))
    assert "capture.empty" in codes(build_result(s))


def test_filter_and_interface_parsing():
    assert build_filter(["1.2.3.4", "1.2.3.4", "8.8.8.8"]) == "icmp or icmp6 or port 53 or host 1.2.3.4 or host 8.8.8.8"
    devs = parse_dumpcap_interfaces("1. \\Device\\NPF_{ABC} (Wi-Fi)\n2. \\Device\\NPF_Loopback (Adapter for loopback "
                                    "traffic capture)\n3. etwdump (Event Tracing for Windows (ETW) reader)\n")
    assert devs[0] == ("1", "\\Device\\NPF_{ABC}", "Wi-Fi")
    assert devs[1][1] == "\\Device\\NPF_Loopback"
