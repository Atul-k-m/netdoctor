"""Cross-check the pure-Python analyzer against Wireshark's own analysis (tshark).

Runs when tshark is on PATH or NETDOCTOR_TSHARK points at it (CI installs it on
Linux). Each scenario capture is analyzed by both, and the counts must match."""

import os
import shutil
import struct
import subprocess

import pytest

from netdoctor.capture import pcapfile, summarize_file

from . import pktgen as g

C, S = "10.0.0.2", "93.184.216.34"
TSHARK = os.environ.get("NETDOCTOR_TSHARK") or shutil.which("tshark")

pytestmark = pytest.mark.skipif(not TSHARK, reason="tshark not available (set NETDOCTOR_TSHARK)")


def tshark_count(path, display_filter: str) -> int:
    proc = subprocess.run([TSHARK, "-n", "-r", str(path), "-Y", display_filter, "-T", "fields", "-e", "frame.number"],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return len([line for line in proc.stdout.splitlines() if line.strip()])


def tshark_values(path, display_filter: str, field: str) -> list[str]:
    proc = subprocess.run([TSHARK, "-n", "-r", str(path), "-Y", display_filter, "-T", "fields", "-e", field],
                          capture_output=True, text=True, timeout=60)
    return [v for line in proc.stdout.splitlines() for v in line.split(",") if v]


def scenario_packets():
    t0 = 1_700_000_000.0
    packets = []
    # 1. retransmission with duplicate ACKs
    c = g.Conversation(C, 50001, S, 443, t0).handshake()
    c.send(b"A" * 1000)
    first_end = c.cseq
    c.send(b"B" * 1000).send(b"C" * 1000)
    end = c.cseq
    c.cseq = first_end
    for _ in range(3):
        c.ack(from_client=False)
    c.send(b"B" * 1000, dt=0.3, advance=False)
    c.cseq = end
    packets += c.packets
    # 2. zero window then server RST
    c = g.Conversation(C, 50002, S, 443, t0 + 10).handshake()
    c.send(b"x" * 500, from_client=False).ack(window=0).ack(window=0).ack(window=8000).rst(from_client=False)
    packets += c.packets
    # 3. TLS 1.2 with a fatal alert from the client
    c = g.Conversation(C, 50003, S, 443, t0 + 20).handshake()
    c.send(g.client_hello("expired.example")).send(g.server_hello_12(), from_client=False).send(g.alert(2, 45))
    packets += c.packets
    # 4. refused connection
    packets += g.Conversation(C, 50004, S, 8443, t0 + 30).syn_refused().packets
    # 5. DNS NXDOMAIN and ICMP frag-needed
    packets.append(g.frame(g.udp(C, "10.0.0.53", 40000, 53, g.dns_query(1, "nope.example")), t0 + 40))
    packets.append(g.frame(g.udp("10.0.0.53", C, 53, 40000, g.dns_response(1, "nope.example", rcode=3)), t0 + 40.01,
                           False))
    orig = g.ipv4(C, S, 1, struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"\x00" * 1372)[:28]
    packets.append(g.frame(g.icmp("172.16.0.1", C, 3, 4, struct.pack("!HH", 0, 1400), orig), t0 + 41, False))
    return packets


def test_counts_match_wireshark(tmp_path):
    path = tmp_path / "scenarios.pcap"
    pcapfile.write_pcap(path, scenario_packets())
    ours = summarize_file(path)
    t = ours["tcp"]["all"]
    theirs = {
        "retransmissions": tshark_count(path, "tcp.analysis.retransmission || tcp.analysis.fast_retransmission"),
        "dup_acks": tshark_count(path, "tcp.analysis.duplicate_ack"),
        "zero_windows": tshark_count(path, "tcp.analysis.zero_window"),
        "rsts": tshark_count(path, "tcp.flags.reset == 1"),
        "out_of_order": tshark_count(path, "tcp.analysis.out_of_order"),
    }
    assert {k: t[k] for k in theirs} == theirs
    assert [a["description"] for a in ours["tls"]["alerts"]] == ["certificate_expired"]
    assert tshark_values(path, "tls.alert_message", "tls.alert_message.desc") == ["45"]
    assert tshark_values(path, "tls.handshake.type == 1", "tls.handshake.extensions_server_name") == ["expired.example"]
    assert len(ours["dns"]["errors"]) == tshark_count(path, "dns.flags.response == 1 && dns.flags.rcode != 0")
    assert len(ours["icmp"]["frag_needed"]) == tshark_count(path, "icmp.type == 3 && icmp.code == 4")
