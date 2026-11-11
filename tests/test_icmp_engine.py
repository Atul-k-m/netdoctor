import socket
import struct

from netdoctor.checks.icmp import guess_hops, summarize
from netdoctor.icmp.base import ProbeReply, ProbeStatus
from netdoctor.icmp.linux import build_echo, checksum, parse_extended_err, reply_from_error
from netdoctor.icmp.ping_cmd import parse_iputils
from netdoctor.netutil import rtt_stats


def test_checksum_and_echo():
    pkt = build_echo(seq=0x1234, size=16)
    assert pkt[0] == 8 and len(pkt) == 24
    assert checksum(pkt) == 0  # a correct checksum makes the sum fold to zero
    assert struct.unpack("!H", pkt[6:8])[0] == 0x1234


def _ee(errno_, origin, type_, code, info, offender):
    ee = struct.pack("=IBBBBII", errno_, origin, type_, code, 0, info, 0)
    sin = struct.pack("=HH4s8x", socket.AF_INET, 0, socket.inet_aton(offender))
    return ee + sin


def test_extended_err_time_exceeded():
    ee = parse_extended_err(_ee(113, 2, 11, 0, 0, "10.0.0.1"))
    rep = reply_from_error(ee, 4.2)
    assert rep.status == ProbeStatus.TTL_EXCEEDED and rep.responder == "10.0.0.1" and rep.rtt_ms == 4.2


def test_extended_err_frag_needed_carries_mtu():
    rep = reply_from_error(parse_extended_err(_ee(90, 2, 3, 4, 1400, "172.16.0.1")), 9.0)
    assert rep.status == ProbeStatus.FRAG_NEEDED and rep.mtu == 1400 and rep.responder == "172.16.0.1"


def test_extended_err_admin_prohibited_and_local():
    rep = reply_from_error(parse_extended_err(_ee(113, 2, 3, 13, 0, "10.9.9.9")), 1.0)
    assert rep.status == ProbeStatus.UNREACHABLE and "prohibited" in rep.detail
    rep = reply_from_error(parse_extended_err(_ee(90, 1, 0, 0, 1500, "0.0.0.0")), 0.1)
    assert rep.status == ProbeStatus.LOCAL_TOO_BIG and rep.mtu == 1500


def test_iputils_parsing():
    assert parse_iputils("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms").status == ProbeStatus.REPLY
    r = parse_iputils("From 10.0.0.1 icmp_seq=1 Time to live exceeded", 3.0)
    assert r.status == ProbeStatus.TTL_EXCEEDED and r.responder == "10.0.0.1"
    r = parse_iputils("From 172.16.0.1 icmp_seq=1 Frag needed and DF set (mtu = 1400)", 3.0)
    assert r.status == ProbeStatus.FRAG_NEEDED and r.mtu == 1400
    r = parse_iputils("ping: local error: message too long, mtu=1500")
    assert r.status == ProbeStatus.LOCAL_TOO_BIG and r.mtu == 1500
    assert parse_iputils("From 10.0.0.1 icmp_seq=1 Destination Host Unreachable").status == ProbeStatus.UNREACHABLE
    assert parse_iputils("1 packets transmitted, 0 received, 100% packet loss").status == ProbeStatus.TIMEOUT


def test_rtt_stats_and_jitter():
    st = rtt_stats([10.0, 20.0, 10.0, 20.0])
    assert st["min"] == 10 and st["max"] == 20 and st["avg"] == 15 and st["jitter"] == 10
    assert rtt_stats([])["avg"] is None


def test_summarize_loss():
    replies = [ProbeReply(ProbeStatus.REPLY, 300.0, "1.2.3.4", ttl=58)] * 8 + [ProbeReply(ProbeStatus.TIMEOUT)] * 2
    st = summarize(replies, 10)
    assert st["loss_pct"] == 20.0 and st["received"] == 8 and st["reply_ttl"] == 58


def test_guess_hops():
    assert guess_hops(57) == (64, 7)
    assert guess_hops(116) == (128, 12)
    assert guess_hops(250) == (255, 5)
    assert guess_hops(None) is None
