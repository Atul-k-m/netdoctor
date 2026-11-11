"""MTR interpretation and the path-MTU sweep against simulated paths."""

import random

from netdoctor.checks.path import analyze_hops
from netdoctor.checks.pmtu import OVERHEAD, sweep
from netdoctor.icmp.base import ProbeReply, ProbeStatus


def hop(ttl, host, loss, avg, unreachable=None):
    received = 0 if loss == 100 else 10
    return {"ttl": ttl, "host": host if loss < 100 else None, "loss_pct": loss, "received": received, "sent": 10,
            "avg": None if loss == 100 else avg, "responders": [], "unreachable": unreachable}


def codes(findings):
    return [c for c, _s, _m in findings]


def test_clean_path():
    hops = [hop(1, "192.168.0.1", 0, 2), hop(2, "10.0.0.1", 0, 8), hop(3, "8.8.8.8", 0, 12)]
    assert codes(analyze_hops(hops, "8.8.8.8", True)) == ["path.reached"]


def test_rate_limited_middle_hop_is_not_loss():
    hops = [hop(1, "192.168.0.1", 0, 2), hop(2, "10.0.0.1", 60, 8), hop(3, "8.8.8.8", 0, 12)]
    found = codes(analyze_hops(hops, "8.8.8.8", True))
    assert "path.icmp_ratelimit" in found and "path.loss_from_hop" not in found


def test_real_loss_starts_at_hop():
    hops = [hop(1, "192.168.0.1", 0, 2), hop(2, "10.0.0.1", 0, 8), hop(3, "203.0.113.1", 20, 15),
            hop(4, "198.51.100.7", 25, 20), hop(5, "8.8.8.8", 20, 22)]
    findings = analyze_hops(hops, "8.8.8.8", True)
    loss = next(m for c, _s, m in findings if c == "path.loss_from_hop")
    assert "hop 3 (203.0.113.1)" in loss


def test_latency_jump_and_stop_and_unreachable():
    hops = [hop(1, "192.168.0.1", 0, 2), hop(2, "10.0.0.1", 0, 5), hop(3, "10.9.0.1", 0, 310), hop(4, "10.9.0.9", 0, 312)]
    assert "path.latency_jump" in codes(analyze_hops(hops, "10.9.0.9", True))
    hops = [hop(1, "192.168.0.1", 0, 2), hop(2, "10.0.0.1", 0, 5), hop(3, None, 100, None), hop(4, None, 100, None)]
    assert "path.stops" in codes(analyze_hops(hops, "203.0.113.9", False))
    hops = [hop(1, "192.168.0.1", 0, 2), hop(2, "10.0.0.1", 0, 5, unreachable="host unreachable")]
    assert "path.unreachable" in codes(analyze_hops(hops, "203.0.113.9", False))


def test_silent_path():
    assert codes(analyze_hops([hop(1, None, 100, None)], "1.1.1.1", False)) == ["path.silent"]


# --------------------------------------------------------------------- PMTU


class SimPath:
    """A path whose MTU is `mtu`; bigger DF packets get frag-needed unless `blackhole`."""

    def __init__(self, mtu, blackhole=False, loss=0.0, iface_mtu=1500, seed=1):
        self.mtu, self.blackhole, self.loss, self.iface_mtu = mtu, blackhole, loss, iface_mtu
        self.rng = random.Random(seed)

    def __call__(self, payload):
        packet = payload + OVERHEAD
        if packet > self.iface_mtu:
            return ProbeReply(ProbeStatus.LOCAL_TOO_BIG)
        if self.rng.random() < self.loss:
            return ProbeReply(ProbeStatus.TIMEOUT)
        if packet > self.mtu:
            if self.blackhole:
                return ProbeReply(ProbeStatus.TIMEOUT)
            return ProbeReply(ProbeStatus.FRAG_NEEDED, 5.0, "172.16.0.1", mtu=self.mtu)
        return ProbeReply(ProbeStatus.REPLY, 10.0, "10.0.0.9")


def test_full_mtu():
    res = sweep(SimPath(1500), 1472)
    assert res["outcome"] == "full" and res["pmtu"] == 1500


def test_reduced_mtu_with_frag_needed():
    res = sweep(SimPath(1400), 1472)
    assert res["outcome"] == "reduced" and res["pmtu"] == 1400 and res["reported_mtu"] == 1400
    assert res["frag_from"] == "172.16.0.1"


def test_blackhole():
    res = sweep(SimPath(1400, blackhole=True), 1472)
    assert res["outcome"] == "blackhole" and res["pmtu"] == 1400


def test_random_loss_does_not_fake_a_blackhole():
    for seed in range(30):
        res = sweep(SimPath(1500, loss=0.2, seed=seed), 1472)
        assert res["outcome"] == "full", seed
        res = sweep(SimPath(1400, loss=0.2, seed=seed), 1472)
        assert res["outcome"] == "reduced" and res["pmtu"] == 1400, seed


def test_blackhole_with_loss_still_found():
    for seed in range(30):
        res = sweep(SimPath(1400, blackhole=True, loss=0.2, seed=seed), 1472)
        assert res["outcome"] == "blackhole" and res["pmtu"] == 1400, seed


def test_local_limit_and_no_icmp():
    res = sweep(SimPath(1500, iface_mtu=1420), 1472)
    assert res["outcome"] == "local_limit" and res["pmtu"] == 1420

    def silent(_payload):
        return ProbeReply(ProbeStatus.TIMEOUT)

    assert sweep(silent, 1472)["outcome"] == "no_icmp"
