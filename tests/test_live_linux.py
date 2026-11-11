"""Linux-only: exercise the real ICMP datagram-socket prober against loopback.
Runs in CI on ubuntu-latest; skipped elsewhere."""

import sys

import pytest

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux ICMP engine")


def test_prober_selected_and_loopback_reply():
    from netdoctor.icmp import ProbeStatus, get_prober

    prober = get_prober()
    rep = prober.probe("127.0.0.1", ttl=64, size=56, timeout=1.0)
    assert rep.status == ProbeStatus.REPLY, (prober.name, rep)
    assert rep.responder == "127.0.0.1" and rep.rtt_ms is not None


def test_df_probe_on_loopback():
    from netdoctor.icmp import ProbeStatus, get_prober

    rep = get_prober().probe("127.0.0.1", ttl=64, size=1472, df=True, timeout=1.0)
    assert rep.status == ProbeStatus.REPLY  # loopback MTU is 65536


def test_full_diagnose_against_loopback(tmp_path):
    import json
    import subprocess

    out = tmp_path / "r.json"
    proc = subprocess.run([sys.executable, "-m", "netdoctor", "diagnose", "127.0.0.1:1", "--quick", "--json", str(out)],
                          capture_output=True, text=True, timeout=180)
    data = json.loads(out.read_text())
    by_id = {c["id"]: c for c in data["checks"]}
    assert by_id["icmp"]["status"] == "pass", by_id["icmp"]
    assert by_id["tcp"]["findings"][0]["code"] == "tcp.refused"
    assert proc.returncode == 1  # a FAIL was found
