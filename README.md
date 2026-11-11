# NetDoctor

NetDoctor works a "this site doesn't load" ticket the way a technical support engineer does. It takes a failing URL or
host and tests it layer by layer from the local machine up to HTTP. It records the evidence for every result, along
with the manual commands that reproduce it, then names the root cause with a confidence and the next step, and writes
the ticket notes as a knowledge-base style incident report.

```
netdoctor diagnose https://app.example.com/login
```

Runs on Windows and Linux with Python 3.10+. The checks need no administrator or root rights: ICMP goes through the
Windows `IcmpSendEcho` API, or unprivileged ICMP sockets on Linux. Packet capture is the one exception. It needs an
elevated terminal or root, and without one it is skipped with the reason.

> **Status:** phases 1–3 of 7 are done (the diagnostic CLI, packet capture and the verdict engine). The Docker fault
> lab, benchmark and IPsec tunnel check are still to come. See [Roadmap](#roadmap).

## What it checks

| # | Layer | Check | Evidence it collects |
|---|-------|-------|----------------------|
| 1 | L1–L3 | **Local** | Interfaces, IPs, MTU; default gateway and routes; ARP entry for the gateway (plus a ping); DNS servers; APIPA; VPN/security agents (Zscaler, Netskope, GlobalProtect, AnyConnect…); proxy settings from environment variables, WinINET (browser), WinHTTP (services) and the PAC URL (downloaded and evaluated), plus WPAD |
| 2 | L7 | **DNS** | System resolver (what apps see) compared with direct queries to the configured servers, 8.8.8.8, 1.1.1.1 and DoH (`https://1.1.1.1/dns-query`). Catches NXDOMAIN, SERVFAIL (with a DNSSEC CD-bit retry), NODATA, REFUSED, timeouts, UDP/53 blocked, sinkholes, split-horizon, 100.64/10 (ZPA-style) answers and hosts-file overrides |
| 3 | L3 | **ICMP** | Loss, RTT min/avg/max, jitter, reply TTL and a hop-count guess |
| 4 | L3 | **Path** | Egress interface and next hop; traceroute with every TTL probed in parallel; MTR-style per-hop loss and latency (Loss%, Snt, Last, Avg, Best, Wrst, StDev) read like an engineer would: rate-limiting vs real loss, where loss starts, latency jumps, routing loops |
| 5 | L4 | **TCP** | Open / refused (RST) / filtered (silence) / unreachable (ICMP); handshake time; FIN vs RST teardown; every address in a DNS round-robin; connection to the proxy; a quick connect scan of 23 common ports (and the "every port is open = middlebox" pattern) |
| 6 | L3 | **Path MTU** | DF-bit ping sweep (binary search, loss-tolerant) for the path MTU; frag-needed vs **PMTUD black hole**; MSS hint |
| 7 | L5–L6 | **TLS** | Version, cipher, ALPN, SNI, full chain, expiry, not-yet-valid, hostname mismatch, untrusted issuer, missing intermediate, self-signed, weak crypto, TLS 1.0-only servers, resets/timeouts during the handshake, and **certificate re-signed by a proxy** (OS store vs Mozilla roots, plus known inspection vendors) |
| 8 | L7 | **HTTP** | Status and redirect chain; key headers and CDN; HSTS; who generated an error (origin vs forward proxy); 407 with the `Proxy-Authenticate` schemes from a raw CONNECT; proxy policy blocks; clock skew; captive portals |
| + | L2–L7 | **Packet capture** | `capture.pcap` of the whole run (dumpcap or pktmon on Windows, tcpdump on Linux), summarized in pure Python: TCP handshakes and RTT, MSS, retransmissions, duplicate ACKs, out-of-order segments, zero windows, RSTs and who sent them; TLS ClientHello/ServerHello (SNI, version, cipher, ALPN) and alerts; proxy CONNECT answers; DNS errors and unanswered queries; ICMP time-exceeded, frag-needed and unreachable messages |

Each protocol, and how NetDoctor uses it, is explained in **[docs/how-it-works.md](docs/how-it-works.md)**. That covers
OSI, ARP, DNS, the TCP handshake and teardown, ICMP, traceroute and TTL, path MTU discovery, TLS, HTTP and proxies, and
the IPsec IKE phases.

## Install

```powershell
# Windows (PowerShell)
git clone https://github.com/Atul-k-m/netdoctor.git
cd netdoctor
python -m venv .venv
.venv\Scripts\pip install -e ".[pac]"     # [pac] adds a JavaScript engine to evaluate PAC files
.venv\Scripts\netdoctor diagnose example.com
```

```bash
# Linux
git clone https://github.com/Atul-k-m/netdoctor.git && cd netdoctor
python3 -m venv .venv && .venv/bin/pip install -e ".[pac]"
.venv/bin/netdoctor diagnose example.com
```

On Linux, ICMP uses unprivileged ping sockets, which are allowed when your group is inside
`net.ipv4.ping_group_range`. That is the default on systemd distros and in Docker containers. If they aren't allowed,
NetDoctor falls back to the `ping` binary.

## Usage

```text
netdoctor diagnose TARGET [options]

  TARGET               https://host/path, host, host:port or an IP (bare host = HTTPS on 443)
  -p, --port N         port to test (overrides the URL)
  -c, --count N        ICMP echo requests (default 20)
  --rounds N           MTR rounds after the first trace (default 10)
  --max-hops N         traceroute TTL limit (default 30)
  --only a,b / --skip a,b   checks: local,dns,icmp,path,tcp,pmtu,tls,http
  --no-scan            skip the common-port scan
  --proxy URL / --no-proxy  force a proxy, or force direct
  --quick              5 pings, 3 MTR rounds, no port scan
  --json FILE          write all evidence as JSON ('-' = stdout)
  --brief              summary table only
  --no-capture         don't capture packets
  --capture-tool T     auto | dumpcap | pktmon (Windows) | tcpdump (Linux)
  --out DIR            run folder for report.md, report.json, capture.pcap (default runs/<time>-<host>)
  --no-save            write nothing to disk

netdoctor pcap FILE [--focus ip:port]... [--json]
                       summarize any .pcap/.pcapng, e.g. one a customer sent
netdoctor report runs/<run>/report.json
                       re-run the verdict engine on saved evidence and rewrite report.md
```

### Verdict and incident report

After the checks, the verdict engine maps the findings to a **root cause**, a **confidence** (High/Medium/Low with
the score breakdown) and an **owner team**. Lower-layer causes explain higher-layer symptoms: a captive portal
explains the TLS hostname mismatch it causes, and an MTU black hole explains the stalled TLS handshake. Anything left
unexplained is listed separately, so a second problem isn't hidden. The rules are listed in
[docs/how-it-works.md §13](docs/how-it-works.md#13-the-verdict-engine-and-the-incident-report).

`report.md` is a knowledge-base article with the sections **Symptom, Environment, Tests run, Evidence, Root cause,
Resolution, What to send to engineering** (plus Other observations and Notes). `report.json` holds the verdict and
all raw evidence.

### Packet capture

Run from an elevated terminal (Windows) or with `sudo` (Linux), and every diagnosis saves `runs/<time>-<host>/capture.pcap`
and adds a **Packet capture summary**. Open the same file in Wireshark; the summary lists the display filters that
show each finding.

```powershell
# Windows, "Run as administrator". dumpcap comes with Wireshark; pktmon is built in and used as the fallback.
$env:NETDOCTOR_DUMPCAP = "C:\Program Files\Wireshark\dumpcap.exe"   # only if Wireshark isn't on PATH
netdoctor diagnose https://example.com
netdoctor pcap runs\20261111-170000-example.com\capture.pcap --focus 93.184.216.34:443
```

```bash
sudo .venv/bin/netdoctor diagnose https://example.com        # tcpdump -i any
```

Without the rights to capture (or with `--no-capture`) the capture shows up as SKIP with the reason, for example
"Npcap is installed with 'Restrict Npcap driver's access to Administrators only'", and all other checks run as
usual. Capture tools get 12 s to start, so one that is blocked (for example by an antivirus holding a new binary)
can't hang the run.

The exit code is 1 when any check fails, 0 otherwise, so NetDoctor can be scripted.

Examples:

```bash
netdoctor diagnose https://intranet.corp.example/login
netdoctor diagnose mail.example.com:993 --only dns,tcp,tls
netdoctor diagnose 10.20.0.5:22 --no-scan
netdoctor diagnose https://example.com --proxy http://proxy.corp:8080 --json runs/ticket-1234.json
```

## Sample output (abridged)

An expired certificate (`netdoctor diagnose https://expired.badssl.com --only dns,tcp,tls,http`):

```text
┌─ L5-L6 TLS  TLS handshake and certificate chain ───────────────────────────────────────┐
│ The server certificate expired on 2015-04-12 (4230 days ago).                          │
│ • Negotiated TLSv1.2, cipher ECDHE-RSA-AES128-GCM-SHA256 (128-bit), ALPN http/1.1,     │
│   SNI expired.badssl.com, handshake 592 ms.                                            │
│ Handshakes                                                                             │
│ Trust store                      Path     Result                                       │
│ OS trust store                   direct   verify error 10: certificate has expired     │
│ no verification (diagnostic)     direct   OK TLSv1.2                                   │
│ Mozilla public roots (certifi)   direct   verify error 10: certificate has expired     │
│ Reproduce by hand: openssl s_client -connect expired.badssl.com:443 -servername ...    │
└──────────────────────────────────────────────────────────────────────────  FAIL  2.1s ─┘
Summary (bottom-up)
  Layer       Check   Result   Finding
  L7 DNS      dns      PASS    expired.badssl.com resolves to 104.154.89.105 in 223 ms
  L4 TCP      tcp      PASS    104.154.89.105:443 accepts connections; handshake in 297 ms avg.
  L5-L6 TLS   tls      FAIL    The server certificate expired on 2015-04-12 (4230 days ago).
  L7 HTTP     http     INFO    HTTP 200 OK from https://expired.badssl.com/ in 1105 ms.
```

The run ends with the verdict, and the run folder holds the full incident report. This one is from
`netdoctor diagnose https://expired.badssl.com --quick --no-capture --out runs\sample-expired`, abridged:

```text
┏━ Verdict ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Root cause  The server's TLS certificate has expired  tls_expired           ┃
┃ Confidence  High (0.93)   Layer L5-L6 TLS   Owner Site / application owner  ┃
┃                                                                             ┃
┃ The certificate presented for expired.badssl.com (*.badssl.com, issued by   ┃
┃ COMODO RSA Domain Validation Secure Server CA) expired on 2015-04-12. DNS,  ┃
┃ routing and TCP to 104.154.89.105:443 work; every client that validates     ┃
┃ certificates rejects the server.                                            ┃
┃ Resolution                                                                  ┃
┃ 1. Renew the certificate and install it (with its chain) on every           ┃
┃    server/load balancer for expired.badssl.com.                             ┃
┃ ...                                                                         ┃
┃ Incident report: runs\sample-expired\report.md                              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

### Verdict spot check on public endpoints (measured)

These are public endpoints with known faults, run with `--quick --no-capture` from a home Windows 11 connection on
2026-11-11. The script compares the verdict's category with the fault each endpoint is meant to show:

| Target | Intended fault | Verdict (rule, confidence) |
|--------|----------------|----------------------------|
| `https://example.com` | none | `no_fault` (0.75) |
| `expired.badssl.com` | expired certificate | `tls_expired` (0.93) |
| `wrong.host.badssl.com` | hostname mismatch | `tls_hostname_mismatch` (0.90) |
| `self-signed.badssl.com` | self-signed | `tls_self_signed` (0.88) |
| `untrusted-root.badssl.com` | untrusted CA | `tls_untrusted` (0.90) |
| `incomplete-chain.badssl.com` | missing intermediate | `tls_incomplete_chain` (0.90) |
| `sha1-intermediate.badssl.com` | SHA-1 intermediate | `tls_expired` (0.93), with SHA-1 listed as a second problem |
| `https://tls-v1-0.badssl.com:1010` | TLS 1.0 only | `tls_old_protocol` (0.88) |
| `example.com:81` | filtered port | `tcp_filtered` (0.90) |
| `127.0.0.1:1` | refused port | `tcp_refused` (0.94) |
| `nothing-here-netdoctor.example` | NXDOMAIN | `dns_nxdomain` (0.93) |
| `dnssec-failed.org` | DNSSEC failure | `dns_dnssec` (0.90) |
| `http://httpbin.org/status/502` | upstream 502 | `http_upstream_error` (0.90) |

**12 of 13** named the intended fault. The miss isn't wrong: `sha1-intermediate.badssl.com`'s leaf certificate also
expired, on 2020-05-30, so the engine ranks "expired" first and reports the SHA-1 chain under *Other observations*.
This is a spot check. The benchmark, which scores root-cause accuracy over injected faults, arrives in phase 5.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

The suite includes real TLS handshakes against local servers with generated certificates: private CA, inspection-vendor
CA, untrusted, expired, not-yet-valid, wrong host, self-signed and missing intermediate. It also covers a fake proxy
that answers 407, a local 502, parsers for Windows and Linux route and ARP output, the WinINET/WinHTTP registry blob,
the DNS disagreement patterns, MTR interpretation, and the PMTU sweep against simulated paths with 20% random loss.
The capture tests build checksummed frames from scratch (TLS 1.2 sessions, retransmissions with duplicate ACKs,
out-of-order segments, zero windows, refused and silent SYNs, TLS alerts split across segments, a proxy 407, DNS
NXDOMAIN and unanswered queries, ICMP frag-needed). They run them through the pcap and pcapng readers, covering both
byte orders, nanosecond timestamps, Linux SLL2 and VLAN tags. When tshark is on PATH, `tests/test_tshark_crosscheck.py`
also checks that the analyzer's counts match Wireshark's `tcp.analysis.*` flags on the same file.

The verdict tests feed synthetic evidence for each of the 12 lab faults (each must name the right category with High
confidence and leave nothing unexplained), plus the interactions between findings and a check that every report has
all seven KB sections.

CI runs the suite on Windows and Ubuntu (Python 3.10, 3.12, 3.13). On Linux it also exercises the real ICMP
datagram-socket engine and the tshark cross-check.

## Roadmap

- [x] **1. Diagnostic CLI:** the eight bottom-up checks with evidence
- [x] **2. Packet capture** during each run (.pcap) with a summary of handshakes, retransmissions, RSTs, zero windows, TLS alerts and DNS errors
- [x] **3. Verdict engine:** rules that map evidence to a root cause, a confidence and the next step; a Markdown knowledge-base incident report plus JSON
- [ ] **4. Fault lab:** Docker Compose with 12 reproducible customer faults, one command to inject and one to clear each
- [ ] **5. Benchmark:** inject each fault, run NetDoctor, score the root cause (results go in this README)
- [ ] **6. `netdoctor tunnel`:** IKE SA state, traffic through the tunnel, MSS/MTU hints
- [ ] **7. Full CI, tests and docs:** architecture diagram and a sample report

## License

MIT
