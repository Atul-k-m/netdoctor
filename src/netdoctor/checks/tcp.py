"""TCP: connect to the service port and tell open, refused (RST), filtered
(silence) and unreachable (ICMP error) apart; watch the teardown; then a quick
connect scan of common ports."""

from __future__ import annotations

import errno
import socket
import statistics
import time
from dataclasses import dataclass

from ..context import RunContext
from ..models import CheckResult, Status, Table
from ..netutil import IS_WINDOWS, call_with_timeout, fmt_ms, parallel_map

ID = "tcp"
LAYER = "L4 TCP"
TITLE = "TCP connect and port scan"

# Windows answers an RST by retrying the SYN twice, so a refused connect takes ~2 s
# there. The timeout must be longer than that or "refused" looks like "filtered".
CONNECT_TIMEOUT = 3.5 if IS_WINDOWS else 3.0
SCAN_TIMEOUT = 3.0 if IS_WINDOWS else 1.5

COMMON_PORTS = [
    (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"), (53, "dns"), (80, "http"), (110, "pop3"),
    (135, "msrpc"), (139, "netbios"), (143, "imap"), (443, "https"), (445, "smb"), (465, "smtps"),
    (587, "submission"), (993, "imaps"), (995, "pop3s"), (1433, "mssql"), (3306, "mysql"), (3389, "rdp"),
    (5432, "postgres"), (5900, "vnc"), (8080, "http-alt"), (8443, "https-alt"),
]
UNREACH_ERRNOS = {errno.EHOSTUNREACH, errno.ENETUNREACH, 113, 101, 10065, 10051}

STATE_TEXT = {
    "open": "open (SYN, SYN/ACK, ACK completed)",
    "refused": "refused (RST)",
    "filtered": "filtered (no answer)",
    "unreachable": "unreachable (ICMP error)",
    "error": "error",
}


@dataclass
class ConnectResult:
    state: str  # open | refused | filtered | unreachable | error
    ms: float
    detail: str = ""
    close: str | None = None

    def to_dict(self) -> dict:
        return {"state": self.state, "ms": round(self.ms, 2), "detail": self.detail, "close": self.close}


def graceful_close(sock: socket.socket) -> str:
    """Send our FIN and see how the server ends its side."""
    try:
        sock.shutdown(socket.SHUT_WR)
        sock.settimeout(1.5)
        for _ in range(64):
            if not sock.recv(65536):
                return "fin"
        return "data"
    except ConnectionResetError:
        return "rst"
    except TimeoutError:
        return "no-fin"
    except OSError:
        return "error"


CLOSE_TEXT = {
    "fin": "We sent FIN, the server answered with its own FIN: a clean four-way close.",
    "rst": "We sent FIN, the server answered with RST: an abortive close (some load balancers do this).",
    "no-fin": "We sent FIN; the server had not closed its side within 1.5 s (it holds the half-closed connection).",
    "data": "We sent FIN; the server kept sending data.",
    "error": "Teardown failed.",
}


def tcp_connect(ip: str, port: int, timeout: float, teardown: bool = False) -> ConnectResult:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    started = time.perf_counter()
    try:
        sock.connect((ip, port))
        ms = (time.perf_counter() - started) * 1000.0
        return ConnectResult("open", ms, close=graceful_close(sock) if teardown else None)
    except ConnectionRefusedError:
        return ConnectResult("refused", (time.perf_counter() - started) * 1000.0, "connection refused")
    except TimeoutError:
        return ConnectResult("filtered", (time.perf_counter() - started) * 1000.0, f"no answer in {timeout:.1f}s")
    except OSError as exc:
        ms = (time.perf_counter() - started) * 1000.0
        if exc.errno in UNREACH_ERRNOS or getattr(exc, "winerror", None) in UNREACH_ERRNOS:
            return ConnectResult("unreachable", ms, exc.strerror or str(exc))
        return ConnectResult("error", ms, str(exc))
    finally:
        sock.close()


def classify(attempts: list[ConnectResult]) -> str:
    states = {a.state for a in attempts}
    if states == {"open"}:
        return "open"
    if "open" in states:
        return "intermittent"
    for s in ("refused", "unreachable", "filtered", "error"):
        if s in states:
            return s
    return "error"


def run(ctx: RunContext) -> CheckResult:
    r = CheckResult(ID, LAYER, TITLE)
    ip, port = ctx.ip, ctx.target.port
    shown = ip or ctx.target.host
    r.commands = [f"Test-NetConnection {shown} -Port {port}"] if IS_WINDOWS else [f"nc -vz -w 3 {shown} {port}"]
    r.commands.append(f"nmap -Pn -sT -p {','.join(str(p) for p, _ in COMMON_PORTS[:12])},... {shown}")
    if not ip:
        return r.skip("No IP address to connect to (DNS failed)")

    attempts = [tcp_connect(ip, port, CONNECT_TIMEOUT, teardown=True)]
    attempts += [tcp_connect(ip, port, CONNECT_TIMEOUT) for _ in range(2 if attempts[0].state == "open" else 1)]
    state = classify(attempts)
    open_ms = [a.ms for a in attempts if a.state == "open"]
    r.data["direct"] = {"ip": ip, "port": port, "state": state, "attempts": [a.to_dict() for a in attempts]}

    at = Table(f"Connect to {ip}:{port}", ["Attempt", "Result", "Time", "Detail"])
    for i, a in enumerate(attempts, 1):
        at.rows.append([str(i), STATE_TEXT[a.state], fmt_ms(a.ms), a.detail])
    r.tables.append(at)

    proxied = ctx.proxied
    level = Status.INFO if proxied else Status.FAIL
    note = " (expected if this network only allows web traffic through the proxy)" if proxied else ""
    if state == "open":
        avg = statistics.fmean(open_ms)
        r.add("tcp.open", Status.PASS, f"{ip}:{port} accepts connections; handshake in {fmt_ms(avg)} avg.")
        if attempts[0].close:
            r.evidence.append(CLOSE_TEXT[attempts[0].close])
        icmp = ctx.result("icmp")
        ping_avg = icmp.data.get("avg") if icmp else None
        if ping_avg and avg < 0.3 * ping_avg and ping_avg > 10:
            r.add("tcp.local_answer", Status.INFO,
                  f"The TCP handshake ({fmt_ms(avg)}) completes far faster than ping ({fmt_ms(ping_avg)}): a nearby "
                  "proxy, firewall or tunnel client is answering the SYN on the server's behalf.")
    elif state == "intermittent":
        r.add("tcp.intermittent", Status.WARN,
              f"{ip}:{port} accepted {len(open_ms)}/{len(attempts)} connections; the rest failed "
              f"({', '.join(a.state for a in attempts if a.state != 'open')}). Overloaded server, flapping load-balancer "
              "member or packet loss.")
    elif state == "refused":
        r.add("tcp.refused", level,
              f"{ip}:{port} actively refused the connection (TCP RST or ICMP port-unreachable): the host is up "
              f"but nothing listens on that port, or a firewall REJECT rule answers for it{note}.")
    elif state == "filtered":
        r.add("tcp.filtered", level,
              f"{ip}:{port} never answered the SYN within {CONNECT_TIMEOUT:.1f}s: packets are silently dropped by a "
              f"firewall/ACL (DROP rule), or the host is down{note}.")
    elif state == "unreachable":
        r.add("tcp.unreachable", level,
              f"Connecting to {ip}:{port} failed with an ICMP unreachable ({attempts[0].detail}): no route to the "
              f"host, or a firewall rejecting with host/admin-prohibited{note}.")
    else:
        r.add("tcp.error", Status.ERROR, f"Connect failed: {attempts[0].detail}")

    _other_addresses(ctx, r, ip, port, state)
    if proxied:
        _check_proxy(ctx, r)
    if ctx.opts.scan:
        _scan(ip, port, state, r)

    r.summary = next((f.message for f in r.findings if f.status in (Status.FAIL, Status.WARN)),
                     next((f.message for f in r.findings if f.code in ("tcp.proxy_ok", "tcp.open")), r.findings[0].message))
    return r


def _other_addresses(ctx: RunContext, r: CheckResult, ip: str, port: int, state: str) -> None:
    """DNS round-robin: if the name has several IPv4 addresses, one dead member makes
    the site fail for some users and some attempts only."""
    others = [a for a in ctx.addresses if a != ip and "." in a][:5]
    if not others:
        return
    results = parallel_map(lambda a: (a, tcp_connect(a, port, CONNECT_TIMEOUT)), others, workers=len(others))
    r.data["other_addresses"] = [{"ip": a, **res.to_dict()} for a, res in results]
    r.tables.append(Table(f"Other addresses of {ctx.target.host}", ["Address", "Result", "Time"],
                          [[a, STATE_TEXT[res.state], fmt_ms(res.ms)] for a, res in results]))
    everything = [(ip, state)] + [(a, res.state) for a, res in results]
    dead = [a for a, s in everything if s not in ("open", "intermittent")]
    alive = [a for a, s in everything if s in ("open", "intermittent")]
    if dead and alive:
        r.add("tcp.some_addresses_dead", Status.WARN,
              f"{len(dead)} of {len(everything)} addresses for {ctx.target.host} do not accept connections on port "
              f"{port} ({', '.join(dead)}); clients that pick those fail, so the problem looks intermittent. "
              "Remove the dead member from DNS / the load balancer.")


def _check_proxy(ctx: RunContext, r: CheckResult) -> None:
    hp = ctx.proxy.host_port if ctx.proxy else None
    if not hp:
        return
    host, port = hp
    infos, err, timed_out = call_with_timeout(socket.getaddrinfo, 5.0, host, port, socket.AF_INET, socket.SOCK_STREAM)
    if timed_out or err or not infos:
        r.add("tcp.proxy_unresolved", Status.FAIL, f"Cannot resolve the proxy host {host}: {err or 'timeout'}.")
        return
    pip = infos[0][4][0]
    res = tcp_connect(pip, port, CONNECT_TIMEOUT, teardown=False)
    r.data["proxy"] = {"host": host, "ip": pip, "port": port, **res.to_dict()}
    r.tables.append(Table("Connect to the proxy", ["Proxy", "Result", "Time"],
                          [[f"{host}:{port} ({pip})", STATE_TEXT[res.state], fmt_ms(res.ms)]]))
    if res.state == "open":
        r.add("tcp.proxy_ok", Status.PASS, f"Proxy {host}:{port} accepts connections ({fmt_ms(res.ms)}).")
    else:
        r.add("tcp.proxy_unreachable", Status.FAIL,
              f"The configured proxy {host}:{port} is {STATE_TEXT[res.state]}: every proxied request will fail.")


def _scan(ip: str, port: int, target_state: str, r: CheckResult) -> None:
    ports = list(COMMON_PORTS)
    if port not in {p for p, _ in ports}:
        ports.append((port, "target"))
    results = parallel_map(lambda pn: (pn, tcp_connect(ip, pn[0], SCAN_TIMEOUT)), ports, workers=len(ports))
    r.data["scan"] = [{"port": p, "service": s, **res.to_dict()} for (p, s), res in results]
    by_state: dict[str, list[str]] = {}
    for (p, s), res in results:
        by_state.setdefault(res.state, []).append(f"{p}/{s}")
    table = Table(f"Common ports on {ip}", ["Port", "Service", "State", "Time"])
    for (p, s), res in results:
        if res.state != "filtered":
            table.rows.append([str(p), s, STATE_TEXT[res.state], fmt_ms(res.ms)])
    if table.rows:
        r.tables.append(table)
    r.evidence.append("Scan: " + "; ".join(f"{k}: {len(v)}" for k, v in sorted(by_state.items()))
                      + (f". Filtered: {', '.join(by_state['filtered'])}" if by_state.get("filtered") else ""))
    n = len(results)
    if len(by_state.get("open", [])) >= n - 1 and n > 10:
        r.add("tcp.all_open", Status.INFO,
              "Practically every port completes the handshake, even unlikely ones (telnet, VNC): a middlebox "
              "(proxy, firewall or tunnel client) is answering SYNs on the host's behalf.")
    elif len(by_state.get("filtered", [])) == n:
        r.add("tcp.all_filtered", Status.INFO,
              "Every scanned port is silently dropped: the host is down, or a firewall drops everything from here.")
    elif target_state == "filtered" and by_state.get("refused"):
        r.add("tcp.port_specific_drop", Status.INFO,
              f"Other ports answer with RST (so the host is up), but port {port} is silently dropped: a firewall rule "
              "targets this port.")
