"""DNS: what the OS resolver returns (what apps see) compared with direct queries
to the configured servers, Google 8.8.8.8, Cloudflare 1.1.1.1 and DNS over HTTPS.
The disagreement pattern points at the root cause."""

from __future__ import annotations

import os
import socket
import ssl
import time
from dataclasses import dataclass, field

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

from ..context import RunContext
from ..models import CheckResult, Status, Table
from ..netutil import IS_WINDOWS, call_with_timeout, classify_ip, fmt_ms, is_ipv4, parallel_map

ID = "dns"
LAYER = "L7 DNS"
TITLE = "Name resolution"

PUBLIC_RESOLVERS = [("Google", "8.8.8.8"), ("Cloudflare", "1.1.1.1")]
DOH_URL = "https://1.1.1.1/dns-query"
SYSTEM_TIMEOUT = 8.0
QUERY_TIMEOUT = 2.0


@dataclass
class Answer:
    resolver: str
    server: str | None
    transport: str  # OS | UDP | TCP | DoH
    outcome: str  # ok | nxdomain | nodata | servfail | refused | timeout | tempfail | error
    addresses: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    ttl: int | None = None
    ms: float | None = None
    detail: str = ""
    cd_ok: bool | None = None  # SERVFAIL normally, but answered with the CD bit set

    @property
    def ipv4(self) -> list[str]:
        return [a for a in self.addresses if is_ipv4(a)]

    def to_dict(self) -> dict:
        return self.__dict__.copy()


# ------------------------------------------------------------------- lookups


def _gai_outcome(exc: socket.gaierror) -> tuple[str, str]:
    code = exc.errno
    if code == socket.EAI_NONAME:
        return "nxdomain", "host not found (NXDOMAIN or no address records)"
    if code == getattr(socket, "EAI_NODATA", object()):
        return "nodata", "name exists but has no address records"
    if code == socket.EAI_AGAIN:
        return "tempfail", "temporary failure (SERVFAIL, or no DNS server answered)"
    if code == socket.EAI_FAIL:
        return "servfail", "non-recoverable DNS failure"
    return "error", str(exc)


def system_lookup(host: str, timeout: float = SYSTEM_TIMEOUT) -> Answer:
    started = time.perf_counter()
    result, error, timed_out = call_with_timeout(socket.getaddrinfo, timeout, host, None, 0, socket.SOCK_STREAM)
    ms = (time.perf_counter() - started) * 1000.0
    name = "System resolver (getaddrinfo)"
    if timed_out:
        return Answer(name, None, "OS", "timeout", ms=ms, detail=f"no result within {timeout:.0f}s")
    if isinstance(error, socket.gaierror):
        outcome, detail = _gai_outcome(error)
        return Answer(name, None, "OS", outcome, ms=ms, detail=detail)
    if error is not None:
        return Answer(name, None, "OS", "error", ms=ms, detail=str(error))
    addrs = list(dict.fromkeys(ai[4][0] for ai in result or []))
    addrs.sort(key=lambda a: 0 if is_ipv4(a) else 1)
    return Answer(name, None, "OS", "ok" if addrs else "nodata", addresses=addrs, ms=ms)


def from_response(resp: dns.message.Message, resolver: str, server: str, transport: str, ms: float) -> Answer:
    rcode = resp.rcode()
    ans = Answer(resolver, server, transport, "error", ms=ms)
    if rcode == dns.rcode.NXDOMAIN:
        ans.outcome = "nxdomain"
    elif rcode == dns.rcode.SERVFAIL:
        ans.outcome = "servfail"
    elif rcode == dns.rcode.REFUSED:
        ans.outcome = "refused"
    elif rcode != dns.rcode.NOERROR:
        ans.detail = dns.rcode.to_text(rcode)
    else:
        for rrset in resp.answer:
            if rrset.rdtype == dns.rdatatype.A:
                ans.addresses.extend(r.address for r in rrset)
                ans.ttl = rrset.ttl if ans.ttl is None else min(ans.ttl, rrset.ttl)
            elif rrset.rdtype == dns.rdatatype.CNAME:
                ans.cnames.extend(str(r.target).rstrip(".") for r in rrset)
        ans.outcome = "ok" if ans.addresses else "nodata"
    return ans


def udp_query(resolver: str, server: str, host: str, timeout: float = QUERY_TIMEOUT, cd: bool = False,
              tries: int = 2) -> Answer:
    query = dns.message.make_query(host, dns.rdatatype.A)
    if cd:
        query.flags |= dns.flags.CD
    started = time.perf_counter()
    last = None
    for _ in range(tries):
        try:
            resp = dns.query.udp(query, server, timeout=timeout)
            transport = "UDP"
            if resp.flags & dns.flags.TC:
                resp = dns.query.tcp(query, server, timeout=timeout)
                transport = "TCP"
            return from_response(resp, resolver, server, transport, (time.perf_counter() - started) * 1000.0)
        except dns.exception.Timeout:
            last = Answer(resolver, server, "UDP", "timeout", detail=f"no reply in {timeout:.0f}s x{tries}")
        except (OSError, dns.exception.DNSException) as exc:
            return Answer(resolver, server, "UDP", "error", ms=(time.perf_counter() - started) * 1000.0, detail=str(exc))
    assert last is not None
    last.ms = (time.perf_counter() - started) * 1000.0
    return last


def doh_query(host: str, timeout: float = 4.0) -> Answer:
    import httpx

    query = dns.message.make_query(host, dns.rdatatype.A)
    query.id = 0  # RFC 8484 4.1: use ID 0 for cache friendliness
    started = time.perf_counter()
    name = "Cloudflare DoH"
    try:
        with httpx.Client(verify=ssl.create_default_context(), timeout=timeout, trust_env=False) as client:
            resp = client.post(DOH_URL, content=query.to_wire(),
                               headers={"content-type": "application/dns-message", "accept": "application/dns-message"})
        ms = (time.perf_counter() - started) * 1000.0
        if resp.status_code != 200:
            return Answer(name, DOH_URL, "DoH", "error", ms=ms, detail=f"HTTP {resp.status_code}")
        return from_response(dns.message.from_wire(resp.content), name, DOH_URL, "DoH", ms)
    except httpx.TimeoutException:
        return Answer(name, DOH_URL, "DoH", "timeout", ms=(time.perf_counter() - started) * 1000.0,
                      detail=f"no reply in {timeout:.0f}s")
    except Exception as exc:  # noqa: BLE001 - TLS interception, resets etc. are evidence
        return Answer(name, DOH_URL, "DoH", "error", ms=(time.perf_counter() - started) * 1000.0,
                      detail=f"{type(exc).__name__}: {exc}"[:200])


def hosts_file_path() -> str:
    if IS_WINDOWS:
        return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
    return "/etc/hosts"


def parse_hosts(text: str) -> dict[str, list[str]]:
    table: dict[str, list[str]] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        for name in parts[1:]:
            table.setdefault(name.lower().rstrip("."), []).append(parts[0])
    return table


def hosts_override(host: str) -> list[str]:
    try:
        with open(hosts_file_path(), encoding="utf-8", errors="replace") as fh:
            return parse_hosts(fh.read()).get(host.lower(), [])
    except OSError:
        return []


# ------------------------------------------------------------------ analysis


@dataclass
class Analysis:
    findings: list[tuple[str, Status, str]]
    ip: str | None
    ip_source: str
    public_answers: list[str]


def analyze(host: str, system: Answer, configured: list[Answer], public: list[Answer], doh: Answer | None,
            hosts_ips: list[str]) -> Analysis:
    """Pure function: compare resolver outcomes and explain the pattern."""
    out: list[tuple[str, Status, str]] = []
    independent = public + ([doh] if doh else [])
    pub_ok = [a for a in independent if a.outcome == "ok"]
    pub_answers = list(dict.fromkeys(ip for a in pub_ok for ip in a.ipv4))
    udp_public_dead = bool(public) and all(a.outcome in ("timeout", "error") for a in public)
    doh_ok = doh is not None and doh.outcome == "ok"
    ip, ip_source = None, ""

    if hosts_ips and host not in ("localhost",):
        out.append(("dns.hosts_override", Status.WARN,
                    f"The hosts file maps {host} to {', '.join(hosts_ips)}; this bypasses DNS entirely "
                    f"({hosts_file_path()})."))

    if system.outcome == "ok":
        sys_v4 = system.ipv4
        ip = sys_v4[0] if sys_v4 else system.addresses[0]
        ip_source = "system resolver"
        msg = f"{host} resolves to {', '.join(system.addresses[:6])} in {fmt_ms(system.ms)}"
        out.insert(0, ("dns.ok", Status.PASS, msg))
        if pub_ok and sys_v4:
            if not set(sys_v4) & set(pub_answers):
                kinds = {classify_ip(a) for a in sys_v4}
                pub_kinds = {classify_ip(a) for a in pub_answers}
                pub_list = ", ".join(pub_answers[:4])
                if kinds & {"unspecified", "loopback"} and "public" in pub_kinds:
                    out.append(("dns.sinkhole", Status.FAIL,
                                f"The local resolver answers {', '.join(sys_v4)} (a sinkhole address) while public DNS "
                                f"returns {pub_list}: the name is being blocked by DNS filtering."))
                elif "private" in kinds and "public" in pub_kinds:
                    out.append(("dns.split_horizon", Status.INFO,
                                f"Local DNS returns private {', '.join(sys_v4)}, public DNS returns {pub_list}: "
                                "split-horizon DNS (internal view of the name) or DNS interception."))
                elif "cgnat" in kinds and "public" in pub_kinds:
                    out.append(("dns.cgnat_answer", Status.INFO,
                                f"Local DNS returns {', '.join(sys_v4)} from 100.64.0.0/10 (CGNAT range), public DNS "
                                f"returns {pub_list}. Private-access clients (e.g. ZPA synthetic IPs) and carrier NAT use this range."))
                else:
                    out.append(("dns.answers_differ", Status.INFO,
                                f"Local and public resolvers return different IPs ({', '.join(sys_v4[:3])} vs {pub_list}); "
                                "normal for CDNs and GeoDNS, suspicious only if the local answer is unexpected."))
        elif independent and all(a.outcome == "nxdomain" for a in independent):
            out.append(("dns.internal_name", Status.INFO,
                        "Resolves locally but public DNS says NXDOMAIN: an internal-only name (split DNS)."))
        elif independent and all(a.outcome in ("timeout", "error") for a in independent):
            out.append(("dns.public_unreachable", Status.INFO,
                        "Public resolvers (UDP/53 and DoH) are unreachable from here; fine while local DNS works."))
        if udp_public_dead and doh_ok:
            out.append(("dns.public_udp_blocked", Status.INFO,
                        "Direct UDP/53 to 8.8.8.8 and 1.1.1.1 times out while DoH works: outbound DNS is restricted to "
                        "the approved resolvers (normal in enterprises; explains why `nslookup host 8.8.8.8` fails)."))
        if system.ms and system.ms > 1000:
            out.append(("dns.slow", Status.WARN, f"The system resolver took {fmt_ms(system.ms)}; anything over ~1 s "
                        "makes every new connection feel slow (first DNS server timing out?)."))
        return Analysis(out, ip, ip_source, pub_answers)

    # The system resolver failed: work out why from the direct queries.
    conf = configured
    any_conf = lambda outcome: any(a.outcome == outcome for a in conf)  # noqa: E731
    conf_all_timeout = bool(conf) and all(a.outcome == "timeout" for a in conf)
    conf_names = ", ".join(a.server or "?" for a in conf) or "the configured server"

    if system.outcome == "nxdomain" or any_conf("nxdomain"):
        if pub_ok:
            out.append(("dns.nxdomain_local", Status.FAIL,
                        f"Local DNS says NXDOMAIN for {host}, but public DNS resolves it to {', '.join(pub_answers[:4])}: "
                        "DNS filtering on the local resolver, a split-horizon zone missing the record, or a stale "
                        "negative cache."))
        else:
            out.append(("dns.nxdomain", Status.FAIL,
                        f"NXDOMAIN: {host} does not exist in DNS"
                        + (" (local and public resolvers agree)" if any(a.outcome == "nxdomain" for a in independent) else "")
                        + ". Typo, deleted or expired domain, or an internal name this resolver does not serve."))
    elif system.outcome == "nodata" or (conf and all(a.outcome == "nodata" for a in conf)):
        out.append(("dns.nodata", Status.FAIL,
                    f"{host} exists but has no A record (NOERROR with an empty answer)."))
    elif system.outcome == "servfail" or any_conf("servfail"):
        if any(a.cd_ok for a in conf + public):
            out.append(("dns.dnssec_failure", Status.FAIL,
                        "SERVFAIL, but the same query with the CD (checking disabled) bit succeeds: DNSSEC "
                        "validation is failing for this domain (bad or expired signatures)."))
        elif pub_ok:
            out.append(("dns.servfail_local", Status.FAIL,
                        f"Local DNS ({conf_names}) returns SERVFAIL while public DNS works: the local resolver "
                        "cannot reach its forwarders or the authoritative servers."))
        else:
            out.append(("dns.servfail", Status.FAIL,
                        "SERVFAIL from every resolver: the domain's authoritative name servers are broken or "
                        "unreachable (lame delegation)."))
    elif conf_all_timeout or system.outcome in ("timeout", "tempfail"):
        if udp_public_dead and doh_ok:
            out.append(("dns.udp53_blocked", Status.FAIL,
                        "Every UDP/53 query timed out (configured servers, 8.8.8.8, 1.1.1.1) but DNS over HTTPS works: "
                        "outbound DNS on port 53 is blocked or the configured DNS server is unreachable."))
        elif udp_public_dead and not doh_ok:
            out.append(("dns.no_dns", Status.FAIL,
                        "No DNS server answered at all (configured, 8.8.8.8, 1.1.1.1, DoH): there is no working "
                        "network path for DNS."))
        else:
            out.append(("dns.timeout", Status.FAIL,
                        f"The configured DNS server ({conf_names}) did not answer within the timeout, while public "
                        "resolvers did: the local DNS server is down or unreachable."))
    elif system.outcome == "refused" or any_conf("refused"):
        out.append(("dns.refused", Status.FAIL,
                    "The DNS server refused the query (REFUSED): it does not allow recursion for this client."))
    else:
        out.append(("dns.error", Status.FAIL, f"Name resolution failed: {system.detail or system.outcome}"))

    if pub_ok:
        ip, ip_source = pub_answers[0] if pub_answers else None, pub_ok[0].resolver
    return Analysis(out, ip, ip_source, pub_answers)


# ----------------------------------------------------------------------- check


def run(ctx: RunContext) -> CheckResult:
    r = CheckResult(ID, LAYER, TITLE)
    host = ctx.target.host
    r.commands = _commands(host)

    if ctx.target.is_ip:
        ctx.ip, ctx.ip_source = host, "target is an IP"
        ctx.addresses = [host]
        ptr, _err, _to = call_with_timeout(socket.gethostbyaddr, 2.0, host)
        r.add("dns.ip_target", Status.PASS, "Target is an IP address; no DNS lookup needed"
              + (f" (PTR: {ptr[0]})." if ptr else "."))
        r.summary = "IP target, DNS not needed"
        return r

    import dns.resolver

    try:
        servers = [s for s in dns.resolver.Resolver().nameservers if is_ipv4(s)][:2]
    except Exception:  # noqa: BLE001 - no resolv.conf etc.
        servers = []
    single_label = "." not in host

    jobs = [("system", None)] + [("configured", s) for s in servers]
    if not single_label:
        jobs += [("public", (n, s)) for n, s in PUBLIC_RESOLVERS] + [("doh", None)]

    def do(job):
        kind, arg = job
        if kind == "system":
            return kind, system_lookup(host)
        if kind == "configured":
            return kind, udp_query(f"Configured DNS {arg}", arg, host)
        if kind == "public":
            return kind, udp_query(f"{arg[0]} {arg[1]}", arg[1], host)
        return kind, doh_query(host)

    results = parallel_map(do, jobs, workers=8)
    system = next(a for k, a in results if k == "system")
    configured = [a for k, a in results if k == "configured"]
    public = [a for k, a in results if k == "public"]
    doh = next((a for k, a in results if k == "doh"), None)

    # A SERVFAIL might be DNSSEC: retry those with checking disabled.
    for a in configured + public:
        if a.outcome == "servfail" and a.server:
            a.cd_ok = udp_query(a.resolver, a.server, host, cd=True, tries=1).outcome == "ok"

    analysis = analyze(host, system, configured, public, doh, hosts_override(host))
    for code, status, msg in analysis.findings:
        r.add(code, status, msg)

    ctx.addresses = system.addresses
    ctx.ip, ctx.ip_source = analysis.ip, analysis.ip_source
    ctx.public_answers = analysis.public_answers

    table = Table(f"A records for {host}", ["Resolver", "Via", "Result", "Answer", "TTL", "Time"])
    for a in [system] + configured + public + ([doh] if doh else []):
        v4, v6 = a.ipv4, [x for x in a.addresses if not is_ipv4(x)]
        answer = ", ".join(v4[:4]) + (" …" if len(v4) > 4 else "")
        if v6:
            answer += (" + " if answer else "") + f"{len(v6)} IPv6"
        if a.cnames:
            answer = "CNAME " + " > ".join(a.cnames[:2]) + (" > " + answer if answer else "")
        if not answer:
            answer = a.detail or "-"
        result = a.outcome.upper() if a.outcome != "ok" else "OK"
        if a.cd_ok:
            result += " (OK with CD bit)"
        table.rows.append([a.resolver, a.transport, result, answer, "-" if a.ttl is None else str(a.ttl), fmt_ms(a.ms)])
    r.tables.append(table)
    if single_label:
        r.evidence.append(f"'{host}' is a single-label name: the OS appends DNS search suffixes, public resolvers are not asked.")
    if system.outcome != "ok" and ctx.ip:
        r.evidence.append(f"Continuing the lower-layer tests with {ctx.ip} from {ctx.ip_source}, to see whether DNS is the only problem.")
    r.data = {
        "system": system.to_dict(),
        "configured": [a.to_dict() for a in configured],
        "public": [a.to_dict() for a in public],
        "doh": doh.to_dict() if doh else None,
        "chosen_ip": ctx.ip,
        "chosen_from": ctx.ip_source,
    }
    first_bad = next((f for f in r.findings if f.status in (Status.FAIL, Status.WARN)), None)
    r.summary = first_bad.message if first_bad else r.findings[0].message
    return r


def _commands(host: str) -> list[str]:
    if IS_WINDOWS:
        return [f"nslookup {host}", f"nslookup {host} 8.8.8.8", f"Resolve-DnsName {host} -Server 1.1.1.1 -DnsOnly",
                "ipconfig /displaydns", "ipconfig /flushdns"]
    return [f"getent ahosts {host}", f"dig {host}", f"dig @8.8.8.8 {host}", f"dig @1.1.1.1 {host} +cd",
            f"curl -sH 'accept: application/dns-json' 'https://1.1.1.1/dns-query?name={host}&type=A'"]
