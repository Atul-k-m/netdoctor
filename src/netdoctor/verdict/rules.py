"""The rules that turn findings into a root cause.

A rule fires when any `any_of` finding (and every `all_of` finding) is present
and no `unless` finding is. Its confidence starts at `base`, goes up for each
`support` finding present and down for each `against` finding. The rule with
the highest confidence becomes the root cause; ties go to the rule listed first,
which is ordered bottom-up so that a lower layer wins.

`explains` lists the findings this root cause accounts for (a trailing `*`
matches a prefix). Whatever FAIL/WARN finding is left unexplained is reported
as a separate observation, so an independent second problem is never hidden.

A code can carry a status filter: "tcp.refused:fail" only matches the FAIL
version (when a proxy is in use the same finding is INFO).

Templates use facts from facts.py, e.g. {host}, {ip}, {cert_not_after}."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from .facts import SafeDict

ABOVE_LOCAL = ("dns.*", "icmp.*", "path.*", "tcp.*", "pmtu.*", "tls.*", "http.*", "capture.*")
ABOVE_DNS = ("icmp.*", "path.*", "tcp.*", "pmtu.*", "tls.*", "http.*", "capture.*")
DNS_SIDE = ("dns.*", "capture.dns_errors", "capture.dns_unanswered")


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    title: str
    layer: str
    any_of: tuple[str, ...]
    all_of: tuple[str, ...] = ()
    unless: tuple[str, ...] = ()
    base: float = 0.8
    support: tuple[tuple[str, float], ...] = ()
    against: tuple[tuple[str, float], ...] = ()
    explains: tuple[str, ...] = ()
    predicate: Callable[[SafeDict], bool] | None = None
    symptom: str = ""
    explanation: str = ""
    resolution: tuple[str, ...] = ()
    next_steps: tuple[str, ...] = ()
    owner: str = ""
    engineering: tuple[str, ...] = ()
    wireshark: tuple[str, ...] = ()


def _skew_explains_cert(f: SafeDict) -> bool:
    skew = f.get("clock_skew_s")
    return isinstance(skew, (int, float)) and abs(skew) > 300


RULES: list[Rule] = [
    # ------------------------------------------------------------- local host
    Rule(
        "local_link_down", "local_network", "No active network connection on the client", "L1-L2 Local host",
        any_of=("local.no_ip",), base=0.96, explains=ABOVE_LOCAL,
        symptom="Nothing works: every site and app reports no network or no internet.",
        explanation="No interface on {client} is up with an IPv4 address, so nothing can leave the machine. Every "
                    "higher-layer failure in this report is a consequence.",
        resolution=("Reconnect the cable or Wi-Fi; check the adapter is enabled (ncpa.cpl / `ip link`).",
                    "Check the switch port or the Wi-Fi association and authentication (802.1X)."),
        next_steps=("Confirm link lights / Wi-Fi association, then re-run NetDoctor.",),
        owner="Customer desktop / local IT",
        engineering=("Adapter list with state (ipconfig /all or ip addr).",),
    ),
    Rule(
        "local_dhcp_failed", "local_network", "DHCP failed: the client has a self-assigned 169.254.x.x address",
        "L2-L3 Local host", any_of=("local.apipa",), base=0.95, explains=ABOVE_LOCAL,
        symptom="Nothing works; Windows shows 'No internet' or 'Unidentified network'.",
        explanation="The interface only has an APIPA (169.254/16) address, which Windows assigns when no DHCP server "
                    "answers. Without a real address and gateway nothing beyond the link works.",
        resolution=("Renew the lease (`ipconfig /release` then `ipconfig /renew`, or `dhclient -r && dhclient`).",
                    "If it fails again: check the DHCP server/scope (exhausted pool?), the VLAN of the switch port, "
                    "and that DHCP relay (ip helper-address) is configured on the gateway."),
        next_steps=("Ask whether other devices on the same network get addresses (scope vs single-client problem).",),
        owner="Network team (DHCP / switching)",
        engineering=("Client MAC address, switch port / SSID, time of the failed DHCP attempt.",),
    ),
    Rule(
        "local_no_default_route", "local_network", "The client has no default gateway",
        "L3 Local host", any_of=("local.no_default_route",), base=0.92, explains=ABOVE_LOCAL,
        symptom="Local resources may work, but nothing off the LAN does.",
        explanation="The routing table has no 0.0.0.0/0 route, so packets to {ip} have nowhere to go.",
        resolution=("Fix the DHCP option 3 (router) or the static IP configuration.",
                    "If a VPN client removed the route, reconnect or repair the VPN client."),
        owner="Customer desktop / network team",
        engineering=("`route print -4` / `ip route` output.",),
    ),
    Rule(
        "local_gateway_unreachable", "local_gateway", "The default gateway does not answer ARP",
        "L2 Local host", any_of=("local.gateway_arp_failed",), base=0.9,
        support=(("dns.no_dns", 0.05), ("dns.timeout", 0.03), ("icmp.no_reply", 0.02)), explains=ABOVE_LOCAL,
        symptom="Nothing beyond the local network works.",
        explanation="The gateway {gateway} has no resolved MAC address in the ARP table and does not answer: layer 2 "
                    "to the first hop is broken, so every DNS query and connection dies at the first hop.",
        resolution=("Check that the gateway/router is up.",
                    "Check the client is on the right VLAN/SSID (wrong VLAN = gateway IP not on that segment).",
                    "Check the cable/Wi-Fi; look for an IP conflict on the gateway address."),
        owner="Network team (LAN)",
        engineering=("`arp -a` / `ip neigh`, the gateway IP, the switch port or SSID.",),
        wireshark=("arp",),
    ),
    # ------------------------------------------------------------------ proxy
    Rule(
        "proxy_unreachable", "proxy_unreachable", "The configured proxy cannot be reached",
        "L4 Proxy", any_of=("tcp.proxy_unreachable", "http.proxy_unreachable", "tcp.proxy_unresolved"), base=0.92,
        explains=("tls.*", "http.*", "capture.*", "tcp.filtered", "tcp.refused"),
        symptom="Every web request fails (the browser shows ERR_PROXY_CONNECTION_FAILED or a timeout).",
        explanation="Requests to {target} are sent to the proxy {proxy} (chosen by: {proxy_source}), and that proxy "
                    "does not accept connections.",
        resolution=("Check the proxy service is running and reachable on that port.",
                    "Check the proxy setting (PAC/WPAD/env) points at the right host; remove a stale proxy setting."),
        owner="Proxy / security team",
        engineering=("Proxy {proxy} (from {proxy_source}) does not accept TCP connections from {egress_ip}.",),
    ),
    Rule(
        "proxy_auth_required", "proxy_auth_required", "The proxy requires authentication (HTTP 407)",
        "L7 Proxy", any_of=("http.proxy_auth_required",), base=0.93, support=(("tls.proxy_refused_connect", 0.03),),
        explains=("tls.*", "http.*", "capture.*", "tcp.filtered", "tcp.refused", "tcp.unreachable"),
        symptom="The browser asks for proxy credentials or shows 'Proxy authentication required'; apps fail with "
                "407 or a tunnel/CONNECT error.",
        explanation="The proxy {proxy} answers {proxy_status} and demands credentials (Proxy-Authenticate: "
                    "{proxy_auth}). The client either sent none, sent wrong/expired ones, or cannot speak the "
                    "offered scheme (NTLM/Negotiate from a non-domain app, Basic disabled).",
        resolution=("Give the application valid proxy credentials, or sign in again if the identity expired.",
                    "For apps that can't authenticate, exempt the app/destination from proxy authentication or send "
                    "it via a path with transparent auth (e.g. a client connector or Kerberos).",
                    "Check the proxy's auth backend (LDAP/Kerberos/SAML) is healthy if many users see this."),
        next_steps=("Check whether the browser works while the app doesn't (app can't do the auth scheme).",
                    "Look up the user in the proxy's auth logs at the time of the run."),
        owner="Proxy / identity team",
        engineering=("Proxy {proxy} answered {proxy_status}; Proxy-Authenticate: {proxy_auth}. Add the user and the app that failed.",),
        wireshark=('http.response.code == 407', 'http.request.method == "CONNECT"'),
    ),
    Rule(
        "proxy_policy_block", "proxy_policy_block", "The proxy blocks this destination by policy",
        "L7 Proxy", any_of=("http.proxy_denied", "http.blocked_by_proxy"), base=0.88,
        explains=("tls.*", "http.*", "capture.*"),
        symptom="A block page or 403 from the proxy/security gateway instead of the site.",
        explanation="The proxy refuses the request for {target}: URL filtering, a category or a cloud-app policy.",
        resolution=("If the access is legitimate, request a policy exception / URL recategorization.",),
        owner="Security policy team",
        engineering=("URL, user, timestamp and the block page title / transaction ID.",),
    ),
    Rule(
        "proxy_upstream_error", "proxy_upstream_error", "The proxy cannot reach the destination",
        "L7 Proxy", any_of=("http.proxy_upstream_error", "http.bad_gateway"),
        predicate=lambda f: bool(f.get("http_by_proxy")) or f.get("proxy_status", "?")[:1] == "5", base=0.86,
        explains=("tls.*", "http.*", "capture.*"),
        symptom="A proxy error page (502/503/504) instead of the site.",
        explanation="The forward proxy {proxy} accepted the request but failed to connect to or get a response from "
                    "the origin ({http_by_proxy}).",
        resolution=("Check the origin is up and reachable from the proxy's egress (DNS, firewall, allow-listing of "
                    "the proxy's egress IPs at the origin).",),
        owner="Proxy team, then site owner",
        engineering=("Proxy {proxy} answered {proxy_status} for {target} ({http_by_proxy}).",),
    ),
    # -------------------------------------------------------------------- DNS
    Rule(
        "dns_nxdomain", "dns_nxdomain", "DNS: the name does not exist (NXDOMAIN)", "L7 DNS",
        any_of=("dns.nxdomain",), base=0.93, explains=DNS_SIDE + ABOVE_DNS,
        symptom="'Server not found' / ERR_NAME_NOT_RESOLVED for {host}; nothing reaches the server.",
        explanation="Every resolver asked ({dns_configured} and the public ones) answers NXDOMAIN for {host}: the "
                    "name has no record in DNS. No connection can start, so no other layer could be tested.",
        resolution=("Check the spelling of the name.",
                    "If it should exist: create/restore the DNS record or renew the domain.",
                    "If it is an internal name: make sure the client uses the internal resolver (VPN/connector "
                    "DNS, NRPT, split DNS)."),
        next_steps=("Ask when it last worked and whether the record was recently changed or removed.",),
        owner="DNS / domain owner",
        engineering=("NXDOMAIN for {host} from {dns_configured} and from 8.8.8.8 / 1.1.1.1 / DoH.",),
        wireshark=("dns.flags.rcode == 3",),
    ),
    Rule(
        "dns_nxdomain_local", "dns_filtered", "Local DNS says NXDOMAIN but public DNS resolves the name",
        "L7 DNS", any_of=("dns.nxdomain_local",), base=0.9, support=(("tcp.open", 0.03), ("http.ok", 0.03)),
        explains=DNS_SIDE,
        symptom="'Server not found' for {host} on this network, while it works elsewhere.",
        explanation="The configured resolver ({dns_configured}) returns NXDOMAIN, but public resolvers return "
                    "{public_answer}, and the site works when reached at that address. The local resolver is "
                    "filtering the name, has a split-horizon zone without the record, or has a stale negative cache.",
        resolution=("Check the local resolver's filtering/RPZ policy for this domain.",
                    "If there is an internal zone for the domain, add the missing record.",
                    "Clear stale negative caches (ipconfig /flushdns, resolver cache)."),
        owner="DNS / security team",
        engineering=("{host}: NXDOMAIN from {dns_configured}, but {public_answer} from public DNS.",),
        wireshark=("dns.flags.rcode == 3",),
    ),
    Rule(
        "dns_sinkhole", "dns_filtered", "DNS filtering returns a sinkhole address", "L7 DNS",
        any_of=("dns.sinkhole",), base=0.88, explains=DNS_SIDE + ABOVE_DNS,
        symptom="{host} does not load (connection refused or a block page).",
        explanation="The local resolver answers {system_answer} for {host} (a sinkhole) while public DNS returns "
                    "{public_answer}: a DNS security policy is blocking the name.",
        resolution=("If the block is wrong, ask the DNS-security owner to allow-list the domain.",),
        owner="Security policy team",
        engineering=("Name, sinkhole answer, public answer, resolver IP.",),
    ),
    Rule(
        "dns_timeout", "dns_timeout", "The configured DNS server does not answer", "L7 DNS",
        any_of=("dns.timeout",), base=0.89, support=(("tcp.open", 0.04), ("capture.dns_unanswered", 0.04)),
        explains=DNS_SIDE + ABOVE_DNS,
        symptom="Every new site is slow or fails with 'Server not found' / ERR_NAME_NOT_RESOLVED; sites by IP work.",
        explanation="Queries to the configured DNS server ({dns_configured}) time out while other resolvers answer: "
                    "the DNS server is down, overloaded, or a firewall drops traffic to it.",
        resolution=("Check the DNS service on {dns_configured} and the path/firewall to it (UDP and TCP 53).",
                    "As a workaround point the client at a working resolver."),
        owner="DNS / network team",
        engineering=("Queries for {host} to {dns_configured} time out; public resolvers answer {public_answer}.",),
        wireshark=("dns.flags.response == 0 && !dns.response_in",),
    ),
    Rule(
        "dns_udp53_blocked", "dns_timeout", "Outbound DNS (UDP/53) is blocked", "L7 DNS",
        any_of=("dns.udp53_blocked",), base=0.88, support=(("capture.dns_unanswered", 0.04),),
        explains=DNS_SIDE + ABOVE_DNS,
        symptom="Names don't resolve; DNS over HTTPS (browsers with secure DNS) may still work.",
        explanation="Every UDP/53 query timed out, including to 8.8.8.8 and 1.1.1.1, while DoH over port 443 "
                    "worked: a firewall blocks DNS and the configured server ({dns_configured}) is not reachable.",
        resolution=("Allow UDP/TCP 53 from the client to its configured resolver, or fix the resolver address.",),
        owner="Network / firewall team",
        engineering=("UDP/53 to {dns_configured}, 8.8.8.8 and 1.1.1.1 times out from {egress_ip}; DoH on 443 works.",),
        wireshark=("dns",),
    ),
    Rule(
        "dns_no_dns", "dns_timeout", "No DNS server is reachable at all", "L7 DNS",
        any_of=("dns.no_dns",), base=0.8, explains=DNS_SIDE + ABOVE_DNS,
        symptom="No name resolves.",
        explanation="Neither the configured resolver ({dns_configured}) nor public resolvers (UDP or DoH) answer. "
                    "Either DNS is blocked everywhere or there is no working uplink.",
        resolution=("Check the uplink (gateway, ISP) and the DNS server.",),
        owner="Network team",
    ),
    Rule(
        "dns_dnssec", "dns_servfail", "DNSSEC validation fails for the domain", "L7 DNS",
        any_of=("dns.dnssec_failure",), base=0.9, explains=DNS_SIDE + ABOVE_DNS,
        symptom="'Server not found' for {host} on validating resolvers.",
        explanation="Resolvers return SERVFAIL, but the same query with the CD (checking disabled) bit succeeds: the "
                    "domain's DNSSEC signatures are broken or expired.",
        resolution=("The domain owner must fix its DNSSEC (re-sign the zone, fix the DS record at the parent).",),
        owner="Domain owner (DNS)",
        engineering=("Name, SERVFAIL vs CD=1 answers, `dig +dnssec` output.",),
    ),
    Rule(
        "dns_servfail", "dns_servfail", "DNS returns SERVFAIL", "L7 DNS",
        any_of=("dns.servfail", "dns.servfail_local"), base=0.85, explains=DNS_SIDE + ABOVE_DNS,
        symptom="'Server not found' for {host}.",
        explanation="The resolver cannot complete the lookup (SERVFAIL): its forwarders or the domain's authoritative "
                    "servers are failing.",
        resolution=("Check the resolver's forwarders/upstream; check the domain's NS servers answer.",),
        owner="DNS team / domain owner",
    ),
    Rule(
        "dns_nodata", "dns_nodata", "The name exists but has no IPv4 address", "L7 DNS",
        any_of=("dns.nodata",), base=0.85, explains=DNS_SIDE + ABOVE_DNS,
        symptom="'Server not found' for {host} on IPv4-only clients.",
        explanation="DNS answers NOERROR with no A record for {host}.",
        resolution=("Add the missing A record, or make sure the client has working IPv6 if the service is IPv6-only.",),
        owner="DNS owner",
    ),
    Rule(
        "dns_refused", "dns_refused", "The DNS server refuses to answer this client", "L7 DNS",
        any_of=("dns.refused",), base=0.85, explains=DNS_SIDE + ABOVE_DNS,
        explanation="The resolver answers REFUSED: it does not allow recursion for this client's address.",
        resolution=("Allow the client's subnet on the resolver, or use the correct resolver.",),
        owner="DNS team",
    ),
    Rule(
        "dns_hosts_override", "dns_hosts_override", "A hosts-file entry overrides DNS for this name", "L7 DNS",
        any_of=("dns.hosts_override",), base=0.5,
        support=(("tcp.refused:fail", 0.45), ("tcp.filtered:fail", 0.45), ("tls.hostname_mismatch", 0.45)),
        explains=("tcp.*", "tls.hostname_mismatch", "dns.answers_differ"),
        symptom="{host} fails on this machine only.",
        explanation="The hosts file maps {host} to {system_answer} (public DNS says {public_answer}); the client "
                    "never asks DNS, and the address it uses does not serve the site.",
        resolution=("Remove or correct the entry in the hosts file, then `ipconfig /flushdns`.",),
        owner="Customer desktop",
    ),
    # ----------------------------------------------------------- network path
    Rule(
        "path_unreachable", "path_unreachable", "No route to the destination (ICMP unreachable)", "L3 Network",
        any_of=("icmp.unreachable", "path.unreachable", "tcp.unreachable:fail", "path.no_route"), base=0.86,
        explains=("icmp.*", "path.*", "tcp.*", "pmtu.*", "tls.*", "http.*", "capture.icmp_unreachable"),
        symptom="Connections to {host} fail immediately with 'host unreachable' / 'network unreachable'.",
        explanation="A router on the path reports the destination {ip} as unreachable (or the client has no route "
                    "to it): a routing gap or an ACL that rejects the traffic.",
        resolution=("Check routing to {ip} at the hop that answers unreachable, and ACLs rejecting this source.",),
        owner="Network team (routing)",
        engineering=("Traceroute, the router that sent the unreachable and its code.",),
        wireshark=("icmp.type == 3",),
    ),
    Rule(
        "path_loss_latency", "path_loss_latency", "Network impairment: {impairment}", "L3 Network",
        any_of=("icmp.loss", "path.loss_from_hop", "icmp.latency_high"), base=0.62,
        support=(("icmp.loss:fail", 0.15), ("path.loss_from_hop", 0.1), ("icmp.latency_high", 0.1),
                 ("path.latency_jump", 0.05), ("capture.retransmissions", 0.05), ("icmp.jitter_high", 0.03),
                 ("tcp.intermittent", 0.03)),
        explains=("icmp.*", "path.*", "tcp.intermittent", "capture.retransmissions", "capture.syn_unanswered",
                  "tls.handshake_timeout", "http.timeout", "pmtu.*"),
        symptom="Everything to {host} is slow and flaky: pages load partially, calls stutter, timeouts.",
        explanation="Ping to {ip} shows {impairment} (jitter {jitter} ms). TCP retransmits lost segments, so every "
                    "transfer slows down and some time out.",
        resolution=("Find the segment that adds the loss/latency (MTR from both ends; check the hop where it starts).",
                    "Check that link for congestion, errors (CRC, duplex), a saturated uplink, or traffic shaping.",
                    "If it is the client's Wi-Fi/ISP: test wired / another network to confirm."),
        next_steps=("Run the test again at a different time to see whether it correlates with load.",
                    "Run an MTR from the server side towards the client to see the return path."),
        owner="Network team / ISP",
        engineering=("Ping to {ip}: {impairment}, jitter {jitter} ms; MTR table and capture attached (retransmissions: {retransmissions}).",),
        wireshark=("tcp.analysis.retransmission", "tcp.analysis.duplicate_ack"),
    ),
    # -------------------------------------------------------------------- TCP
    Rule(
        "tcp_refused", "tcp_refused", "The port is closed: connection refused (RST)", "L4 TCP",
        any_of=("tcp.refused:fail",), base=0.9, support=(("icmp.ok", 0.04), ("capture.syn_rst", 0.04)),
        against=(("dns.hosts_override", 0.1),),
        explains=("capture.syn_rst", "tls.*", "http.*"),
        symptom="'Connection refused' / ERR_CONNECTION_REFUSED to {host}:{port}, instantly.",
        explanation="{ip}:{port} answers the SYN with a TCP RST (or ICMP port-unreachable): the host is up, but no "
                    "service listens on port {port}, or a firewall REJECT rule answers for it.",
        resolution=("Check the service is running and listening on {port} (`ss -ltnp` / `netstat -ano`).",
                    "If it should be reachable: look for a host or network firewall REJECT rule for this port.",
                    "Check the client uses the right port / the service didn't move."),
        owner="Server / application owner",
        engineering=("SYN to {ip}:{port} from {egress_ip} is answered with RST.",),
        wireshark=("tcp.flags.reset == 1",),
    ),
    Rule(
        "tcp_filtered", "tcp_filtered", "Traffic to the port is silently dropped (filtered)", "L4 TCP",
        any_of=("tcp.filtered:fail",), base=0.82,
        support=(("tcp.port_specific_drop", 0.1), ("icmp.ok", 0.05), ("path.reached", 0.03),
                 ("capture.syn_unanswered", 0.04)),
        against=(("icmp.no_reply", 0.07), ("tcp.all_filtered", 0.05), ("dns.hosts_override", 0.1)),
        explains=("capture.syn_unanswered", "tcp.port_specific_drop", "tcp.all_filtered", "icmp.no_reply",
                  "path.stops", "tls.*", "http.*"),
        symptom="Connecting to {host}:{port} hangs and then times out (ERR_CONNECTION_TIMED_OUT).",
        explanation="SYNs to {ip}:{port} get no answer at all, neither SYN/ACK nor RST: a firewall or ACL drops them "
                    "(or the host is down; see whether it answers ping and other ports).",
        resolution=("Find the firewall/ACL/security group dropping TCP {port} to {ip} and allow it for this source.",
                    "If the host is down, bring it back (check ping, other ports, console)."),
        next_steps=("Compare from another network: a source-specific rule shows up as works-there/fails-here.",),
        owner="Network / firewall team",
        engineering=("SYNs from {egress_ip} to {ip}:{port} get no answer (no SYN/ACK, no RST).",),
        wireshark=("tcp.flags.syn == 1 && tcp.analysis.retransmission",),
    ),
    Rule(
        "tcp_partial", "tcp_partial", "Some servers behind {host} don't accept connections", "L4 TCP",
        any_of=("tcp.some_addresses_dead", "tcp.intermittent"), base=0.8, explains=("capture.syn_unanswered",),
        symptom="{host} works sometimes and fails sometimes.",
        explanation="Not every address/attempt succeeds: one DNS round-robin member or load-balancer backend is down.",
        resolution=("Remove the dead address from DNS / the pool, or bring the member back.",),
        owner="Server / load-balancer owner",
    ),
    # --------------------------------------------------------------- path MTU
    Rule(
        "pmtu_blackhole", "pmtu_blackhole", "Path MTU black hole: large packets are dropped without ICMP",
        "L3 Path MTU", any_of=("pmtu.blackhole",), base=0.9,
        support=(("tls.handshake_timeout", 0.05), ("capture.tls_no_server_hello", 0.04), ("local.tunnel_adapter", 0.02)),
        explains=("tls.handshake_timeout", "tls.eof", "http.timeout", "http.request_failed",
                  "capture.tls_no_server_hello", "capture.retransmissions", "pmtu.*"),
        symptom="Small things work (ping, TCP connect, tiny pages) but HTTPS hangs, large pages/downloads stall, "
                "VPN-reached apps time out.",
        explanation="DF packets up to {pmtu} bytes reach {ip}, bigger ones ({pmtu_fail_size}+) vanish and no ICMP "
                    "'fragmentation needed' comes back, so TCP never learns to send smaller segments. The TLS "
                    "handshake (large ServerHello/Certificate) is the first thing to stall. Typical inside "
                    "IPsec/GRE tunnels where a firewall drops ICMP type 3 code 4.",
        resolution=("Allow ICMP type 3 code 4 (fragmentation needed) on the tunnel and firewalls in the path.",
                    "Clamp TCP MSS on the tunnel to {pmtu_mss} (`iptables ... -j TCPMSS --clamp-mss-to-pmtu`, "
                    "`ip tcp adjust-mss {pmtu_mss}`).",
                    "Or lower the tunnel/interface MTU to {pmtu}."),
        next_steps=("Confirm with `ping -f -l {pmtu_mss} {ip}` (works) vs a 1472-byte ping (fails).",),
        owner="Network team (tunnel / firewall)",
        engineering=("DF pings to {ip}: {pmtu} bytes pass, {pmtu_fail_size}+ bytes vanish with no ICMP frag-needed; suggested MSS clamp {pmtu_mss}.",),
        wireshark=("icmp.type == 3 && icmp.code == 4", "tcp.analysis.retransmission"),
    ),
    # -------------------------------------------------------------------- TLS
    Rule(
        "client_clock_skew", "client_clock", "The client's clock is wrong", "L5-L6 TLS",
        any_of=("tls.not_yet_valid", "tls.expired"), all_of=("http.clock_skew",), predicate=_skew_explains_cert,
        base=0.9, explains=("tls.*", "http.*", "capture.tls_alert"),
        symptom="Certificate date errors (NET::ERR_CERT_DATE_INVALID) on many sites at once.",
        explanation="The device clock differs from the server's by about {clock_skew_min} minutes, which makes valid "
                    "certificates look expired or not yet valid. Kerberos also breaks beyond 5 minutes.",
        resolution=("Fix the time: enable automatic time sync (w32tm /resync, chrony/NTP).",),
        owner="Customer desktop",
    ),
    Rule(
        "tls_expired", "tls_expired", "The server's TLS certificate has expired", "L5-L6 TLS",
        any_of=("tls.expired",), base=0.93, support=(("capture.tls_alert", 0.02),),
        explains=("capture.tls_alert", "http.tls_error", "http.request_failed", "tls.expiring_soon", "tls.verify_failed"),
        symptom="'Your connection is not private' (NET::ERR_CERT_DATE_INVALID) in browsers; apps fail with "
                "'certificate has expired'.",
        explanation="The certificate presented for {host} ({cert_subject}, issued by {cert_issuer}) expired on "
                    "{cert_not_after}. DNS, routing and TCP to {ip}:{port} work; every client that validates "
                    "certificates rejects the server.",
        resolution=("Renew the certificate and install it (with its chain) on every server/load balancer for {host}.",
                    "Restart or reload the service so the new certificate is served; verify with "
                    "`openssl s_client -connect {host}:{port} -servername {host}`.",
                    "Add expiry monitoring (alert at 30/14/7 days)."),
        next_steps=("Check whether every server behind the name is affected (one stale node is common).",),
        owner="Site / application owner (PKI)",
        engineering=("Certificate {cert_subject}, issuer {cert_issuer}, notAfter {cert_not_after}, served by {ip}:{port}.",),
        wireshark=("tls.handshake.type == 11", "tls.alert_message"),
    ),
    Rule(
        "tls_not_yet_valid", "tls_not_yet_valid", "The server's certificate is not valid yet", "L5-L6 TLS",
        any_of=("tls.not_yet_valid",), base=0.85, explains=("capture.tls_alert", "http.tls_error"),
        symptom="Certificate date errors for {host}.",
        explanation="The certificate for {host} is valid only from {cert_not_before}: deployed too early, or issued "
                    "with a wrong start date (the client clock looks right).",
        resolution=("Reissue/redeploy a certificate whose validity has started.",),
        owner="Site owner (PKI)",
    ),
    Rule(
        "tls_hostname_mismatch", "tls_hostname_mismatch", "The certificate does not match the hostname",
        "L5-L6 TLS", any_of=("tls.hostname_mismatch",), unless=("http.captive_portal",), base=0.9,
        against=(("dns.hosts_override", 0.1),),
        explains=("capture.tls_alert", "http.tls_error", "http.request_failed", "tls.verify_failed"),
        symptom="'Your connection is not private' (NET::ERR_CERT_COMMON_NAME_INVALID) for {host}.",
        explanation="The server at {ip} presents a certificate for {cert_sans}, which does not cover {host}. The "
                    "wrong certificate is bound to this name/virtual host, the SAN is missing, or the name points "
                    "at the wrong server.",
        resolution=("Install a certificate whose SAN list includes {host} (or a matching wildcard).",
                    "Check the TLS SNI/virtual-host binding on the server or load balancer.",
                    "Check DNS for {host} points at the intended server."),
        owner="Site / application owner",
        engineering=("SNI {host} sent to {ip}:{port}; the certificate covers only {cert_sans}.",),
    ),
    Rule(
        "tls_intercepted_untrusted", "tls_untrusted_ca", "TLS is intercepted by {tls_vendor}, whose root CA is not trusted",
        "L5-L6 TLS", any_of=("tls.intercepted_untrusted",), base=0.92,
        explains=("capture.tls_alert", "http.tls_error", "http.request_failed", "tls.untrusted"),
        symptom="Certificate errors (NET::ERR_CERT_AUTHORITY_INVALID) on HTTPS sites; the issuer is {cert_issuer}.",
        explanation="The certificate for {host} was minted by {tls_vendor} (issuer {cert_issuer}): TLS is being "
                    "inspected, but this device does not have that inspection root CA installed.",
        resolution=("Install the {tls_vendor} root certificate on the device (MDM/GPO), and in apps with their own "
                    "trust store (Java, Python, Node, Firefox).",
                    "If the device should not be inspected, fix the SSL-inspection policy/bypass."),
        owner="Security / endpoint team",
        engineering=("Presented chain: {cert_subject} issued by {cert_issuer}, root {cert_root}; device {client}.",),
    ),
    Rule(
        "tls_untrusted", "tls_untrusted_ca", "The certificate is issued by an untrusted CA", "L5-L6 TLS",
        any_of=("tls.untrusted",), base=0.9,
        explains=("capture.tls_alert", "http.tls_error", "http.request_failed", "tls.private_root_public_site"),
        symptom="'Your connection is not private' (NET::ERR_CERT_AUTHORITY_INVALID) for {host}.",
        explanation="The chain for {host} ends at {cert_root} (issuer {cert_issuer}), which neither this device nor "
                    "the public root list trusts. Either the server uses a private CA the device doesn't know, or a "
                    "device in the path (an intercepting proxy, a man in the middle) is re-signing the traffic.",
        resolution=("If the site is public: find what re-signs the traffic (proxy, security software, MITM) and "
                    "remove it or install its root deliberately.",
                    "If it's an internal site: distribute the internal root CA to clients.",
                    "If the server is misconfigured: install a certificate from a trusted CA."),
        owner="Security team / site owner",
        engineering=("Full chain (subjects, issuers, fingerprints), vantage point, whether other networks see the "
                     "same chain.",),
    ),
    Rule(
        "tls_self_signed", "tls_self_signed", "The server uses a self-signed certificate", "L5-L6 TLS",
        any_of=("tls.self_signed",), base=0.88, explains=("capture.tls_alert", "http.tls_error"),
        symptom="Certificate warnings for {host}.",
        explanation="{host} presents a self-signed certificate ({cert_subject}) that no trust store contains.",
        resolution=("Replace it with a certificate from a trusted (public or internal) CA.",),
        owner="Site owner",
    ),
    Rule(
        "tls_incomplete_chain", "tls_incomplete_chain", "The server does not send its intermediate certificate",
        "L5-L6 TLS", any_of=("tls.incomplete_chain",), base=0.9, explains=("capture.tls_alert", "http.tls_error"),
        symptom="Works in some browsers, fails in curl/Python/Java/mobile apps with 'unable to get local issuer'.",
        explanation="{host} sends only its leaf certificate, not the intermediate ({cert_issuer}). Browsers can fetch "
                    "it via AIA; most other clients can't.",
        resolution=("Configure the server to send the full chain (leaf + intermediates).",),
        owner="Site owner",
    ),
    Rule(
        "tls_weak", "tls_weak", "The certificate chain uses cryptography clients reject", "L5-L6 TLS",
        any_of=("tls.weak_crypto",), base=0.88, explains=("capture.tls_alert", "http.tls_error"),
        explanation="A certificate in {host}'s chain is signed with a weak algorithm or key (e.g. SHA-1).",
        resolution=("Reissue the chain with SHA-256+ signatures and 2048-bit+ RSA or ECDSA keys.",),
        owner="Site owner",
    ),
    Rule(
        "tls_old_protocol", "tls_old_protocol", "The server only supports TLS 1.0/1.1", "L5-L6 TLS",
        any_of=("tls.old_protocol",), base=0.88, explains=("capture.tls_alert", "http.*", "tls.old_version"),
        symptom="ERR_SSL_VERSION_OR_CIPHER_MISMATCH / 'protocol version' errors for {host}.",
        explanation="{host} negotiates only an obsolete TLS version that current clients refuse (RFC 8996).",
        resolution=("Enable TLS 1.2 and 1.3 on the server.",),
        owner="Site owner",
    ),
    Rule(
        "tls_os_store", "tls_os_trust_store", "This device's trust store lacks the site's (public) root",
        "L5-L6 TLS", any_of=("tls.os_store_missing_root",), base=0.72,
        symptom="Browsers work; Python/Java tools on this device fail with certificate errors.",
        explanation="The chain is publicly trusted, but the OS store on this device does not contain its root yet.",
        resolution=("Run Windows Update / update the CA bundle, or install the root.",),
        owner="Customer desktop",
    ),
    Rule(
        "tls_reset", "tls_blocked", "The connection is reset during the TLS handshake", "L5-L6 TLS",
        any_of=("tls.reset", "capture.tls_reset"), base=0.8, explains=("capture.tls_reset", "http.*"),
        symptom="ERR_CONNECTION_RESET for {host}.",
        explanation="Right after the ClientHello (which carries SNI {host}) the connection is reset: an SNI-based "
                    "firewall/IPS block, or the port does not speak TLS.",
        resolution=("Check firewall/IPS/URL-filtering logs for this SNI; allow it if legitimate.",),
        owner="Security / firewall team",
        wireshark=("tls.handshake.extensions_server_name", "tcp.flags.reset == 1"),
    ),
    Rule(
        "tls_handshake_stall", "tls_handshake_stall", "The TLS handshake stalls after TCP connects", "L5-L6 TLS",
        any_of=("tls.handshake_timeout",), unless=("pmtu.blackhole",), base=0.66,
        support=(("capture.tls_no_server_hello", 0.1), ("pmtu.reduced", 0.04)),
        explains=("capture.tls_no_server_hello", "http.timeout", "http.request_failed"),
        symptom="HTTPS to {host} hangs; TCP connects.",
        explanation="TCP to {ip}:{port} works but no ServerHello arrives. The usual cause is an MTU black hole "
                    "(the sweep could not confirm it), otherwise a middlebox discarding TLS.",
        resolution=("Test path MTU with DF pings / lower the MTU to confirm; check middleboxes for TLS drops.",),
        owner="Network team",
    ),
    Rule(
        "tls_handshake_error", "tls_handshake_error", "The TLS handshake fails", "L5-L6 TLS",
        any_of=("tls.alert", "tls.eof", "tls.not_tls", "tls.handshake_failed", "tls.verify_failed",
                "tls.no_certificate", "tls.connect_failed"), base=0.75,
        explains=("capture.tls_alert", "http.*"),
        explanation="The TLS handshake with {host} fails (see the TLS evidence for the alert or error).",
        resolution=("Compare the client's offer (versions, ciphers, SNI) with the server's configuration.",),
        owner="Site owner",
    ),
    Rule(
        "tls_inspection", "tls_inspection", "TLS to {host} is inspected (re-signed) by {tls_vendor}", "L5-L6 TLS",
        any_of=("tls.intercepted", "tls.private_root_public_site"), base=0.6,
        symptom="Browsers work; apps with certificate pinning or their own trust store fail on {host}.",
        explanation="The certificate is issued by {cert_issuer}, chaining to {cert_root}, a root installed on this "
                    "device rather than a public CA: TLS is being inspected. Pinned apps and tools that ignore the "
                    "OS store (Java, Python, Git, Docker) will reject it.",
        resolution=("Add the failing app/domain to the SSL-inspection bypass list, or",
                    "add the inspection root CA to the app's trust store."),
        owner="Security policy team",
    ),
    # ------------------------------------------------------------------- HTTP
    Rule(
        "captive_portal", "captive_portal", "A captive portal intercepts the traffic", "L7 HTTP",
        any_of=("http.captive_portal",), base=0.94,
        explains=("tls.*", "http.*", "capture.*", "dns.answers_differ", "dns.split_horizon"),
        symptom="Sites redirect to a login/terms page; HTTPS sites show certificate errors or time out.",
        explanation="Plain-HTTP requests are redirected to a portal ({captive_signals}). Until the user logs in or "
                    "accepts the terms, the network intercepts traffic, which also explains the TLS errors.",
        resolution=("Open any http:// page (e.g. http://neverssl.com) and complete the portal login/terms.",
                    "If this should not happen (managed network): check the guest/NAC policy for this device."),
        owner="Customer / network (NAC, guest Wi-Fi)",
    ),
    Rule(
        "http_upstream_error", "http_upstream_error", "The site's backend is failing (HTTP {http_status})", "L7 HTTP",
        any_of=("http.bad_gateway", "http.gateway_timeout", "http.unavailable"),
        predicate=lambda f: not f.get("http_by_proxy"), base=0.9,
        explains=("http.no_hsts", "capture.server_reset"),
        symptom="An error page '{http_status} {http_reason}' from {host}.",
        explanation="DNS, routing, TCP and TLS to {host} all work. The front end ({http_server}) answers "
                    "{http_status} because it cannot get a valid response from its upstream application: the backend "
                    "is down, crashing, or timing out.",
        resolution=("Check the backend/upstream servers behind the front end (health checks, process status, logs).",
                    "Check the front end's upstream configuration (address/port) and its connect/read timeouts."),
        next_steps=("Note the exact time and any request ID header so the app team can find the request in logs.",),
        owner="Application owner",
        engineering=("{target} returned {http_status} {http_reason} from Server: {http_server}; add any request-ID header from the response.",),
        wireshark=("http.response.code >= 500",),
    ),
    Rule(
        "http_server_error", "http_server_error", "The application returns a server error (HTTP {http_status})",
        "L7 HTTP", any_of=("http.server_error",), base=0.85,
        explanation="The application at {host} fails while handling the request (HTTP {http_status}).",
        resolution=("Check the application logs for the request at the time of the run.",),
        owner="Application owner",
    ),
    Rule(
        "http_redirect_loop", "http_redirect_loop", "The site redirects in a loop", "L7 HTTP",
        any_of=("http.redirect_loop", "http.too_many_redirects"), base=0.85,
        symptom="ERR_TOO_MANY_REDIRECTS.",
        explanation="The redirect chain for {target} never ends (HTTP/HTTPS or cookie/login redirect misconfiguration).",
        resolution=("Fix the redirect rules (often HTTPS redirect + proxy/LB terminating TLS).",),
        owner="Application owner",
    ),
    Rule(
        "http_access_denied", "http_access_denied", "The site refuses access (HTTP {http_status})", "L7 HTTP",
        any_of=("http.forbidden", "http.auth_required"), base=0.8,
        explanation="The network path works; {host} answers {http_status} {http_reason}: authentication, a WAF rule "
                    "or an IP/geo restriction.",
        resolution=("Check credentials/permissions, WAF logs or IP allow-lists on the site.",),
        owner="Application owner",
    ),
    Rule(
        "http_not_found", "http_not_found", "The URL does not exist on the server (HTTP 404)", "L7 HTTP",
        any_of=("http.not_found",), base=0.78,
        explanation="The network path works; the server has no resource at {target}.",
        resolution=("Check the URL/path; check the deployment if it used to work.",),
        owner="Application owner",
    ),
    Rule(
        "http_rate_limited", "http_rate_limited", "The site rate-limits this client (HTTP 429)", "L7 HTTP",
        any_of=("http.rate_limited",), base=0.78,
        explanation="{host} answers 429 Too Many Requests.",
        resolution=("Reduce request rate / check whether many users share one egress IP (NAT, proxy).",),
        owner="Application owner",
    ),
    Rule(
        "http_timeout", "http_timeout", "The server accepts connections but never answers HTTP", "L7 HTTP",
        any_of=("http.timeout",), unless=("pmtu.blackhole",), base=0.7,
        explanation="TCP (and TLS) to {host} work, but the HTTP request gets no response in time.",
        resolution=("Check the application is processing requests (hung workers, thread pool exhaustion).",),
        owner="Application owner",
    ),
]

NO_FAULT = Rule(
    "no_fault", "no_fault", "No fault found from this client", "-", any_of=(), base=0.75,
    symptom="The user reports a problem with {target}, but it could not be reproduced from this vantage point.",
    explanation="Every layer from the local network to HTTP works for {target} from {client}: DNS resolves, the "
                "path and port are reachable, TLS validates and HTTP answers.",
    resolution=("Ask for the exact error, time and URL; check whether it is intermittent or limited to one app.",
                "Re-run NetDoctor on the affected device and network at the time of the problem."),
    next_steps=("If the problem is intermittent, run NetDoctor repeatedly (e.g. every 5 minutes) and compare.",),
    owner="Support (gather more information)",
)

UNCLASSIFIED = Rule(
    "unclassified", "unclassified", "Unclassified failure: {first_fail}", "-", any_of=(), base=0.4,
    explanation="NetDoctor found a failure that no rule covers yet: {first_fail}",
    resolution=("Review the evidence below; add a rule if this pattern recurs.",),
    owner="Support (manual analysis)",
)
