# How NetDoctor works

This document explains every protocol NetDoctor touches, in the order it tests them, and connects each one to what shows up in real support tickets. Each section ends with the manual commands that reproduce NetDoctor's test and the Wireshark display filters that show the evidence in a capture.

All addresses in the examples come from the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) or from private ranges, so none of them point at a real host.

## Contents

1. [Troubleshooting bottom-up](#1-troubleshooting-bottom-up)
2. [The OSI model and TCP/IP](#2-the-osi-model-and-tcpip)
3. [ARP](#3-arp)
4. [DNS resolution](#4-dns-resolution)
5. [TCP](#5-tcp)
6. [ICMP](#6-icmp)
7. [Traceroute, TTL and MTR](#7-traceroute-ttl-and-mtr)
8. [Path MTU discovery](#8-path-mtu-discovery)
9. [TLS](#9-tls)
10. [HTTP and proxies](#10-http-and-proxies)
11. [IPsec and IKE](#11-ipsec-and-ike)
12. [Packet capture and the capture summary](#12-packet-capture-and-the-capture-summary)
13. [The verdict engine and the incident report](#13-the-verdict-engine-and-the-incident-report)
14. [Cheat sheet](#14-cheat-sheet)

---

## 1. Troubleshooting bottom-up

"The site doesn't load" is a symptom, not a diagnosis. The browser shows much the same error page whether the laptop has no IP address, the DNS server is down, a firewall drops port 443, a proxy wants credentials, the certificate expired, or the application behind a load balancer crashed. A support engineer's job is to find the **lowest layer that fails** and collect evidence for it, because every layer above it fails as a side effect.

`netdoctor diagnose <url|host>` runs its checks in this order:

| # | Check | Question it answers | Needs from the layer below |
|---|-------|---------------------|----------------------------|
| 1 | Local | Does this machine have an address, a default gateway it can reach at layer 2, a route, and which proxy will apps use? | nothing |
| 2 | DNS | Does the name resolve, and do different resolvers agree? | a working local network |
| 3 | ICMP | Is the destination reachable at layer 3, with how much loss, latency and jitter? | an IP address from DNS |
| 4 | Path | Where along the path do loss and latency start? (traceroute plus an MTR-style table) | L3 reachability |
| 5 | TCP | Does the service port accept connections? Is a closed port refused or filtered? | a route to the host |
| 6 | Path MTU | Can full-size packets cross the path, or is there an MTU black hole? | L3 reachability |
| 7 | TLS | Version, cipher, ALPN, SNI, chain, expiry, hostname, trust, interception | an open TCP port |
| 8 | HTTP | Status, redirects, headers, HSTS, proxy authentication, captive portals | a TLS session (for https) |

Order matters for two reasons.

1. **Dependencies.** Each layer depends on the one below. If ARP cannot resolve the gateway, DNS will time out, because the DNS server is off-subnet and every query has to go through the gateway. Someone who starts at DNS will "fix DNS" and get nowhere. Testing bottom-up makes the first failure the most likely root cause, and lets NetDoctor mark higher checks as skipped instead of piling up misleading secondary failures.
2. **Masking.** A failure at one layer can hide behind a success at another, so no single test is conclusive. ICMP may be blocked while TCP works fine. A proxy may complete the TCP handshake for a server that is actually down. A certificate may validate only because a TLS-inspecting proxy re-signed it. For this reason NetDoctor records evidence from every layer it can reach, and the verdict engine ([section 13](#13-the-verdict-engine-and-the-incident-report)) weighs the evidence together rather than trusting one result.

Every check records three things: a status, the evidence behind it, and the equivalent manual commands. That way an engineer can paste the results into a ticket and anyone can reproduce them.

---

## 2. The OSI model and TCP/IP

The OSI model is a vocabulary for saying where a problem lives. The Internet actually runs on the simpler four-layer TCP/IP model, but support teams still say "layer 2 problem" or "layer 7 load balancer".

| Layer | Name | PDU | Example protocols | Example failure | NetDoctor check |
|-------|------|-----|-------------------|-----------------|-----------------|
| 7 | Application | message | HTTP, DNS, SMTP | HTTP 502 from a reverse proxy, 407 from a forward proxy | HTTP, DNS |
| 6 | Presentation | data | TLS record encryption, character encodings | certificate expired, unknown CA | TLS |
| 5 | Session | data | TLS session setup and resumption, RPC | handshake failure alert | TLS |
| 4 | Transport | segment (TCP), datagram (UDP) | TCP, UDP | port refused (RST) or filtered (timeout) | TCP |
| 3 | Network | packet | IPv4, IPv6, ICMP, IPsec ESP | no route, packet loss, MTU black hole | ICMP, Path, Path MTU |
| 2 | Data link | frame | Ethernet, 802.11, 802.1Q VLANs, ARP | gateway MAC not resolved, wrong VLAN | Local (ARP/neighbor table) |
| 1 | Physical | bits | copper, fiber, radio | cable unplugged, weak Wi-Fi signal | Local (interface up/down) |

TCP/IP collapses this into **Link** (OSI 1 and 2), **Internet** (3), **Transport** (4) and **Application** (5 to 7). TLS doesn't fit neatly into either model. It runs on top of TCP and below HTTP, so it is usually described as sitting between layers 4 and 7.

### Encapsulation and header overhead

Each layer wraps the data from the layer above in its own header:

```
+-------------+-----------+----------+--------------------------+---------+
| Ethernet 14 | IPv4 20   | TCP 20   | application data         | FCS 4   |
+-------------+-----------+----------+--------------------------+---------+
              |<--------------- IP packet (MTU 1500) ----------->|
|<------------------------ Ethernet frame (1518) -------------------------->|
```

| Header | Size | Notes |
|--------|------|-------|
| Ethernet II | 14 bytes + 4-byte FCS trailer | 6-byte destination MAC, 6-byte source MAC, 2-byte EtherType (0x0800 IPv4, 0x86DD IPv6, 0x0806 ARP). An 802.1Q VLAN tag adds 4 bytes. On the wire there are also 8 bytes of preamble and SFD, plus a 12-byte inter-frame gap. |
| IPv4 | 20 bytes (up to 60 with options) | TTL, protocol number (1 ICMP, 6 TCP, 17 UDP, 50 ESP), DF/MF flags, source and destination addresses |
| IPv6 | 40 bytes, fixed | Hop Limit replaces TTL. Routers never fragment IPv6 packets. |
| TCP | 20 bytes (up to 60 with options) | Timestamps alone add 12 bytes to every segment |
| UDP | 8 bytes | ports, length, checksum |
| ICMP | 8 bytes | type, code, checksum, plus 4 bytes that depend on the type |

The **MTU** (maximum transmission unit) counts the layer-3 packet, not the Ethernet header. On standard Ethernet with an MTU of 1500:

- The largest TCP payload per segment, the **MSS**, is 1500 − 20 (IP) − 20 (TCP) = **1460** bytes, or 1448 when TCP timestamps are in use.
- The largest ICMP echo payload is 1500 − 20 − 8 = **1472** bytes. That number shows up again in the path MTU section.

---

## 3. ARP

IP addresses are logical, but an Ethernet or Wi-Fi frame must carry a destination **MAC address**. ARP (RFC 826) maps an IPv4 address on the local subnet to a MAC address.

A host decides where to send each packet. If the destination is on its own subnet, it ARPs for the destination itself. Otherwise it ARPs for its **default gateway**, puts the gateway's MAC address in the frame, and leaves the IP destination unchanged.

```
Host 192.168.1.20 (MAC 00:1a:2b:3c:4d:5e)                Gateway 192.168.1.1
   |                                                             |
   |  ARP request, opcode 1, to ff:ff:ff:ff:ff:ff (broadcast)    |
   |  "Who has 192.168.1.1? Tell 192.168.1.20"                   |
   |------------------------------------------------------------>|
   |                                                             |
   |  ARP reply, opcode 2, unicast to 00:1a:2b:3c:4d:5e          |
   |  "192.168.1.1 is at 3c:84:6a:11:22:33"                      |
   |<------------------------------------------------------------|
   |                                                             |
   |  IP packet to 198.51.100.20, Ethernet dst 3c:84:6a:11:22:33 |
   |------------------------------------------------------------>|
```

ARP frames use EtherType 0x0806. They carry the sender's MAC and IP and the target's MAC and IP. In a request the target MAC is all zeros because that is the unknown being asked for. Requests are **broadcast**, so every host in the layer-2 domain (the VLAN) receives them. Replies are **unicast** back to the requester.

### The ARP cache

Results are cached so the host doesn't ARP for every packet. Entries go through states: Linux shows REACHABLE, STALE, DELAY, PROBE, INCOMPLETE and FAILED, and Windows `Get-NetNeighbor` shows Reachable, Stale, Probe, Incomplete, Unreachable and Permanent. Static entries never expire. A stale entry is not a problem by itself; it is revalidated the next time it is used.

### Gratuitous ARP

A gratuitous ARP is an unsolicited announcement of a host's own mapping, with the sender IP equal to the target IP. It is used:

- when an interface comes up or its MAC address changes,
- by first-hop redundancy protocols (VRRP, HSRP) when a backup router takes over the virtual gateway IP, so that switches and hosts update their tables at once,
- to detect duplicate addresses. RFC 5227 ARP probes use sender IP 0.0.0.0; if anyone answers, the address is already taken.

Two hosts with the same IP produce intermittent, maddening symptoms. Connectivity flips depending on whose MAC address the gateway cached last.

### What a bad gateway entry tells you

If the default gateway's entry is **INCOMPLETE/FAILED** (Linux) or **Unreachable/Incomplete** (Windows), the host sent ARP requests and got no reply. Nothing off-subnet can work, and the user typically reports "DNS is broken", because DNS is the first thing that times out. Usual causes:

- The gateway is down, or its interface is shut.
- The host is on the wrong VLAN or SSID, so the gateway is in a different broadcast domain.
- A cable, switch port, port security or 802.1X problem.
- A static IP configuration with a wrong mask or gateway, so the gateway isn't on the host's subnet.

An entry can also be missing simply because nothing has talked to the gateway recently. An absent entry is therefore weaker evidence than one stuck in INCOMPLETE/FAILED or Unreachable.

An address in **169.254.0.0/16** (APIPA, RFC 3927) means the host asked for DHCP and got no offer, so it assigned itself a link-local address. There is no default gateway in that case. Look at DHCP, the VLAN, or the physical link, not at DNS.

IPv6 replaces ARP with Neighbor Discovery: ICMPv6 Neighbor Solicitation (type 135) and Neighbor Advertisement (type 136).

**What NetDoctor does:** the Local check lists the interfaces with their state, addresses and MTU, finds the default gateway(s) in the routing table, and looks up each gateway in the ARP/neighbor table to show whether its MAC address is resolved.

| Task | Windows | Linux |
|------|---------|-------|
| Show the ARP cache | `arp -a`, `Get-NetNeighbor -AddressFamily IPv4` | `ip neigh` |
| Show addresses and gateway | `ipconfig /all`, `route print -4` | `ip addr`, `ip route` |

Wireshark: `arp`, `arp.opcode == 1` (requests), `arp.duplicate-address-detected`.

---

## 4. DNS resolution

### How a name gets resolved

An application calls the operating system's resolver, for example `getaddrinfo()`. The OS checks the hosts file and its cache, then sends a **recursive** query (RD=1, "recursion desired") to its configured DNS server. That recursive resolver walks the tree **iteratively** on the client's behalf:

```
App        OS stub resolver     Recursive resolver     Root      .com TLD    example.com authoritative
 |  getaddrinfo  |                     |                 |           |              |
 |-------------->|  A? www.example.com (RD=1)            |           |              |
 |               |-------------------->|  A? www...      |           |              |
 |               |                     |---------------->|           |              |
 |               |                     |<- referral: .com NS records |              |
 |               |                     |---------------------------->|              |
 |               |                     |<- referral: example.com NS -|              |
 |               |                     |------------------------------------------->|
 |               |                     |<- A 203.0.113.10, TTL 300, AA=1 -----------|
 |               |<- answer (RA=1) ----|                                            |
 |<- 203.0.113.10|                                                                  |
```

Every answer carries a **TTL**. Resolvers and clients cache it for that many seconds, which is why a DNS change takes time to "propagate". The old record lives on in caches until its TTL runs out.

**Negative caching** (RFC 2308): an NXDOMAIN or NODATA answer is cached too. It is kept for the lower of the SOA record's TTL and its MINIMUM field. If a record was missing and has just been created, users can keep getting NXDOMAIN until the negative TTL expires or someone flushes the cache.

### Where answers can come from before DNS is asked

- **The hosts file** (`C:\Windows\System32\drivers\etc\hosts`, `/etc/hosts`) is checked before DNS by default. On Linux the order is set in `/etc/nsswitch.conf` (`hosts: files dns`). A forgotten hosts entry is a classic cause of "it works for everyone except this one laptop".
- **The Windows DNS Client cache** holds positive answers, negative answers and the hosts-file entries. You can view it with `ipconfig /displaydns` and clear it with `ipconfig /flushdns`.
- **The NRPT** (Name Resolution Policy Table) on Windows sends queries for specific namespaces to specific DNS servers. DirectAccess, Always On VPN and zero-trust or private-access clients use it, so that `*.corp.example.com` goes to an internal resolver while everything else uses the normal one. Use `Get-DnsClientNrptPolicy` to see the active rules.
- **Search suffixes:** a single-label name such as `intranet` gets the primary or connection-specific DNS suffix appended (`intranet.corp.example.com`). On Linux the `search` and `options ndots:` lines in `/etc/resolv.conf` control this.

A key gotcha: **`nslookup` does not use the OS resolver.** It sends queries straight to a DNS server and ignores the hosts file, the DNS client cache and the NRPT. `Resolve-DnsName` and `getent ahosts` go through the OS stack like applications do. When `nslookup` and the browser disagree, this is usually why.

### Message flags and response codes

| Flag | Meaning |
|------|---------|
| QR | 0 = query, 1 = response |
| AA | Authoritative Answer: the answer came from a server authoritative for the zone |
| TC | Truncated: the response didn't fit, so retry over TCP |
| RD / RA | Recursion Desired (set by the client) / Recursion Available (set by the server) |
| AD | Authenticated Data: the resolver validated the answer with DNSSEC |
| CD | Checking Disabled: the client asks the resolver not to do DNSSEC validation |

| RCODE | Name | Meaning in a ticket |
|-------|------|---------------------|
| 0 | NOERROR | Success. If the answer section is empty, it is **NODATA**: the name exists but has no record of that type (for example, an A record but no AAAA). |
| 2 | SERVFAIL | The resolver tried and failed. Causes include unreachable authoritative servers, a DNSSEC validation failure, or a broken delegation. |
| 3 | NXDOMAIN | The name does not exist at all: a typo, a deleted record, or an internal-only name asked of a public resolver |
| 5 | REFUSED | The server won't answer this client, for example an authoritative-only server or a resolver with an ACL |
| 1 / 4 | FORMERR / NOTIMP | Malformed query or unsupported operation. Rare, and often a middlebox mangling EDNS. |

### Transport and timeouts

DNS uses **UDP port 53** by default. Without EDNS(0) (RFC 6891) a UDP response is limited to 512 bytes. With EDNS the client advertises a larger buffer; 1232 bytes is a common safe value since DNS Flag Day 2020. If a response is still too large, the server sets **TC=1** and the client retries over **TCP port 53**. A firewall that allows UDP/53 but blocks TCP/53 breaks large responses, such as DNSSEC-signed answers or names with many records, while small names keep working.

A **timeout** is not the same as **SERVFAIL**. A timeout means no answer arrived at all: the server is down, the path is broken, or UDP/53 is filtered. SERVFAIL means a resolver answered and said "I couldn't". Clients retry across their configured servers with growing timeouts. On Linux, glibc's defaults are `timeout:5` and `attempts:2`. So one dead DNS server can add seconds of delay before every connection even when the second server works.

### DNSSEC failures and the CD-bit trick

A validating resolver (8.8.8.8 and 1.1.1.1 both validate) returns **SERVFAIL** when DNSSEC validation fails, for example because of expired RRSIG signatures or a DS record in the parent zone that doesn't match the child's keys. To confirm it, repeat the query with the **CD** bit set (`dig +cd`). If the name resolves with CD=1 and fails without it, the problem is the domain's DNSSEC, which only the domain owner can fix. Newer resolvers also attach **Extended DNS Errors** (RFC 8914), such as EDE 6 "DNSSEC Bogus", 7 "Signature Expired", 15 "Blocked", 17 "Filtered" and 22 "No Reachable Authority". `dig` prints these.

### DNS over HTTPS

DoH (RFC 8484) carries ordinary DNS messages inside HTTPS, either as a POST body or as a base64url `?dns=` GET parameter, to a URL such as `https://1.1.1.1/dns-query`, with media type `application/dns-message`. To a firewall it looks like any other HTTPS on port 443. That makes it a useful diagnostic: if DoH works but plain UDP/53 to the same provider doesn't, port 53 is being filtered. Many enterprises block or disable DoH so that DNS stays visible to their security controls. Firefox, for example, checks the canary domain `use-application-dns.net` and won't enable DoH by default if that name returns NXDOMAIN.

### Why different resolvers give different answers

| Pattern | Usual explanation | Fault? |
|---------|-------------------|--------|
| Different public IPs from each resolver | CDN or GeoDNS steering by resolver location. Resolvers also differ on EDNS Client Subnet (RFC 7871): Google sends it, Cloudflare does not. | No |
| Internal resolver returns a private IP, public resolvers a public one | Split-horizon DNS: an internal view of the same name | Usually expected |
| Internal resolver returns NXDOMAIN, public resolvers resolve it | DNS filtering or a block policy, or a split-horizon zone that is missing the record | Often |
| `0.0.0.0`, `127.0.0.1` or a block-page IP | DNS sinkhole or filter (enterprise DNS security, Pi-hole, and similar) | Policy, not a network fault |
| Answer in **100.64.0.0/10** | RFC 6598 shared address space, used by carrier-grade NAT. Private-access (ZPA-style) clients also commonly hand out synthetic IPs from this range for private applications and route them into their tunnel. | Expected if the app is published through such a service |
| Only the system resolver differs | Hosts-file entry, a stale local cache, or an NRPT rule | Check locally |

### What NetDoctor compares

NetDoctor asks for the same name several ways and compares the results:

1. **The system resolver** (`getaddrinfo`): exactly what applications see, including the hosts file, caches and the NRPT.
2. **The configured DNS servers, queried directly**, which shows the real RCODE and TTL. `getaddrinfo` hides those details.
3. **8.8.8.8** and **1.1.1.1** over UDP/53.
4. **DoH** to `https://1.1.1.1/dns-query`.

| System | Configured server | 8.8.8.8 / 1.1.1.1 | DoH | Likely meaning |
|--------|-------------------|-------------------|-----|----------------|
| fails | timeout | OK | OK | The local DNS server is down or unreachable |
| fails | NXDOMAIN | OK | OK | Filtering or split-horizon on the internal resolver |
| fails | NXDOMAIN | NXDOMAIN | NXDOMAIN | The name really doesn't exist (typo, deleted record, internal-only name) |
| OK | OK | timeout | OK | Outbound UDP/53 is blocked except to approved resolvers. Normal in enterprises, but it explains why `nslookup host 8.8.8.8` times out. |
| fails | timeout | timeout | timeout | No DNS path at all. Look lower: gateway, routing, Internet uplink. |
| SERVFAIL | SERVFAIL | SERVFAIL | SERVFAIL | Broken DNSSEC or unreachable authoritative servers. A domain-owner problem; confirm with CD=1. |
| answer X | answer Y | answer Y | answer Y | Hosts-file override or a stale local cache |
| sinkhole IP | sinkhole IP | real IP | real IP | A DNS filtering policy |

| Task | Windows | Linux / cross-platform |
|------|---------|------------------------|
| Resolve like an application | `Resolve-DnsName www.example.com` | `getent ahosts www.example.com` |
| Ask a specific server | `Resolve-DnsName www.example.com -Server 8.8.8.8 -DnsOnly`, `nslookup www.example.com 1.1.1.1` | `dig @1.1.1.1 www.example.com` |
| DNSSEC check | `Resolve-DnsName www.example.com -DnssecCd` | `dig +dnssec www.example.com`, `dig +cd www.example.com` |
| DoH | browser or curl | `dig @1.1.1.1 +https www.example.com` (BIND 9.18+), `curl -H "accept: application/dns-json" "https://1.1.1.1/dns-query?name=www.example.com&type=A"` |
| Cache | `ipconfig /displaydns`, `ipconfig /flushdns` | `resolvectl statistics`, `resolvectl flush-caches` |
| Which servers and rules | `Get-DnsClientServerAddress`, `Get-DnsClientNrptPolicy` | `resolvectl status`, `cat /etc/resolv.conf` |

Wireshark: `dns`, `dns.flags.rcode != 0`, `dns.flags.rcode == 3` (NXDOMAIN), `dns.flags.truncated == 1`, `dns.time > 1` (slow responses).

---

## 5. TCP

### The header fields that matter

| Field | Size | Why support cares |
|-------|------|-------------------|
| Source / destination port | 16 bits each | Which service; ephemeral client ports are usually 49152–65535 on Windows and 32768–60999 on Linux |
| Sequence number | 32 bits | Byte position of this segment's data. The initial sequence number (ISN) is random (RFC 6528). |
| Acknowledgment number | 32 bits | Next byte the sender expects to receive |
| Flags | SYN, ACK, FIN, RST, PSH, URG, ECE, CWR | SYN opens, FIN closes gracefully, RST aborts, PSH means "deliver now" |
| Window | 16 bits | Receive buffer space available, multiplied by the window-scale factor |
| Options | up to 40 bytes | MSS (kind 2), window scale (kind 3), SACK permitted (kind 4), SACK blocks (kind 5), timestamps (kind 8) |

### The three-way handshake

```
Client 192.0.2.10:50514                                  Server 198.51.100.20:443
   |                                                              |
   |  SYN  seq=1000  win=64240  <MSS 1460, WS 8, SACK_PERM, TS>   |
   |------------------------------------------------------------->|
   |                                                              |
   |  SYN,ACK  seq=7000 ack=1001  <MSS 1460, WS 7, SACK_PERM, TS> |
   |<-------------------------------------------------------------|
   |                                                              |
   |  ACK  seq=1001 ack=7001                                      |
   |------------------------------------------------------------->|
   |                   ESTABLISHED (one round trip)               |
```

Each side picks a random ISN, and the SYN and FIN flags each consume one sequence number, which is why the ACKs above are ISN + 1. Wireshark shows relative sequence numbers that start at 0 by default. The time from SYN to SYN/ACK is a clean measure of round-trip time at the TCP layer. NetDoctor reports it, which is useful when ICMP is blocked and ping can't measure latency.

**Options are negotiated only in the SYN packets.**

- **MSS:** each side advertises the largest segment it can receive, normally its interface MTU minus 40 (1460 on Ethernet). Each side sends segments no larger than the peer's MSS. MSS knows nothing about links further along the path; path MTU discovery and MSS clamping (section 8) handle those.
- **Window scale** (RFC 7323): the window field is only 16 bits (65,535 bytes max). The scale option shifts it left by up to 14 bits. A middlebox that strips this option silently caps throughput on high-latency links.
- **SACK:** lets the receiver report which blocks arrived, so only the gaps are resent.
- **Timestamps:** used for RTT measurement and PAWS (protection against wrapped sequence numbers).

### Data transfer and retransmission

The sender keeps unacknowledged data in flight up to the smaller of the receiver's window and its own congestion window. Lost data is resent in two ways:

- **Retransmission timeout (RTO):** RFC 6298 sets the initial RTO at 1 second and doubles it after each timeout.
- **Fast retransmit** (RFC 5681): three **duplicate ACKs**, each acknowledging the same byte, signal that a segment was lost while later ones arrived. The sender resends right away without waiting for the RTO.

A lost SYN is resent with exponential backoff. Linux retries six times by default (`net.ipv4.tcp_syn_retries`), which adds up to about two minutes; Windows gives up much sooner. That is why a filtered port makes a client hang until a timeout, while a refused port fails at once.

A **zero window** means the receiver's buffer is full: its application isn't reading data fast enough. The sender stops and sends small zero-window probes until the window opens. This is a problem on the receiving host (a slow application, disk or CPU), not on the network, and captures prove it clearly.

### Teardown

```
Client (active close)                                  Server
   |  FIN,ACK  seq=u                                      |  FIN_WAIT_1
   |----------------------------------------------------->|
   |  ACK  ack=u+1                                        |  server: CLOSE_WAIT
   |<-----------------------------------------------------|  client: FIN_WAIT_2
   |  FIN,ACK  seq=v                                      |  server: LAST_ACK
   |<-----------------------------------------------------|
   |  ACK  ack=v+1                                        |  client: TIME_WAIT (2 x MSL)
   |----------------------------------------------------->|  server: CLOSED
```

Each direction is closed separately, which is why it takes four segments. Often you see only three, because the server sends its ACK and its FIN together. The side that closes first waits in **TIME_WAIT** for twice the maximum segment lifetime (60 seconds on Linux) so that late duplicates of the old connection can't be mistaken for a new one. A pile-up of **CLOSE_WAIT** sockets means an application is not closing its sockets. That is an application bug, not a network fault.

**RST** aborts a connection immediately, with no graceful close. Legitimate causes:

- a SYN arrives at a port where nothing is listening,
- a segment arrives for a connection the host doesn't know about, for example after a reboot or a failover,
- an application aborts the connection.

Stateful firewalls and NAT devices also send or provoke resets when an idle connection exceeds their timeout ("connection reset by peer" after the user returns from lunch). An RST whose IP TTL differs from the server's other packets was probably **injected by a middlebox** rather than sent by the server.

### Refused vs filtered vs unreachable

| What happens on the wire | Socket error | NetDoctor state | Meaning |
|--------------------------|--------------|-----------------|---------|
| SYN → SYN/ACK | connect succeeds | open | Something accepts connections on that port: the server, or a middlebox acting for it |
| SYN → RST,ACK | `ECONNREFUSED` / `WSAECONNREFUSED` (10061) | refused | The host is reachable and nothing listens there, or a firewall REJECTs with a TCP reset |
| SYN → ICMP type 3 code 3 (port unreachable) | `ECONNREFUSED` on Linux | refused | A firewall REJECT with its default reply (iptables uses `icmp-port-unreachable`) |
| SYN → ICMP type 3 code 0/1/9/10/13 | `EHOSTUNREACH`, `ENETUNREACH`, `WSAEHOSTUNREACH` (10065) | unreachable | A router or firewall reports no route, or "administratively prohibited" |
| SYN → nothing, SYN retransmitted | timeout (`ETIMEDOUT` / `WSAETIMEDOUT`, 10060) | filtered | A firewall DROP, an ACL, a broken return path, or a host that is down |

On Windows a refused connection takes about two seconds rather than failing at once, because Windows retries the SYN after it receives an RST. Don't read the delay as packet loss.

**Port scan.** Besides the target port, NetDoctor does a quick connect scan of common ports, the equivalent of `nmap -sT`, and labels each one open, closed (refused) or filtered, as nmap does. Two patterns are worth knowing:

- **Everything filtered:** a host or perimeter firewall drops all traffic except what it explicitly allows.
- **Every port open:** real servers almost never listen on everything. When every port completes a handshake, something in the path is answering for the host: a transparent proxy, a firewall acting as a SYN proxy, a tarpit, or a local tunnel client that intercepts connections and completes the handshake itself. In that case "open" proves nothing about the real server, and the TLS and HTTP results show who you are actually talking to.

| Task | Windows | Linux |
|------|---------|-------|
| Test one port | `Test-NetConnection 198.51.100.20 -Port 443` | `nc -vz 198.51.100.20 443` |
| Connect scan | `nmap -sT -Pn -p 22,80,443 host` | same |
| Socket states | `netstat -ano`, `Get-NetTCPConnection` | `ss -tanp` |

Wireshark: `tcp.flags.syn == 1 && tcp.flags.ack == 0` (connection attempts), `tcp.flags.reset == 1`, `tcp.analysis.retransmission`, `tcp.analysis.duplicate_ack`, `tcp.analysis.zero_window`, `tcp.analysis.flags` (every TCP expert warning), `tcp.stream eq 3` (one connection).

---

## 6. ICMP

ICMP (RFC 792) is IP's control and error protocol. It is carried directly in IP as protocol number 1; ICMPv6 is protocol 58. Every message starts with the same 4 bytes:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Identifier           |        Sequence Number        |  <- echo request/reply
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data ...
```

**Error messages** (destination unreachable, time exceeded) carry the IP header and at least the first 8 bytes of the packet that caused the error. That is enough for the sender's kernel to match the error to a socket by port or ICMP identifier. It is also how traceroute and PMTUD tools learn which probe a router is complaining about.

| Type | Code | Name | Typical cause |
|------|------|------|---------------|
| 0 | 0 | Echo reply | answer to ping |
| 8 | 0 | Echo request | ping |
| 3 | 0 | Net unreachable | the router has no route to the network |
| 3 | 1 | Host unreachable | the last-hop router couldn't ARP for the host |
| 3 | 3 | Port unreachable | UDP to a closed port; iptables REJECT default |
| 3 | 4 | Fragmentation needed and DF set | packet larger than the next-hop MTU (carries the next-hop MTU, see section 8) |
| 3 | 9 / 10 | Network / host administratively prohibited | legacy ACL codes |
| 3 | 13 | Communication administratively prohibited | firewall or ACL reject (RFC 1812) |
| 5 | 0–3 | Redirect | a router telling a host to use a better gateway on the same subnet |
| 11 | 0 | Time exceeded in transit (TTL reached 0) | what traceroute relies on, also routing loops |
| 11 | 1 | Fragment reassembly time exceeded | lost fragments |

### Why "no ping reply" does not mean "host down"

- Host firewalls often block inbound echo requests. Windows Defender Firewall does by default on many profiles.
- Cloud load balancers and many cloud networks don't answer ICMP at all.
- Routers create ICMP in their control plane (CPU), not in their forwarding hardware, and **rate-limit** it with control-plane policing. Linux hosts rate-limit too (`net.ipv4.icmp_ratelimit`). Under load, ICMP replies are the first thing dropped while real traffic is forwarded normally.

So NetDoctor treats 100 % ICMP loss together with a successful TCP connection as "ICMP filtered", not as an outage.

### Ping statistics

- **Loss:** the percentage of echo requests with no reply. A rule of thumb for real-time traffic such as voice and video is under 1 %.
- **RTT min / avg / max:** min is the best the path can do, avg is typical, and a high max shows spikes (queueing, Wi-Fi retries, a busy CPU).
- **Jitter:** how much latency varies. RFC 3550 (RTP) defines interarrival jitter as a smoothed estimate, J = J + (|D| − J) / 16, over one-way transit-time differences. NetDoctor uses a simpler measure in the same spirit: the **mean absolute difference between consecutive RTTs**. For RTTs of 20, 22, 21, 35 and 20 ms, the differences are 2, 1, 14 and 15, so the jitter is 32 / 4 = **8.0 ms**. Common voice guidelines are under 30 ms of jitter and under 150 ms one-way delay (ITU-T G.114).
- **Reply TTL:** operating systems start packets at well-known TTLs: 64 (Linux, macOS), 128 (Windows) and 255 (many network devices). A reply with TTL 116 most likely started at 128 and crossed 12 hops. A reply with TTL 52 most likely started at 64 and also crossed 12 hops. This is a guess. It measures the return path, which may differ from the forward path.

| Task | Windows | Linux |
|------|---------|-------|
| Ping 20 times | `ping -n 20 host` | `ping -c 20 host` |
| PowerShell | `Test-Connection host -Count 20` | — |

Wireshark: `icmp`, `icmp.type == 3`, `icmp.type == 11`, `icmp.resp_not_found` (requests that got no reply).

---

## 7. Traceroute, TTL and MTR

### How TTL produces a path

Every router that forwards an IPv4 packet decrements its **TTL** (IPv6: Hop Limit). When the TTL reaches 0, the router discards the packet and sends **ICMP time exceeded (type 11, code 0)** back to the source, using one of its own interface addresses as the source. Traceroute sends probes with TTL 1, 2, 3 and so on, and notes who complains at each step:

```
Source               R1                 R2                 Destination
  |--- probe TTL=1 --->|                                        |
  |<-- ICMP 11/0 ------|  (TTL hit 0 at R1)                     |
  |--- probe TTL=2 ------------------->|                        |
  |<-- ICMP 11/0 ----------------------|  (R1 forwarded, TTL 0 at R2)
  |--- probe TTL=3 ------------------------------------------->|
  |<-- final reply --------------------------------------------|
       (echo reply, port unreachable, or SYN/ACK, depending on probe type)
```

| Tool | Probe | How it knows it reached the end |
|------|-------|---------------------------------|
| Windows `tracert` | ICMP echo request, 3 per hop, 30 hops max by default | echo reply from the destination |
| Linux `traceroute` (default) | UDP to destination port 33434 and up, a new port per probe | ICMP port unreachable (type 3 code 3) from the destination |
| `traceroute -I` | ICMP echo | echo reply |
| `traceroute -T -p 443`, `tcptraceroute` | TCP SYN to a real service port | SYN/ACK or RST. Gets through firewalls that only allow the service port. |
| `tracepath` (Linux) | UDP, no root needed | port unreachable; also reports the path MTU |
| `mtr` | ICMP by default (UDP/TCP optional), repeated rounds | keeps sending and accumulates per-hop statistics |
| Windows `pathping` | tracert first, then 100 probes per hop at 250 ms intervals | prints per-node and per-link loss after about 25 s per hop |

MTR's report columns are **Loss%** (share of probes to this hop with no answer), **Snt** (probes sent), **Last**, **Avg**, **Best**, **Wrst** (worst) and **StDev** (all in ms).

### How to read a trace

**1. Loss at one hop that does not continue is rate limiting, not loss.**

```
Hop  Host              Loss%  Snt   Avg
 1   192.168.1.1        0.0%   10   1.2
 2   10.20.0.1          0.0%   10   8.4
 3   203.0.113.9       60.0%   10  12.1    <- only this hop "loses" probes
 4   198.51.100.2       0.0%   10  13.0
 5   198.51.100.20      0.0%   10  13.4    (destination)
```

Hop 3 is busy or deprioritizes generating ICMP, but it forwards transit traffic fine, as the 0 % at hops 4 and 5 proves. Opening a ticket against hop 3's owner over this wastes everyone's time.

**2. Loss that starts at hop N and continues to the destination is real.** The problem is on the link into hop N, at hop N itself, or on the return path from there. Since every later hop shows it too, the destination's loss figure is what the user feels.

**3. Latency works the same way.** A jump that persists through later hops is real: typically a long-haul link (crossing an ocean adds tens of milliseconds) or a congested link. A spike at one hop that later hops don't show is just that router being slow to generate ICMP.

**4. `* * *`.** In the middle with later hops answering, a router doesn't send time-exceeded messages, or they are filtered. That is harmless. As a tail with no destination reply, something near the end drops the probes; for ICMP probes that is often the destination's own firewall. If TCP to the service works, the path is fine.

**5. Asymmetric paths.** Each hop's RTT includes the return trip from that hop, and the return path can differ from the forward one. A "slow hop" may sit on a fine forward link but a congested return link.

**6. ECMP and load balancing.** Several IPs at one hop number mean parallel paths. Routers usually hash flows on addresses and ports, so classic UDP traceroute, which changes the destination port on every probe, can wander across paths. Paris traceroute keeps the flow identifiers constant to avoid this.

**7. Routing loops.** The same two or three addresses repeating until the hop limit means a loop. Packets bounce between routers until their TTL runs out.

### What NetDoctor does

NetDoctor sends ICMP echo probes for **every TTL in parallel** rather than one hop at a time, so the first pass takes about one timeout instead of one timeout per silent hop. It then runs repeated **MTR-style rounds**, again sending TTL-limited probes toward the destination rather than pinging each hop's address, and builds a per-hop table of loss and latency. It reads that table with the rules above, so a single lossy middle hop isn't reported as the problem.

How it gets ICMP without administrator or root rights:

- **Windows:** it calls `IcmpSendEcho` in `iphlpapi.dll`. That is the ICMP helper API that Windows' own `ping` and `tracert` are built on. The `IP_OPTION_INFORMATION` structure sets the TTL and the DF flag, and the reply status says what happened: `IP_SUCCESS` (0), `IP_TTL_EXPIRED_TRANSIT` (11013), `IP_REQ_TIMED_OUT` (11010), `IP_DEST_HOST_UNREACHABLE` (11003) or `IP_PACKET_TOO_BIG` (11009). The reply also holds the address of the router that answered.
- **Linux:** it uses unprivileged ICMP datagram sockets, `socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)`, which the kernel allows for groups listed in `net.ipv4.ping_group_range`. It sets `IP_TTL` for the hop and enables `IP_RECVERR`. Time-exceeded and frag-needed errors then arrive on the socket's **error queue**, read with `recvmsg(..., MSG_ERRQUEUE)`. Each carries a `sock_extended_err` structure with the ICMP type and code, the next-hop MTU in `ee_info`, and the offending router's address. If datagram ICMP sockets aren't allowed, NetDoctor falls back to the iputils `ping` binary.

| Task | Windows | Linux |
|------|---------|-------|
| Traceroute without DNS lookups | `tracert -d host` | `traceroute -n host` |
| Through firewalls | — | `traceroute -T -p 443 -n host` |
| Per-hop statistics | `pathping -n host` | `mtr -rwbc 100 host` |

Wireshark: `icmp.type == 11`, `icmp.type == 0 || icmp.type == 8`, `ip.ttl < 5`.

---

## 8. Path MTU discovery

### MTU, MSS and the DF bit

- **MTU** is the largest IP packet a link can carry: 1500 on Ethernet, less on tunnels.
- **MSS** is the largest TCP payload: MTU minus 40 for IPv4.
- **DF (Don't Fragment)** is a bit in the IPv4 flags field. With DF=0 a router may split an oversized packet into fragments, at a cost in CPU, performance and reliability. With DF=1 it must drop the packet and report back. Modern TCP stacks set DF on every segment so they can discover the path MTU.

**RFC 1191 Path MTU Discovery (IPv4):** when a DF packet is too large for the next link, the router drops it and returns **ICMP type 3 code 4 "Fragmentation needed and DF set"**, with the **next-hop MTU** in the second 32-bit word of the ICMP header. The sender caches the smaller MTU for that destination (Linux keeps it for 10 minutes, `net.ipv4.route.mtu_expires = 600`) and resends smaller segments.

```
Host (MTU 1500)          R1 ====== tunnel, MTU 1400 ====== R2            Server
   |--- 1500-byte packet, DF=1 ->|                                          |
   |<-- ICMP 3/4 "frag needed, next-hop MTU 1400" --|                       |
   |--- 1400-byte packet, DF=1 ------------------------------------------>|
```

**IPv6** (RFC 8201) works the same way, except routers never fragment. They send **ICMPv6 Packet Too Big** (type 2). The minimum IPv6 MTU is 1280. Blocking ICMPv6 type 2 breaks IPv6 outright.

**PLPMTUD** (Packetization Layer PMTUD, RFC 4821 for TCP and RFC 8899 for datagram protocols such as QUIC) does without ICMP. The transport probes with larger packets and watches which ones are acknowledged. Linux enables it for TCP with `net.ipv4.tcp_mtu_probing`.

### PMTUD black holes

A **black hole** occurs when something drops the ICMP frag-needed messages. Usually that is an over-strict firewall rule like "block all ICMP" on a tunnel endpoint, an IPsec/GRE head-end or a PPPoE link. The sender never learns that the path is smaller, and keeps retransmitting the same large segment until the connection times out.

```
Client          Firewall (blocks ICMP)     Tunnel router (MTU 1400)          Server
  |--- SYN (MSS 1460) ------------------------------------------------------>|
  |<--------------------------------------------------- SYN/ACK (MSS 1460) --|
  |--- TLS ClientHello (small, fits) --------------------------------------->|
  |                                   X<--- ServerHello + Certificate -------|
  |                                   |     1500-byte segments, DF=1         |
  |                                   |     too big for the tunnel: dropped  |
  |          X<-- ICMP 3/4 MTU 1400 --|     sent toward the server,          |
  |                                         but dropped by the firewall      |
  |   ... the client waits; the server retransmits 1500-byte segments; the handshake hangs
```

The symptom pattern is distinctive, and worth memorizing:

- ping with default (small) packets works,
- the TCP handshake completes,
- small requests work, but the **TLS handshake hangs** (the server's certificate flight is large), big pages stall, file transfers freeze, and SSH connects and then stalls during key exchange.

### Overhead math

| Encapsulation | Bytes added | Effective MTU from 1500 | TCP MSS |
|---------------|-------------|-------------------------|---------|
| none (Ethernet) | 0 | 1500 | 1460 |
| PPPoE | 8 | 1492 | 1452 |
| GRE over IPv4 (20 outer IP + 4 GRE) | 24 | 1476 | 1436 |
| IPsec ESP tunnel mode, AES-GCM (20 IP + 8 ESP + 8 IV + 2 trailer + 16 ICV + 0–3 padding) | 54–57 | about 1443–1446 | about 1403 |
| IPsec ESP tunnel mode, AES-CBC + HMAC-SHA1-96 (20 + 8 + 16 IV + 2 + 12 ICV + 0–15 padding) | 58–73 | about 1427–1442 | about 1387 |
| NAT traversal (ESP in UDP 4500) | +8 on top of ESP | | |
| GRE inside IPsec | add both | | |
| **Common safe setting for tunnels** | | **1400** | **1360** |

Different products count overhead slightly differently, and the exact padding depends on the packet size. That is why vendors standardize on an MTU of 1400 and an MSS of 1360 rather than computing an exact value per cipher.

### Fixes

1. **Allow ICMP type 3 code 4 (and ICMPv6 type 2) through.** This is the real fix. PMTUD can't work without these messages.
2. **TCP MSS clamping** on the tunnel device rewrites the MSS option in passing SYNs so that endpoints never send segments too big for the tunnel:
   - Linux: `iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu`
   - Cisco IOS, on the tunnel interface: `ip mtu 1400` and `ip tcp adjust-mss 1360`
3. **Lower the MTU** on the tunnel interface, or as a workaround on the client (`netsh interface ipv4 set subinterface "Wi-Fi" mtu=1400 store=persistent`, `ip link set dev eth0 mtu 1400`). MSS clamping only helps TCP. UDP-based protocols such as QUIC and many VPN clients rely on an accurate MTU or on their own PLPMTUD.

### NetDoctor's DF-bit sweep

ICMP **payload size + 28** = IP packet size (20 bytes IPv4 + 8 bytes ICMP). A 1472-byte payload is a 1500-byte packet; a 1372-byte payload is a 1400-byte packet.

1. **Baseline:** send a small DF ping. If even that fails, the destination doesn't answer ICMP and the test can't run, so it is reported as skipped, not failed.
2. **Full size:** try a packet as large as the local interface MTU. If it gets a reply, the path carries full-size packets.
3. **Binary search** for the largest payload that still gets an echo reply. Each size is sent as three probes at once and counts as failed only if all three fail. A boundary set only by silence (no frag-needed) is re-tested with six more probes before it is believed; if any of them is answered, the earlier failure was random loss and the search resumes above it. In unit tests against a simulated path with 20% random loss, this never reports a false black hole or a wrong MTU.
4. **Classify** the result:

| Result | Meaning |
|--------|---------|
| Full size works | Path MTU = interface MTU. No MTU problem. |
| Large probes answered with frag-needed / `IP_PACKET_TOO_BIG` | PMTUD works. The report gives the path MTU and the router that announced it. TCP will adapt by itself. |
| Large probes silently time out, small ones succeed, no frag-needed seen | **PMTUD black hole** at the found size. Recommend allowing ICMP 3/4 and clamping the MSS to path MTU − 40. |

On Linux the kernel reports frag-needed through the error queue with the MTU in `ee_info`, and it reports sizes above the local interface MTU right away as `EMSGSIZE`. On Windows the DF flag goes in `IP_OPTION_INFORMATION.Flags` and a too-big result comes back as status 11009. Limitations: the sweep measures the forward path to one destination, the destination must answer ICMP, and a few middleboxes treat ICMP echo differently from TCP.

| Task | Windows | Linux |
|------|---------|-------|
| 1500-byte packet with DF | `ping -f -l 1472 host` | `ping -M do -s 1472 -c 3 host` |
| 1400-byte packet with DF | `ping -f -l 1372 host` | `ping -M do -s 1372 -c 3 host` |
| Discover PMTU hop by hop | — | `tracepath -n host` |
| Interface MTU | `netsh interface ipv4 show subinterfaces` | `ip link show` |
| Cached PMTU | — | `ip route get 198.51.100.20` |

Error text to recognize: Windows prints "Packet needs to be fragmented but DF set." and Linux prints "Frag needed and DF set (mtu = 1400)", or "local error: message too long, mtu=1400" when the local interface itself is smaller.

Wireshark: `icmp.type == 3 && icmp.code == 4`, `icmp.mtu`, `ip.flags.df == 1 && frame.len > 1400`, `tcp.analysis.retransmission && frame.len > 1400`.

---

## 9. TLS

### TLS 1.2 full handshake (ECDHE)

```
Client                                                        Server
  |  ClientHello: version, random, cipher_suites, extensions:     |
  |    server_name (SNI), ALPN, supported_groups,                 |
  |    signature_algorithms                                       |
  |-------------------------------------------------------------->|
  |                      ServerHello: chosen suite, random        |
  |                      Certificate: leaf + intermediates        |
  |                      ServerKeyExchange: ECDHE public key,     |
  |                        signed with the certificate's key      |
  |                      ServerHelloDone                          |
  |<--------------------------------------------------------------|
  |  ClientKeyExchange: client ECDHE public key                   |
  |  ChangeCipherSpec, Finished                                   |
  |-------------------------------------------------------------->|
  |                      ChangeCipherSpec, Finished               |
  |<--------------------------------------------------------------|
  |  application data         (2 round trips after the TCP handshake)
```

### TLS 1.3 handshake (RFC 8446)

```
Client                                                        Server
  |  ClientHello: random, cipher_suites,                          |
  |    supported_versions (includes 0x0304 = TLS 1.3),            |
  |    key_share (ECDHE public key), signature_algorithms,        |
  |    server_name (SNI), ALPN                                    |
  |-------------------------------------------------------------->|
  |                      ServerHello: key_share, supported_versions
  |                      {EncryptedExtensions: ALPN result}       |
  |                      {Certificate}                            |
  |                      {CertificateVerify}                      |
  |                      {Finished}                               |
  |<--------------------------------------------------------------|
  |  {Finished}                                                   |
  |-------------------------------------------------------------->|
  |  application data         (1 round trip after the TCP handshake)

  {...} = encrypted with handshake keys
```

Details that matter in practice:

- The TLS 1.3 ClientHello still says `legacy_version = 0x0303` (TLS 1.2). The real version is negotiated in the `supported_versions` extension. Old middleboxes that inspect the version field are the reason for this design.
- In TLS 1.3 the **server certificate is encrypted**, so Wireshark can't show it without session keys. Set `SSLKEYLOGFILE` in the browser and give Wireshark the key log file. In TLS 1.2 the certificate is visible in clear.
- **SNI** (`server_name`, RFC 6066) tells the server which hostname is wanted, so a shared IP (CDN, load balancer) can present the right certificate. A client that omits SNI usually gets a default certificate and a hostname mismatch. SNI is sent in clear (unless Encrypted Client Hello is used), which is what firewalls and proxies use for **SNI-based filtering**. An RST right after the ClientHello is a typical sign of SNI-based blocking.
- **ALPN** (RFC 7301) negotiates the application protocol inside the handshake: `h2` (HTTP/2) or `http/1.1`. If no common protocol exists, the server sends a `no_application_protocol` alert (120).

### Certificate chain validation

A client accepts a server certificate only if all of the following hold:

1. **It builds a chain** from the leaf through one or more intermediates to a **root** in its trust store. Each certificate must be signed by the next one up. Issuers must carry `basicConstraints CA:TRUE`, and their key usage and path-length limits must allow the chain.
2. **Every certificate is within its validity period** (`notBefore` ≤ now ≤ `notAfter`).
3. **The hostname matches a DNS name in the Subject Alternative Name (SAN) extension.** Modern clients ignore the subject Common Name. A wildcard such as `*.example.com` covers exactly one label: it matches `www.example.com` but not `example.com` or `a.b.example.com`.
4. Revocation, through CRL, OCSP or OCSP stapling, is checked to varying degrees by different clients.

Common real-world failures:

- **Missing intermediate.** The server must send its leaf plus intermediates (the root is optional, since the client already has it). If the server sends only the leaf, browsers often hide the mistake by fetching the intermediate from the certificate's **AIA** (Authority Information Access) URL or from a cache. curl, Python, Java and most OpenSSL-based clients don't, and fail with "unable to get local issuer certificate". The result is "works in Chrome, fails in our integration".
- **Expired certificate**, often an internal certificate that someone forgot to renew.
- **Not yet valid / clock skew.** A device whose clock is far off sees valid certificates as expired or not yet valid. Compare the local time with the server's HTTP `Date` header.

### TLS alerts

| Code | Alert | Typical cause |
|------|-------|---------------|
| 40 | handshake_failure | no shared cipher suite or protocol parameters |
| 42 | bad_certificate | a certificate was corrupt or failed verification (often a client certificate) |
| 45 | certificate_expired | the peer rejected an expired certificate |
| 48 | unknown_ca | the peer doesn't trust the issuing CA (for example, a server rejecting a client certificate) |
| 70 | protocol_version | the client offered only versions the server refuses (for example, TLS 1.0 to a TLS 1.2+ server) |
| 80 | internal_error | a server-side problem |
| 112 | unrecognized_name | the server doesn't know the SNI name it was sent |
| 120 | no_application_protocol | ALPN mismatch |

### OpenSSL verification codes NetDoctor maps

| Code | OpenSSL name | NetDoctor reading |
|------|--------------|-------------------|
| 9 | `X509_V_ERR_CERT_NOT_YET_VALID` | certificate not yet valid. Check the local clock. |
| 10 | `X509_V_ERR_CERT_HAS_EXPIRED` | expired certificate |
| 18 | `X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT` | the leaf is self-signed |
| 19 | `X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN` | the chain ends in a root that isn't trusted (a private CA, or interception) |
| 20 | `X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY` | the issuer can't be found: missing intermediate or unknown CA |
| 21 | `X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE` | the leaf can't be verified (often a single-certificate chain with no issuer available) |
| 62 | `X509_V_ERR_HOSTNAME_MISMATCH` | the hostname isn't in the SAN list |
| 66 / 67 | `X509_V_ERR_EE_KEY_TOO_SMALL` / `X509_V_ERR_CA_KEY_TOO_SMALL` | a key in the chain is too short for the security level (e.g. RSA 1024) |
| 68 | `X509_V_ERR_CA_MD_TOO_WEAK` | a CA signed with a weak digest (SHA-1 or MD5); current clients reject it |

A lone leaf with code 20 is ambiguous: a missing intermediate, or a certificate from a private CA. NetDoctor reads it as a missing intermediate only when the leaf carries an AIA "CA Issuers" URL, which public CAs always include and private or intercepting CAs usually don't.

### TLS inspection: certificates re-signed by a proxy

A forward proxy that performs **TLS inspection** runs two TLS sessions:

```
Client  ==TLS #1==>  Inspecting proxy  ==TLS #2==>  Server
        certificate for www.example.com, issued on the fly by the proxy's CA
                                         real certificate, validated by the proxy
```

The proxy validates the server's real certificate itself, then presents the client with a certificate for the same name, minted on the fly and signed by the proxy's own CA. This works only if that CA's root is installed on the device. Cloud security proxies do this when an SSL inspection policy applies. Zscaler Internet Access, for example, re-signs inspected traffic with a Zscaler-issued or organization-provided CA whose root is deployed to managed devices. Consequences seen in tickets:

- **"Untrusted root" or "unable to get local issuer certificate"** when the root isn't installed, or is installed only in the OS store while the application uses its own.
- **Certificate pinning apps break.** Many mobile apps, some update agents and some desktop clients accept only a specific certificate or key, so they fail under inspection and need an inspection bypass.
- **Applications with their own CA stores**: Python (`certifi`), Node.js, Java (`cacerts`), Git built on OpenSSL, and Firefox (unless enterprise roots are enabled) ignore the Windows store. The fixes are per application: `SSL_CERT_FILE` or `REQUESTS_CA_BUNDLE` for Python, `NODE_EXTRA_CA_CERTS` for Node, `keytool -importcert` for Java, `git config --global http.sslBackend schannel` on Windows, and `pip --cert` or `PIP_CERT` for pip.
- **Schannel vs OpenSSL.** On Windows, Edge, Chrome, .NET, PowerShell's `Invoke-WebRequest` and the bundled `curl.exe` validate through the Windows certificate store and honor roots installed there. Python and other OpenSSL-based tools don't, unless they're configured to. Two tools on the same laptop can therefore disagree about the same site.

**How NetDoctor detects re-signing.** It validates the chain twice: once against the **OS trust store** and once against **Mozilla's public root list** (the `certifi` bundle). It also matches issuer and root names against known inspection products (for example Zscaler, Netskope, Palo Alto Networks, Fortinet, mitmproxy, Fiddler and Burp).

| OS store | Mozilla roots | Name resolves publicly | Interpretation |
|----------|---------------|------------------------|----------------|
| pass | pass | — | a normal public certificate |
| pass | fail | yes | **re-signed by a locally installed root**: TLS inspection, or a corporate CA intercepting traffic |
| pass | fail | no (internal only) | a private or enterprise CA for an internal site. Expected. |
| fail | pass | — | the OS store lacks a public root (see the Windows note below) |
| fail | fail | — | untrusted chain: self-signed, an unknown CA (interception without the root installed), a missing intermediate, expiry, or a wrong host. The verification code says which. |

**Windows note:** Windows ships with a small set of roots and downloads other public roots on demand (Automatic Root Certificates Update) the first time chain building needs them. Python's `ssl` module on Windows only reads what is already in the store. Python can therefore fail with "unable to get local issuer certificate" on a site that Edge opens without trouble. NetDoctor reports this case separately, because it is a client trust-store issue, not interception.

NetDoctor also records the negotiated version, cipher suite, ALPN result and the SNI it sent; flags TLS versions below 1.2; lists the full chain as received, with subject, issuer, validity, days to expiry and SANs; and flags a chain where the server sent only the leaf.

| Task | Command |
|------|---------|
| Handshake and chain | `openssl s_client -connect host:443 -servername host -showcerts` |
| Test ALPN or a version | add `-alpn h2,http/1.1` or `-tls1_2` / `-tls1_3` |
| Read a certificate | `openssl x509 -in cert.pem -noout -subject -issuer -dates -ext subjectAltName` |
| From an application's view | `curl -v https://host/` (add `-k` to skip verification and look past a TLS error) |
| Find inspection roots on Windows | `Get-ChildItem Cert:\LocalMachine\Root \| Where-Object Subject -match "Zscaler"` |

Wireshark: `tls.handshake.type == 1` (ClientHello), `tls.handshake.type == 2` (ServerHello), `tls.handshake.type == 11` (Certificate, visible in TLS 1.2), `tls.handshake.extensions_server_name == "www.example.com"`, `tls.alert_message`.

---

## 10. HTTP and proxies

### Status codes support engineers actually see

| Code | Meaning | Usually generated by |
|------|---------|----------------------|
| 301 / 308 | Moved permanently (308 keeps the method and body) | origin or CDN |
| 302 / 307 | Temporary redirect (307 keeps the method) | origin; also **captive portals** |
| 401 | Authentication required (`WWW-Authenticate`) | origin server |
| 403 | Forbidden | origin, WAF, or a proxy **block page** |
| 404 | Not found | origin |
| **407** | **Proxy authentication required** (`Proxy-Authenticate`) | **forward proxy**. Never the origin. |
| 429 | Too many requests (`Retry-After`) | origin, API gateway, WAF |
| 500 | Internal server error | application |
| **502** | **Bad gateway**: the proxy got an invalid response or none from its upstream | reverse proxy or load balancer (nginx, ELB) or forward proxy |
| 503 | Service unavailable: overloaded or in maintenance | origin or load balancer |
| 504 | Gateway timeout: the upstream didn't answer in time | reverse proxy, load balancer or forward proxy |

**Who answered?** Headers reveal it.

- `Server` (nginx, cloudflare, a proxy product name).
- `Via`, which proxies add (RFC 9110).
- `X-Squid-Error`, which Squid adds to its own error pages: `ERR_CONNECT_FAIL`, `ERR_DNS_FAIL`, `ERR_ACCESS_DENIED`, `ERR_CACHE_ACCESS_DENIED`.
- CDN request IDs such as `CF-Ray` and `X-Amz-Cf-Id`.
- The branding of the error page itself.

A 502 with `Server: nginx` and nothing proxy-like in the path means the network to the site's front door is fine and the application behind it is down. Escalate to the application owner with the timestamp and request ID.

### Forward proxies, CONNECT and 407

An **explicit forward proxy** is configured on the client. For plain HTTP the client sends the full URL (`GET http://www.example.com/ HTTP/1.1`). For HTTPS it asks the proxy to open a tunnel with **CONNECT**:

```
Client                              Proxy :3128                          Server
  |  CONNECT www.example.com:443 HTTP/1.1                                   |
  |  Host: www.example.com:443        |                                     |
  |---------------------------------->|                                     |
  |  HTTP/1.1 407 Proxy Authentication Required                             |
  |  Proxy-Authenticate: Basic realm="corp"                                 |
  |<----------------------------------|                                     |
  |  CONNECT ... + Proxy-Authorization: Basic <base64 user:pass>            |
  |---------------------------------->|---- TCP handshake ---------------->|
  |  HTTP/1.1 200 Connection established                                    |
  |<----------------------------------|                                     |
  |  TLS ClientHello (tunneled; end to end unless the proxy inspects TLS) ->|
```

A **transparent proxy** intercepts traffic without client configuration, by redirecting it in the network path. It can't send a 407, because the client doesn't know a proxy is there. A 407 therefore always means an explicitly configured proxy (directly, through a PAC file, or through an endpoint agent acting as a local proxy).

**Proxy authentication schemes in `Proxy-Authenticate`:**

- **Basic:** base64-encoded `user:password`. That is encoding, not encryption.
- **NTLM:** a three-message challenge-response bound to a single TCP connection. It breaks when keep-alive is lost or when an intermediary splits the connection.
- **Negotiate (Kerberos through SPNEGO):** needs a valid ticket, a correct SPN (`HTTP/proxy.example.com`) and a clock within 5 minutes of the KDC (the default maximum skew). Addressing the proxy by IP address, or a missing SPN, makes clients fall back to NTLM or fail.

**PAC files** are JavaScript served over HTTP. They define `FindProxyForURL(url, host)`, which returns a list such as `"PROXY proxy.example.com:8080; DIRECT"`:

```js
function FindProxyForURL(url, host) {
  if (isPlainHostName(host) || dnsDomainIs(host, ".corp.example.com"))
    return "DIRECT";
  if (isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0"))
    return "DIRECT";
  return "PROXY proxy.example.com:8080; DIRECT";
}
```

Pitfalls:

- An unreachable PAC URL makes clients fall back to their own behavior, often going direct.
- `dnsResolve` and `isInNet` make every proxy decision depend on DNS.
- PAC results are cached.
- A trailing `DIRECT` can silently send traffic around the proxy when the proxy is unreachable.

Cloud security services commonly use PAC files and explicit proxy settings as one way to forward browser traffic to the service. **WPAD** finds a PAC file automatically, through DHCP option 252 or a DNS lookup of `wpad.<domain>` followed by a fetch of `http://wpad.<domain>/wpad.dat`. On Windows this is the "Automatically detect settings" checkbox.

### WinINET vs WinHTTP vs environment variables

| Stack | Who uses it | Where it is configured |
|-------|-------------|------------------------|
| **WinINET** (per user) | Edge, Chrome and most interactive desktop apps | Settings > Network > Proxy; `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` (`ProxyEnable`, `ProxyServer`, `ProxyOverride`, `AutoConfigURL`) |
| **WinHTTP** (machine-wide) | Windows services, Windows Update, many agents and background tasks | `netsh winhttp show proxy`, `netsh winhttp set proxy`, `netsh winhttp import proxy source=ie` |
| **Environment variables** | curl, Python, Git, pip, most CLI tools on every OS | `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `ALL_PROXY` |

The classic ticket is **"the browser works but the agent, service or script doesn't"**. The browser uses the WinINET or PAC proxy, but the service uses WinHTTP, which is still set to "Direct access", or the script only reads environment variables. Quirks to know:

- curl reads **only lowercase** `http_proxy` for HTTP URLs (a defense against the httpoxy attack) but accepts either case for `HTTPS_PROXY`.
- `NO_PROXY` syntax varies by tool. Suffix matching is common; CIDR support is not universal.
- Java ignores these variables entirely and uses `-Dhttps.proxyHost`, `-Dhttps.proxyPort` or `java.net.useSystemProxies`.

**What NetDoctor does:**

- The Local check reports all three proxy sources, plus the PAC URL and auto-detect setting.
- The HTTP check tests through the proxy that applies to the target.
- When a proxy is in play, it sends its own raw CONNECT (or proxied GET) to the proxy. That captures the exact status line and the `Proxy-Authenticate` schemes, which libraries usually reduce to a generic error message.
- It follows redirects one at a time and records each hop's status, `Location` and key headers.
- If TLS verification failed, it can repeat the request with verification disabled, clearly labeled as such (the equivalent of `curl -k`), so the HTTP layer can still be seen.

### HSTS

`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` (RFC 6797) tells the browser to use only HTTPS for this host for `max-age` seconds. While HSTS is in force, the browser rewrites `http://` to `https://` before sending anything and **won't let the user click through certificate errors**. That is why a broken inspection setup or a captive portal on an HSTS site produces a hard error page with no "proceed anyway" link. `preload` asks to be built into browsers' preload list.

### Captive portals

Hotel, airport and guest Wi-Fi portals intercept traffic until the user logs in or accepts terms:

- **HTTP** requests get a `302` (or an injected page) pointing to the portal's login page on a different domain.
- **HTTPS** can't be redirected cleanly. The client sees a certificate for the portal's name (hostname mismatch), a connection reset, or a timeout.
- Some portals also intercept DNS.

Operating systems detect portals by fetching a known plain-HTTP **probe URL** and checking for the exact expected answer:

| Probe | Expected answer |
|-------|-----------------|
| `http://connectivitycheck.gstatic.com/generate_204` (Android, Chrome) | `204 No Content`, empty body |
| `http://www.msftconnecttest.com/connecttest.txt` (Windows NCSI) | `200`, body `Microsoft Connect Test` |
| `http://captive.apple.com/hotspot-detect.html` (Apple) | `200`, body containing `Success` |

Any other answer, typically a redirect to a login page, means the network is behind a portal. Newer networks can advertise the portal directly (DHCP option 114 and RAs, RFC 8910, plus the Captive Portal API, RFC 8908). NetDoctor fetches a probe URL and also checks whether plain-HTTP requests to the target are redirected to an unrelated host with login- or portal-like URLs.

### Clock skew

Every HTTP response carries a `Date` header with the server's clock, which gives a quick outside reference for the local clock. Skew matters for TLS (certificates look expired or not yet valid), for Kerberos (5 minutes by default) and for any token with a short lifetime.

| Task | Command |
|------|---------|
| Headers and redirects | `curl -sv -o /dev/null http://host/`, `curl -sIL https://host/` |
| Through a proxy | `curl -v -x http://proxy:3128 https://host/` |
| Windows proxy settings | `netsh winhttp show proxy`, `reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"` |
| Captive portal probe | `curl -sv http://connectivitycheck.gstatic.com/generate_204` |

Wireshark: `http`, `http.response.code >= 400`, `http.response.code == 407`, `http.request.method == "CONNECT"`, `http.location`.

---

## 11. IPsec and IKE

### Why site-to-site tunnels exist

A site-to-site IPsec tunnel joins two networks over the public Internet as if they shared a private link. Branch offices use them to reach headquarters, data centers or cloud VPCs, and also to forward traffic to cloud security services. Branch offices commonly send their Internet-bound traffic to services such as Zscaler Internet Access over **GRE or IPsec tunnels** from the edge router or firewall, while laptops use an endpoint client or PAC and explicit-proxy forwarding instead.

### ESP, AH, transport and tunnel mode

| | ESP (IP protocol 50) | AH (IP protocol 51) |
|-|----------------------|---------------------|
| Confidentiality | yes (encryption) | no |
| Integrity and authentication | yes, of the ESP payload | yes, including the outer IP header |
| Works through NAT | yes, with NAT-T (UDP encapsulation) | no; NAT changes the authenticated header |
| In practice | almost all deployments | rare |

```
Original packet:   | IP | TCP | data |
ESP transport:     | IP | ESP | TCP | data | ESP trailer | ICV |
ESP tunnel:        | new IP | ESP | IP | TCP | data | ESP trailer | ICV |
ESP tunnel + NAT-T:| new IP | UDP 4500 | ESP | IP | TCP | data | ESP trailer | ICV |
```

**Transport mode** protects the payload of host-to-host traffic. **Tunnel mode** wraps the whole original packet in a new IP header between two gateways. Site-to-site VPNs use tunnel mode.

### SAs, SPIs, SAD, SPD and traffic selectors

- A **Security Association (SA)** is a one-way agreement: algorithms, keys, sequence counters and lifetimes. A working tunnel needs an SA pair (one inbound, one outbound) for each set of protected networks.
- The **SPI** (Security Parameter Index), a 32-bit value in every ESP header, tells the receiver which SA, and therefore which keys, to use.
- The **SAD** (Security Association Database) holds the active SAs. The **SPD** (Security Policy Database) holds the rules: protect, bypass or discard, by source, destination and protocol.
- **Traffic selectors** are the networks a CHILD_SA protects, for example `10.1.0.0/16 <=> 10.2.0.0/16`. IKEv1 calls them proxy IDs; on Cisco ASA they come from the crypto ACL ("interesting traffic"). **Policy-based** VPNs match traffic against these selectors. **Route-based** VPNs (VTI) use `0.0.0.0/0` selectors and send traffic into the tunnel with routing.

### IKEv1 (RFC 2409)

IKE negotiates the keys and SAs over **UDP 500**. IKEv1 does it in two phases.

**Phase 1** builds the IKE (ISAKMP) SA, a secure channel for negotiating with the peer.

```
Main Mode (6 messages)                            Aggressive Mode (3 messages)
Initiator                 Responder              Initiator                  Responder
  |-- 1: SA proposals -------->|                   |-- SA, KE, Ni, ID ----------->|
  |<- 2: chosen proposal ------|                   |<- SA, KE, Nr, ID, AUTH ------|
  |-- 3: KE (DH), Ni --------->|                   |-- AUTH --------------------->|
  |<- 4: KE (DH), Nr ----------|
  |-- 5: IDi, AUTH (encrypted)>|     Aggressive Mode is faster but sends the identity
  |<- 6: IDr, AUTH (encrypted)-|     in clear, and with PSK its hash can be cracked offline.
```

Messages 1 and 2 agree on the encryption, hash, Diffie-Hellman group, authentication method (PSK or certificates) and lifetime. Messages 3 and 4 exchange DH public values and nonces, from which both sides derive keys. Messages 5 and 6 authenticate the peers, already encrypted.

**Phase 2 (Quick Mode, 3 messages)** runs under the phase-1 SA. It proposes IPsec transforms, exchanges traffic selectors (IDs) and nonces, and optionally performs a new DH exchange for **PFS** (perfect forward secrecy). It produces the inbound and outbound IPsec SA pair.

### IKEv2 (RFC 7296)

IKEv2 is simpler and more robust. Four messages produce the IKE SA and the first CHILD_SA:

```
Initiator                                                       Responder
  |  IKE_SA_INIT: HDR, SAi1, KEi, Ni,                                |
  |    N(NAT_DETECTION_SOURCE_IP), N(NAT_DETECTION_DESTINATION_IP)   |
  |----------------------------------------------------------------->|
  |  IKE_SA_INIT: HDR, SAr1, KEr, Nr, [CERTREQ], N(NAT_DETECTION_*)  |
  |<-----------------------------------------------------------------|
  |  IKE_AUTH: HDR, SK{ IDi, [CERT], AUTH, SAi2, TSi, TSr }          |
  |----------------------------------------------------------------->|
  |  IKE_AUTH: HDR, SK{ IDr, [CERT], AUTH, SAr2, TSi, TSr }          |
  |<-----------------------------------------------------------------|
            IKE SA + first CHILD_SA (the IPsec SA pair) established
```

- **IKE_SA_INIT** negotiates algorithms, runs Diffie-Hellman, exchanges nonces and detects NAT by comparing hashes of the addresses and ports.
- **IKE_AUTH** is encrypted (`SK{}`). It proves identities with a PSK or certificates and sets up the first CHILD_SA with its **traffic selectors** (`TSi`/`TSr`).
- **CREATE_CHILD_SA** adds more CHILD_SAs and rekeys both IKE and CHILD SAs.
- **INFORMATIONAL** carries deletes, notifications and **Dead Peer Detection**. An empty INFORMATIONAL request is a liveness check. IKEv1 used a separate DPD extension (RFC 3706).

In Wireshark the IKEv2 exchange types are 34 (IKE_SA_INIT), 35 (IKE_AUTH), 36 (CREATE_CHILD_SA) and 37 (INFORMATIONAL). The IKEv1 equivalents are 2 (Main Mode, "Identity Protection"), 4 (Aggressive) and 32 (Quick Mode).

**NAT traversal:** if either side is behind NAT, the peers switch to **UDP 4500** after IKE_SA_INIT. There, IKE messages are prefixed with a 4-byte **non-ESP marker** (all zeros) so they can be told apart from ESP packets, which are carried in the same UDP port (RFC 3948). Peers send NAT keepalives to keep the NAT mapping open. Without NAT, ESP travels as raw IP protocol 50, which some NAT devices and firewalls block.

**Lifetimes:** IKE SAs typically last hours and CHILD_SAs about an hour, or a data volume. Both are rekeyed before they expire. Mismatched lifetimes or failed rekeys show up as tunnels that drop at regular intervals.

### Common failures and what the logs say

| Symptom | IKE notify / log hint | Usual cause |
|---------|-----------------------|-------------|
| Phase 1 / IKE_SA_INIT fails | `NO_PROPOSAL_CHOSEN` (notify 14), "no acceptable proposal found" | encryption, integrity or DH group mismatch |
| Retries with a different DH group | `INVALID_KE_PAYLOAD` (17) | the initiator guessed the wrong DH group; normally recovers on its own |
| Authentication fails | `AUTHENTICATION_FAILED` (24); strongSwan: "MAC mismatched" for a wrong PSK | PSK mismatch, wrong ID type or value, expired or untrusted certificate |
| IKE up, CHILD_SA refused | `TS_UNACCEPTABLE` (38) | traffic selectors (subnets) don't match on the two sides |
| Nothing arrives at all | no IKE response; packets leave on UDP 500 and never return | UDP 500/4500 blocked, wrong peer IP, ISP or NAT filtering |
| IKE works, ESP doesn't | SAs up, inbound counters at 0 | ESP (protocol 50) blocked, or NAT-T not used when it is needed |
| Tunnel up, no traffic | SA byte counters don't increase | traffic not routed into the tunnel, NAT applied before IPsec (missing NAT exemption), firewall policy |
| One-way traffic | outbound counters increase, inbound stay at 0 | the far side has no route back or wrong selectors, or the return path is filtered |
| Small packets work, large ones hang | SAs up, counters increase | MTU or fragmentation inside the tunnel; see section 8 (MSS clamping, ICMP 3/4) |

Reading SA counters is the fastest test of whether a tunnel actually carries traffic:

| Task | Command |
|------|---------|
| SA state and byte/packet counters | `swanctl --list-sas` |
| Configured connections | `swanctl --list-conns` |
| Bring a CHILD_SA up | `swanctl --initiate --child <name>` |
| Live log | `swanctl --log` |
| Legacy (stroke) interface | `ipsec statusall` |
| Kernel SAs, policies and counters | `ip xfrm state`, `ip xfrm policy`, `ip -s xfrm state` |
| Capture | `tcpdump -ni eth0 'udp port 500 or udp port 4500 or esp'` |

Wireshark: `isakmp`, `isakmp.exchtype == 34`, `esp`, `udp.port == 4500`.

### NetDoctor and IPsec (planned)

- **Lab (planned, phase 4):** a Docker Compose lab builds a strongSwan site-to-site tunnel between two gateways. One of its injectable faults is an MTU black hole inside the tunnel, created by dropping ICMP frag-needed messages, which is the failure described in section 8.
- **`netdoctor tunnel` (planned, phase 6):** checks the lab tunnel's IKE SA state, confirms that traffic actually crosses it (SA counters plus a test flow), and gives MSS/MTU hints based on the measured path MTU through the tunnel.

---

## 12. Packet capture and the capture summary

The checks tell you what failed. A capture shows what happened on the wire, which is what engineering asks for when they escalate a ticket. `netdoctor diagnose` captures packets during the run, saves them as `capture.pcap` in the run folder (`runs/<time>-<host>/`), and summarizes the file in pure Python. You can open the same file in Wireshark. `netdoctor pcap FILE` summarizes any capture, including one a customer sends you.

### How the capture is taken

| OS | Tool | Notes |
|----|------|-------|
| Windows | **dumpcap** (Wireshark's capture engine, through Npcap) | Found on PATH, through `NETDOCTOR_DUMPCAP`, or in the Wireshark install folder. NetDoctor picks the Npcap device whose friendly name matches the interface that routes to the target, or the Npcap loopback adapter for 127.0.0.1. |
| Windows | **pktmon** (built into Windows 10 2004 and later) | Fallback when dumpcap is missing or blocked. It captures at the NIC component to an ETL file, which `pktmon pcapng` converts. NetDoctor then rewrites the result as plain pcap and removes the filters it added. |
| Linux | **tcpdump** `-i any -U` | Needs root or CAP_NET_RAW. `-i any` writes Linux "cooked" headers (SLL or SLL2) instead of Ethernet, and the reader handles both. |

**Permissions.** Capturing needs administrator or root rights almost everywhere. On Windows, Npcap can also be installed with *Restrict Npcap driver's access to Administrators only* (registry `HKLM\SYSTEM\CurrentControlSet\Services\npcap\Parameters\AdminOnly = 1`). NetDoctor checks the token (`IsUserAnAdmin`) and that setting before it starts anything. If it can't capture, the capture appears in the report as SKIP with the reason, and every check still runs.

**Never hang.** Each tool gets 12 seconds to report that it is capturing ("Capturing on…" or "listening on…", or a pcap header in the file). If it doesn't, NetDoctor stops it and moves on. This matters on machines where an antivirus holds new executables for a cloud scan.

**Clean stop.** dumpcap is started in its own process group and stopped with Ctrl+Break (`CTRL_BREAK_EVENT`), and tcpdump with SIGINT. Both then flush and close the file. A hard kill can leave a half-written last record, and the reader tolerates that and says so.

**Capture filter.** The filter is in BPF syntax, built before the DNS check runs: `icmp or icmp6 or port 53 or host <target IPs> or host 8.8.8.8 or host 8.8.4.4 or host 1.1.1.1 or host <proxy>`. NetDoctor resolves the target once in advance to fill it in, and falls back to asking 8.8.8.8 directly when the local resolver is the problem. All ICMP is included because the interesting messages, time-exceeded and frag-needed, come from routers whose addresses aren't known in advance.

### File formats

- **pcap:** a 24-byte global header, then a 16-byte record header and the packet bytes for each packet. The magic number `a1b2c3d4` or `a1b23c4d`, in either byte order, gives the endianness and whether timestamps are in microseconds or nanoseconds. The link type is in the global header.
- **pcapng:** a sequence of blocks. Each Section Header Block sets the byte order. Each Interface Description Block gives an interface's link type and timestamp resolution (`if_tsresol`, a power of 10 or 2). Enhanced Packet Blocks carry the packets. pktmon and Wireshark write pcapng by default.

The decoder handles Ethernet (including 802.1Q/QinQ tags), Linux SLL and SLL2, raw IP and BSD/Npcap loopback framing. It uses the IPv4 total length to strip Ethernet padding, because padding bytes are not TCP payload.

### What the summary computes

| Item | How | Wireshark equivalent |
|------|-----|----------------------|
| Handshake | SYN, SYN/ACK, then the client's ACK of ISN+1. RTT = SYN to SYN/ACK. MSS and window scale come from the SYN options. | `tcp.flags.syn == 1`, `tcp.analysis.initial_rtt` |
| Refused | RST in answer to a SYN | `tcp.flags.reset == 1` |
| Unanswered SYN | SYN, maybe retransmitted, with no SYN/ACK and no RST: filtered | `tcp.flags.syn == 1 && tcp.analysis.retransmission` |
| Retransmission | Every byte range seen is recorded per direction. A segment whose range was **already fully seen** is a retransmission. Keep-alives (0–1 byte at next-expected−1) are excluded. | `tcp.analysis.retransmission` |
| Out-of-order | Below the highest sequence seen but **filling a gap**: new data arriving late, not a resend | `tcp.analysis.out_of_order` |
| Duplicate ACK | A pure ACK repeating the previous ACK number and window while data is outstanding | `tcp.analysis.duplicate_ack` |
| Zero window | Window field 0 on a segment without SYN, FIN or RST: the receiver's buffer is full | `tcp.analysis.zero_window` |
| RST after the handshake | Reported with the side that sent it. Server-side resets point at an application abort, a load-balancer idle timeout or an IPS. | `tcp.flags.reset == 1` |
| TLS | Each direction is reassembled from its sequence numbers, the first 128 KB of it, so records split across segments still parse. NetDoctor reads ClientHello (SNI, ALPN, supported_versions), ServerHello (version, cipher, ALPN), the TLS 1.2 Certificate message (certificate count) and plaintext alerts (level, description, and which side sent them). | `tls.handshake.type == 1`, `tls.alert_message` |
| Stalled TLS | ClientHello with no ServerHello and no RST: the server's large handshake packets never arrived, the classic MTU black-hole signature | No single display filter can say "a stream without a ServerHello". Filter `tls.handshake.type == 1`, then Follow → TCP Stream on each match and check for a ServerHello. |
| Proxy / HTTP | If the stream starts with `CONNECT`, NetDoctor records the proxy's status line and its Proxy-Authenticate, Via and X-Squid-Error headers. For plaintext HTTP it records the request line, Host, status and Location. | `http.request.method == "CONNECT"`, `http.response.code == 407` |
| DNS | Queries are matched to responses on (client, port, server, ID). NetDoctor reports error RCODEs, queries left unanswered more than 2 s before the capture ended, and response times. | `dns.flags.rcode != 0`, `dns.flags.response == 0 && !dns.response_in` |
| ICMP | Time-exceeded per router, frag-needed with the next-hop MTU and the destination it refers to (taken from the embedded original header), destination-unreachable codes, and echo requests vs replies | `icmp.type == 3 && icmp.code == 4` |

**Focus.** A NetDoctor run deliberately creates "bad" traffic: the port scan produces refused and unanswered SYNs, and the TLS check closes connections abruptly. The findings therefore judge only flows to the target (and to the proxy), and count the rest separately. RSTs that the client sends after a handshake are labeled as NetDoctor's own aborts. Closing a socket that still has unread data, such as TLS 1.3 session tickets, makes the OS send RST instead of FIN.

**What a capture can't show.** TLS 1.3 encrypts everything after the ServerHello, including the certificate and any alert the client sends when it rejects that certificate. Those alerts show up as application-data records. That is why the TLS check, not the capture, is the source of truth for certificate problems. In TLS 1.2 the client's alert, for example `certificate_expired` (45) or `unknown_ca` (48), is sent before ChangeCipherSpec and is readable on the wire.

**Checked against Wireshark.** `tests/test_tshark_crosscheck.py` builds captures containing a retransmission with duplicate ACKs, zero windows, a server RST, a refused SYN, a TLS 1.2 fatal alert, a DNS NXDOMAIN and an ICMP frag-needed. The test asserts that tshark's analysis flags (`tcp.analysis.*`, `tls.alert_message`, `dns.flags.rcode`) give the same counts as NetDoctor's. It runs wherever tshark is on PATH, or when `NETDOCTOR_TSHARK` is set.

---

## 13. The verdict engine and the incident report

Each check reports findings with stable codes such as `dns.nxdomain`, `tcp.filtered`, `pmtu.blackhole` or `tls.expired`. The verdict engine reads those codes, not the prose, and reasons the way an engineer does: find the lowest layer that really fails, check that the evidence above and below fits, and treat everything that follows from the root cause as a consequence rather than a separate problem.

### Rules

The rules live in `src/netdoctor/verdict/rules.py`, about 45 of them, ordered bottom-up. A rule has:

| Field | Meaning |
|-------|---------|
| `any_of` / `all_of` / `unless` | Findings that trigger the rule, or rule it out. `tcp.refused:fail` matches only the FAIL form: when a proxy carries the web traffic, a blocked direct connection is reported as INFO, which is expected. |
| `base` | Starting confidence (0–1) |
| `support` / `against` | Findings that raise or lower the confidence when present |
| `explains` | Findings this root cause accounts for (`tls.*` matches a prefix) |
| `predicate` | An extra condition on facts. Example: a 502 is a proxy problem only if the proxy generated it (an `X-Squid-Error` header, a proxy `Server` header). |
| text | Symptom, explanation, resolution steps, next steps, owner team, what to send to engineering, Wireshark filters. Templates are filled with facts from the run: `{host}`, `{ip}`, `{cert_not_after}`, `{pmtu}`, `{proxy_auth}`. |

**Choosing the root cause.** Each matching rule's confidence is `base + support − against`, clamped to 0.05–0.99. The highest wins, and on a tie the rule listed first (the lower layer) wins. Confidence of 0.85 or more is labeled High, 0.6 or more Medium, and anything below that Low. If nothing fails, the `no_fault` verdict (0.75) competes with the low-confidence rules: TLS inspection while everything works is reported as an alternative, not blamed. A failure that no rule covers becomes `unclassified` (0.40) and names that failure.

**Consequences vs separate problems.** After the winner is chosen, every FAIL or WARN finding it doesn't explain is listed under *Other observations*, so an independent second problem is never hidden. Examples of explanation:

| Root cause | Explains |
|------------|----------|
| `local_dhcp_failed`, `local_gateway_unreachable` | everything above the local host (DNS timeouts, failed connections) |
| `dns_nxdomain`, `dns_timeout` | every check above DNS. When DNS fails locally but a public resolver answers, NetDoctor keeps testing with that IP, so `tcp.open` then *supports* "DNS is the only problem". |
| `captive_portal` | the TLS hostname mismatch and certificate errors the portal causes. `tls_hostname_mismatch` carries `unless: http.captive_portal`. |
| `pmtu_blackhole` | `tls.handshake_timeout`, `http.timeout`, the capture's stalled ClientHello. Without a confirmed black hole, a handshake timeout alone is only a Medium-confidence `tls_handshake_stall`. |
| `proxy_auth_required` | the TLS check's refused CONNECT, and the INFO-level direct-connection failures |

**Benign once the service answered.** `icmp.no_reply`, `path.stops` and `path.silent` are moved to *Notes* when TCP, TLS or HTTP reached the service. "Ping fails but the site works" is ICMP filtering, not a fault.

**Category.** Each rule has an `id` (specific) and a `category` (coarse), for example `dns_timeout`, `dns_udp53_blocked` and `dns_no_dns` all belong to the category `dns_timeout`. The benchmark (phase 5) scores categories, because the lab can legitimately produce any of the variants depending on whether it has internet access.

### The incident report

Every run writes `runs/<time>-<host>/report.md` and `report.json`. The Markdown follows a knowledge-base article layout, so it can be pasted into a ticket or a KB:

1. **Symptom**: what the user sees (with the browser error code where there is one, e.g. `NET::ERR_CERT_DATE_INVALID`), plus the first failing layer and the layers below it that passed.
2. **Environment**: client, OS, NetDoctor and ICMP engine, egress interface/IP/gateway/MTU, DNS servers, proxy decision and its source, VPN/security agents, the target and the IP tested.
3. **Tests run**: one row per check with its result, key finding and time, plus the manual commands that reproduce each one.
4. **Evidence**: the findings that support the root cause, any that argue against it, the relevant check tables (the DNS comparison, the TCP attempts, the TLS chain, the DF probes…), and the capture summary.
5. **Root cause**: title, confidence with its breakdown (`base 0.82 +0.10 tcp.port_specific_drop +0.05 icmp.ok`), the explanation, and the other explanations considered, each marked as a consequence where it is one.
6. **Resolution**: numbered fix steps, then next steps for the support engineer.
7. **What to send to engineering**: owner team, time (UTC), client and egress, destination, the specific facts (for example "SYNs from 10.20.0.2 to 10.20.0.10:443 get no answer"), evidence lines, attachments (`report.json`, `capture.pcap`) and the Wireshark filters to apply.

`report.json` holds `{"verdict": …, "diagnosis": …}`, the verdict plus all raw evidence. `netdoctor report runs/…/report.json` re-runs the engine on saved evidence and rewrites `report.md`. That is how improved rules get applied to old tickets.

### How it was checked

- `tests/test_verdict.py` feeds synthetic evidence for each of the 12 lab faults. Each must name the right category with High confidence and leave no unexplained findings. The tests also cover the interactions: a local failure explaining DNS and TCP failures, a captive portal suppressing the TLS rule, a black hole beating a handshake stall, a hosts-file entry pointing at the wrong server, clock skew explaining certificate dates, a proxy-generated 502, and a second independent problem staying visible.
- A live spot check against 13 public endpoints is in the README. That is a spot check; the real benchmark arrives in phase 5.

---

## 14. Cheat sheet

| Symptom | Most likely layer | First test | Typical root cause |
|---------|-------------------|------------|--------------------|
| Address 169.254.x.x | L2 / DHCP | `ipconfig /all`, `ip addr` | DHCP unreachable, wrong VLAN, link down |
| Nothing works, gateway ARP entry incomplete | L2 | `arp -a`, `ip neigh` | gateway down, wrong VLAN or SSID, cabling |
| "Server not found" for one name only | DNS | resolve via system, then 8.8.8.8 | typo, deleted record, NXDOMAIN filtering, stale negative cache |
| Every name fails slowly | DNS | query the configured server directly | DNS server down or unreachable, UDP/53 blocked |
| Works for everyone except one PC | local DNS / hosts | `Resolve-DnsName` vs `nslookup`, check the hosts file | hosts-file override, stale cache, NRPT rule |
| SERVFAIL from every resolver | DNS (authoritative) | `dig +cd` | broken DNSSEC, unreachable authoritative servers |
| Ping fails but the site loads | L3 policy | TCP connect to the port | ICMP filtered; not a fault |
| Slow and choppy calls | L3 path | ping (loss, jitter), MTR | loss or congestion at the hop where loss starts and persists |
| One hop shows 60 % loss, later hops 0 % | L3 path | read the MTR table | ICMP rate limiting on that router; not a fault |
| Connection fails instantly | L4 | TCP connect (RST?) | service not running, firewall REJECT |
| Connection hangs, then times out | L4 / L3 | TCP connect (timeout?), traceroute | firewall DROP, ACL, broken return route |
| Every port shows open | L4 middlebox | TLS/HTTP results, port scan | transparent proxy, SYN proxy, local tunnel client |
| Connects, small requests work, TLS or downloads hang | L3 MTU | DF ping sweep (`ping -f -l 1472`) | PMTUD black hole in a tunnel; fix ICMP 3/4 or clamp MSS |
| "Certificate expired" | TLS | `openssl s_client`, check the dates | expired certificate, or a wrong client clock |
| "Name mismatch" on a known site | TLS | check SAN vs hostname, check for redirects | wrong certificate or missing SNI, captive portal |
| "Unable to get local issuer" in Python/curl, browser fine | TLS trust | OS store vs certifi verification | inspection root not in the app's CA store, missing intermediate, Windows on-demand root |
| Issuer is a security vendor's CA | TLS inspection | check the issuer and installed roots | TLS inspection; install the root or add a bypass for pinned apps |
| 407 Proxy Authentication Required | HTTP / proxy | raw CONNECT to the proxy, check `Proxy-Authenticate` | missing or expired credentials, Kerberos SPN or clock problem |
| Browser works, service or script doesn't | proxy config | WinINET vs WinHTTP vs env vars | WinHTTP set to direct, script ignores the PAC |
| 502 Bad Gateway | HTTP upstream | check `Server`/`Via`/`X-Squid-Error` | origin application down behind its reverse proxy |
| Every HTTP site redirects to a login page | HTTP / captive portal | probe URL (`generate_204`) | captive portal not yet accepted |
| IPsec tunnel up, no traffic | IPsec / routing | SA counters (`swanctl --list-sas`) | selectors, routing, missing NAT exemption |
| IKE fails right away | IPsec / IKE | IKE logs (notify type) | proposal mismatch, PSK or certificate auth failure |
