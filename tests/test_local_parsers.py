from netdoctor.checks.local import (
    lookup_route,
    parse_arp_a,
    parse_proc_net_arp,
    parse_proc_net_route,
    parse_route_print,
)

ROUTE_PRINT = """\
===========================================================================
Interface List
 12...cc 47 40 30 79 ac ......Intel(R) Wi-Fi 6 AX201 160MHz
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.0.1      192.168.0.3     35
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    331
      192.168.0.0    255.255.255.0         On-link       192.168.0.3    291
      192.168.0.3  255.255.255.255         On-link       192.168.0.3    291
        10.8.0.0      255.255.0.0         10.8.0.1         10.8.0.6     25
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0      192.168.0.1  Default
===========================================================================
"""

# German Windows: headers and "On-link" are translated, the rows keep their shape.
ROUTE_PRINT_DE = """\
Aktive Routen:
     Netzwerkziel    Netzwerkmaske          Gateway    Schnittstelle Metrik
          0.0.0.0          0.0.0.0       10.0.0.138       10.0.0.17     25
         10.0.0.0    255.255.255.0   Auf Verbindung       10.0.0.17    281
"""

PROC_ROUTE = """\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t0100140A\t0003\t0\t0\t0\t00000000\t0\t0\t0
eth0\t0000140A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
tun0\t0000000A\t00000000\t0000\t0\t0\t0\t000000FF\t0\t0\t0
"""

ARP_A = """\

Interface: 192.168.0.3 --- 0xc
  Internet Address      Physical Address      Type
  192.168.0.1           b8-fb-b3-5a-cb-fb     dynamic
  192.168.0.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static

Interface: 192.168.56.1 --- 0x9
  Internet Address      Physical Address      Type
  192.168.56.255        ff-ff-ff-ff-ff-ff     static
"""

PROC_ARP = """\
IP address       HW type     Flags       HW address            Mask     Device
10.20.0.1        0x1         0x2         02:42:0a:14:00:01     *        eth0
10.20.0.9        0x1         0x0         00:00:00:00:00:00     *        eth0
"""


def test_route_print():
    routes = parse_route_print(ROUTE_PRINT)
    assert len(routes) == 5  # persistent routes are not active routes
    default = routes[0]
    assert (default.destination, default.prefixlen, default.gateway, default.interface, default.metric) == (
        "0.0.0.0", 0, "192.168.0.1", "192.168.0.3", 35)
    assert routes[1].gateway is None  # On-link
    assert routes[4].prefixlen == 16


def test_route_print_localized():
    routes = parse_route_print(ROUTE_PRINT_DE)
    assert [r.gateway for r in routes] == ["10.0.0.138", None]


def test_proc_net_route():
    routes = parse_proc_net_route(PROC_ROUTE)
    assert len(routes) == 2  # the tun0 route is not RTF_UP
    assert routes[0].gateway == "10.20.0.1" and routes[0].prefixlen == 0 and routes[0].interface == "eth0"
    assert routes[1].destination == "10.20.0.0" and routes[1].prefixlen == 24 and routes[1].gateway is None


def test_lookup_route_longest_prefix():
    routes = parse_route_print(ROUTE_PRINT)
    assert lookup_route(routes, "10.8.4.4").gateway == "10.8.0.1"
    assert lookup_route(routes, "192.168.0.77").gateway is None
    assert lookup_route(routes, "8.8.8.8").gateway == "192.168.0.1"
    assert lookup_route(routes, "not-an-ip") is None


def test_arp_a():
    entries = parse_arp_a(ARP_A)
    gw = next(e for e in entries if e.ip == "192.168.0.1")
    assert gw.mac == "b8-fb-b3-5a-cb-fb" and gw.interface == "192.168.0.3" and gw.kind == "dynamic"
    assert {e.interface for e in entries} == {"192.168.0.3", "192.168.56.1"}


def test_proc_net_arp():
    entries = {e.ip: e for e in parse_proc_net_arp(PROC_ARP)}
    assert entries["10.20.0.1"].mac == "02:42:0a:14:00:01"
    assert entries["10.20.0.9"].mac is None and entries["10.20.0.9"].kind == "incomplete"
