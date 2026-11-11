"""Local host: interfaces and addresses, default gateway, routes, ARP for the
gateway, DNS servers, security/VPN agents, and proxy settings."""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import struct
from dataclasses import dataclass

import psutil

from .. import proxyconf
from ..context import RunContext
from ..icmp import ProbeStatus
from ..models import CheckResult, Status, Table
from ..netutil import IS_LINUX, IS_WINDOWS, fmt_ms, run_command

ID = "local"
LAYER = "L1-L3 Local host"
TITLE = "Interfaces, gateway, routes, proxy"

# Process names of agents that change how traffic leaves the machine.
AGENTS = {
    "zsatunnel.exe": "Zscaler Client Connector (tunnel service)",
    "zsatray.exe": "Zscaler Client Connector (tray)",
    "zsaservice.exe": "Zscaler Client Connector (service)",
    "zstunnel": "Zscaler Client Connector (Linux tunnel)",
    "stagentsvc.exe": "Netskope Client",
    "pangps.exe": "Palo Alto GlobalProtect",
    "pangpa.exe": "Palo Alto GlobalProtect",
    "vpnagent.exe": "Cisco Secure Client / AnyConnect",
    "acumbrellaagent.exe": "Cisco Umbrella roaming module",
    "fortitray.exe": "FortiClient",
    "fortisslvpndaemon.exe": "FortiClient SSL VPN",
    "openvpn.exe": "OpenVPN",
    "openvpn": "OpenVPN",
    "wireguard.exe": "WireGuard",
    "charon": "strongSwan IKE daemon",
    "charon-systemd": "strongSwan IKE daemon",
    "warp-svc.exe": "Cloudflare WARP",
    "warp-svc": "Cloudflare WARP",
    "tailscaled.exe": "Tailscale",
    "tailscaled": "Tailscale",
}
TUNNEL_IFACE = re.compile(
    r"zscaler|zcc|tun\d*|tap\d*|wg\d*|wireguard|ppp\d*|ipsec|vti|xfrm|gre|globalprotect|pangp|anyconnect|cisco|"
    r"forti|netskope|openvpn|tailscale|warp|vpn",
    re.I,
)


@dataclass
class Route:
    destination: str
    prefixlen: int
    gateway: str | None  # None = on-link
    interface: str  # Windows: interface IP; Linux: interface name
    metric: int

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class ArpEntry:
    ip: str
    mac: str | None  # None = incomplete
    kind: str
    interface: str

    def to_dict(self) -> dict:
        return self.__dict__.copy()


# --------------------------------------------------------------------- parsers

_IP = r"\d{1,3}(?:\.\d{1,3}){3}"
# The gateway column is an IP or a (possibly translated, multi-word) "On-link".
_ROUTE_LINE = re.compile(rf"^\s*({_IP})\s+({_IP})\s+(.+?)\s+({_IP})\s+(\d+)\s*$")


def parse_route_print(text: str) -> list[Route]:
    """Parse the 'Active Routes' table of `route print -4`. Matching on the shape of
    the rows (four IPs and a metric) keeps it working on localized Windows."""
    routes = []
    for line in text.splitlines():
        m = _ROUTE_LINE.match(line)
        if not m:
            continue
        dest, mask, gateway, iface, metric = m.groups()
        try:
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
        except ValueError:
            continue
        gw = gateway if re.fullmatch(_IP, gateway) else None
        routes.append(Route(dest, prefix, gw, iface, int(metric)))
    return routes


def _hex_ip(value: str) -> str:
    return socket.inet_ntoa(struct.pack("<L", int(value, 16)))


def parse_proc_net_route(text: str) -> list[Route]:
    routes = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 8:
            continue
        iface, dest, gateway, flags, _ref, _use, metric, mask = f[:8]
        if not int(flags, 16) & 0x1:  # RTF_UP
            continue
        prefix = bin(int(mask, 16)).count("1")
        gw = _hex_ip(gateway)
        routes.append(Route(_hex_ip(dest), prefix, None if gw == "0.0.0.0" else gw, iface, int(metric)))
    return routes


_ARP_IFACE = re.compile(rf"^\S.*?:\s*({_IP})\s+---")
_ARP_LINE = re.compile(rf"^\s+({_IP})\s+([0-9a-fA-F]{{2}}(?:-[0-9a-fA-F]{{2}}){{5}})\s+(\S+)")


def parse_arp_a(text: str) -> list[ArpEntry]:
    entries, iface = [], ""
    for line in text.splitlines():
        m = _ARP_IFACE.match(line)
        if m:
            iface = m.group(1)
            continue
        m = _ARP_LINE.match(line)
        if m:
            mac = m.group(2).lower()
            entries.append(ArpEntry(m.group(1), None if mac == "00-00-00-00-00-00" else mac, m.group(3), iface))
    return entries


def parse_proc_net_arp(text: str) -> list[ArpEntry]:
    entries = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 6:
            continue
        ip, _hw, flags, mac, _mask, dev = f[:6]
        complete = int(flags, 16) & 0x2
        entries.append(ArpEntry(ip, mac.lower() if complete and mac != "00:00:00:00:00:00" else None,
                                "complete" if complete else "incomplete", dev))
    return entries


def lookup_route(routes: list[Route], ip: str) -> Route | None:
    """Longest-prefix match, then lowest metric (what the kernel does, minus policy routing)."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return None
    best = None
    for r in routes:
        try:
            net = ipaddress.IPv4Network(f"{r.destination}/{r.prefixlen}", strict=False)
        except ValueError:
            continue
        if addr in net and (best is None or (r.prefixlen, -r.metric) > (best.prefixlen, -best.metric)):
            best = r
    return best


# ---------------------------------------------------------------- collectors


def get_routes() -> list[Route]:
    if IS_WINDOWS:
        _rc, out = run_command(["route", "print", "-4"], timeout=10)
        return parse_route_print(out)
    if IS_LINUX:
        try:
            with open("/proc/net/route") as fh:
                return parse_proc_net_route(fh.read())
        except OSError:
            return []
    return []


def get_arp() -> list[ArpEntry]:
    if IS_WINDOWS:
        _rc, out = run_command(["arp", "-a"], timeout=10)
        return parse_arp_a(out)
    if IS_LINUX:
        try:
            with open("/proc/net/arp") as fh:
                return parse_proc_net_arp(fh.read())
        except OSError:
            return []
    return []


def get_interfaces() -> list[dict]:
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    out = []
    for name, entries in addrs.items():
        st = stats.get(name)
        ipv4 = [{"address": a.address, "netmask": a.netmask} for a in entries if a.family == socket.AF_INET]
        ipv6 = [a.address.split("%")[0] for a in entries if a.family == socket.AF_INET6]
        mac = next((a.address for a in entries if a.family == psutil.AF_LINK), None)
        out.append({
            "name": name,
            "up": bool(st and st.isup),
            "mtu": st.mtu if st else None,
            "speed_mbps": st.speed if st else None,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "mac": mac,
            "loopback": any(ipaddress.ip_address(a["address"]).is_loopback for a in ipv4),
        })
    return out


def interface_for_ip(interfaces: list[dict], ip: str) -> dict | None:
    for iface in interfaces:
        if any(a["address"] == ip for a in iface["ipv4"]):
            return iface
    return None


def get_agents() -> list[tuple[str, str]]:
    found = {}
    try:
        for proc in psutil.process_iter(["name"]):
            name = (proc.info.get("name") or "").lower()
            if name in AGENTS:
                found[name] = AGENTS[name]
    except Exception:  # noqa: BLE001 - access denied on some processes is normal
        pass
    return sorted(found.items())


def get_dns_servers() -> list[str]:
    try:
        import dns.resolver

        return list(dns.resolver.Resolver().nameservers)
    except Exception:  # noqa: BLE001
        return []


# ----------------------------------------------------------------------- check


def run(ctx: RunContext) -> CheckResult:
    r = CheckResult(ID, LAYER, TITLE)
    r.data["host"] = {"hostname": socket.gethostname(), "os": platform.platform(), "python": platform.python_version()}

    # Interfaces and addresses
    interfaces = get_interfaces()
    r.data["interfaces"] = interfaces
    active = [i for i in interfaces if i["up"] and not i["loopback"] and i["ipv4"]]
    table = Table("Active interfaces", ["Interface", "IPv4", "MTU", "Speed", "MAC"])
    for i in active:
        table.rows.append([
            i["name"],
            ", ".join(f"{a['address']}/{_prefix(a['netmask'])}" for a in i["ipv4"]),
            str(i["mtu"] or "-"),
            f"{i['speed_mbps']} Mb/s" if i["speed_mbps"] else "-",
            i["mac"] or "-",
        ])
    if active:
        r.tables.append(table)
    routable = [i for i in active if any(not a["address"].startswith("169.254.") for a in i["ipv4"])]
    apipa = [i for i in active if all(a["address"].startswith("169.254.") for a in i["ipv4"])]
    if not active:
        r.add("local.no_ip", Status.FAIL, "No active network interface has an IPv4 address (cable, Wi-Fi or adapter down).")
    elif not routable and apipa:
        r.add("local.apipa", Status.FAIL,
              f"{apipa[0]['name']} has only a self-assigned 169.254.x.x (APIPA) address: DHCP failed, "
              "no DHCP server answered on this link.")

    # Routes and default gateway
    routes = get_routes()
    r.data["routes"] = [x.to_dict() for x in routes]
    defaults = sorted((x for x in routes if x.prefixlen == 0 and x.gateway), key=lambda x: x.metric)
    r.data["default_gateways"] = [x.to_dict() for x in defaults]
    if routes:
        rt = Table("IPv4 routes (default first, then networks; host/broadcast/multicast routes hidden)",
                   ["Destination", "Gateway", "Interface", "Metric"])
        shown = [x for x in routes if x.prefixlen == 0] + sorted(
            (x for x in routes if 0 < x.prefixlen < 32 and not x.destination.startswith(("224.", "127."))),
            key=lambda x: (-x.prefixlen, x.metric))
        for x in shown[:14]:
            rt.rows.append([f"{x.destination}/{x.prefixlen}", x.gateway or "on-link", _iface_label(interfaces, x.interface), str(x.metric)])
        r.tables.append(rt)
    if active and not defaults:
        r.add("local.no_default_route", Status.FAIL,
              "No default route: the host can only reach its own subnets, nothing beyond the LAN.")
    gateways = list(dict.fromkeys(x.gateway for x in defaults if x.gateway))
    if len({x.interface for x in defaults}) > 1:
        r.add("local.multiple_default_routes", Status.INFO,
              "Several default routes on different interfaces (VPN or tunnel client active?): "
              + ", ".join(f"{x.gateway} via {_iface_label(interfaces, x.interface)} metric {x.metric}" for x in defaults))

    # Default gateway: ping it (also refreshes the ARP cache), then read ARP.
    gw_info = []
    if gateways:
        gw = gateways[0]
        gw_iface = _route_iface(interfaces, defaults[0])
        point_to_point = gw_iface is not None and (not gw_iface["mac"] or TUNNEL_IFACE.search(gw_iface["name"]))
        replies = [ctx.prober.probe(gw, timeout=1.0) for _ in range(3)]
        ok = [p.rtt_ms for p in replies if p.status == ProbeStatus.REPLY and p.rtt_ms is not None]
        arp = {e.ip: e for e in get_arp()}
        entry = arp.get(gw)
        r.data["gateway"] = {"ip": gw, "ping_replies": len(ok), "ping_rtts": ok, "arp": entry.to_dict() if entry else None,
                             "interface": gw_iface["name"] if gw_iface else None}
        if ok:
            gw_info.append(f"Default gateway {gw} answers ping ({len(ok)}/3, avg {fmt_ms(sum(ok) / len(ok))}).")
        else:
            gw_info.append(f"Default gateway {gw} does not answer ping (many routers don't; ARP below is the real test).")
        if point_to_point:
            gw_info.append(f"Default route uses {gw_iface['name']}, a point-to-point/tunnel interface: no ARP on that link.")
        elif entry and entry.mac:
            gw_info.append(f"ARP: {gw} is at {entry.mac} ({entry.kind}), so layer 2 to the gateway works.")
        elif entry or not ok:
            r.add("local.gateway_arp_failed", Status.FAIL,
                  f"ARP for the default gateway {gw} is unresolved: nothing on this link answers for that IP "
                  "(gateway down, wrong VLAN/SSID, cable or Wi-Fi association problem).")
        else:
            gw_info.append(f"No ARP entry listed for {gw}, but it answered ping, so it is reachable.")
    r.evidence.extend(gw_info)

    # DNS servers
    servers = get_dns_servers()
    r.data["dns_servers"] = servers
    if servers:
        r.evidence.append("DNS servers: " + ", ".join(servers))

    # Agents and tunnel adapters
    agents = get_agents()
    r.data["agents"] = agents
    for _proc, label in agents:
        r.add("local.security_agent", Status.INFO, f"{label} is running; it may tunnel, proxy or inspect this traffic.")
    tunnels = [i for i in active if TUNNEL_IFACE.search(i["name"])]
    for i in tunnels:
        r.add("local.tunnel_adapter", Status.INFO, f"Tunnel/VPN adapter up: {i['name']} (MTU {i['mtu']}).")

    # Proxy settings
    _proxy_section(ctx, r)

    if not r.findings or all(f.status == Status.INFO for f in r.findings):
        names = ", ".join(i["name"] for i in routable[:3]) or "-"
        gw = gateways[0] if gateways else "none"
        r.summary = f"Up: {names}; default gateway {gw}; proxy: {ctx.proxy.source if ctx.proxy else 'n/a'}"
    else:
        r.summary = next(f.message for f in r.findings if f.status in (Status.FAIL, Status.WARN))

    r.commands = (
        ["ipconfig /all", "route print -4", "arp -a", "netsh winhttp show proxy",
         "reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\""]
        if IS_WINDOWS else ["ip -br addr", "ip route", "ip neigh", "env | grep -i proxy", "cat /etc/resolv.conf"]
    )
    return r


def resolve_proxy(ctx: RunContext) -> tuple[list[proxyconf.ProxySetting], proxyconf.PacResult | None]:
    """Read every proxy source and set ctx.proxy. Used by the check and, quietly, by
    the runner when the local check is skipped."""
    env = proxyconf.env_setting()
    wininet = proxyconf.wininet_setting()
    winhttp = proxyconf.winhttp_setting()
    pac = None
    if wininet and wininet.pac_url and not ctx.opts.proxy and not ctx.opts.no_proxy:
        pac = proxyconf.fetch_pac(wininet.pac_url, ctx.target)
    ctx.proxy = proxyconf.decide(ctx.target, env, wininet, pac, ctx.opts.proxy, ctx.opts.no_proxy)
    return [s for s in (env, wininet, winhttp) if s is not None], pac


def _proxy_section(ctx: RunContext, r: CheckResult) -> None:
    settings, pac = resolve_proxy(ctx)
    r.data["proxy"] = {"settings": [s.to_dict() for s in settings], "pac": pac.to_dict() if pac else None,
                       "decision": ctx.proxy.to_dict() if ctx.proxy else None}
    pt = Table("Proxy configuration", ["Source", "Setting"])
    by_source = {s.source: s for s in settings}
    for s in settings:
        pt.rows.append([s.label, s.describe()])
    r.tables.append(pt)

    env = by_source.get("env")
    if env and env.enabled:
        r.add("local.proxy_env", Status.INFO, f"Proxy environment variables set: {env.server}"
              + (f"; NO_PROXY={','.join(env.bypass)}" if env.bypass else ""))
    wininet = by_source.get("wininet")
    winhttp = by_source.get("winhttp")
    if wininet and wininet.enabled:
        r.add("local.proxy_manual", Status.INFO, f"System (WinINET) proxy: {wininet.server}")
    if pac:
        if pac.fetched:
            msg = f"PAC file {pac.url} downloaded ({pac.size} bytes"
            msg += ", has FindProxyForURL)" if pac.has_function else ", but no FindProxyForURL function!)"
            if pac.result is not None:
                msg += f"; for this URL it returns '{pac.result}'"
            elif pac.engine is None:
                msg += "; install netdoctor[pac] to evaluate it"
            r.add("local.pac", Status.INFO if pac.has_function else Status.WARN, msg)
        else:
            r.add("local.pac_unreachable", Status.WARN,
                  f"PAC file {pac.url} could not be downloaded ({pac.error}); browsers then fall back to "
                  "direct or fail, so behaviour differs between apps.")
    if wininet and wininet.auto_detect:
        r.evidence.append("'Automatically detect settings' (WPAD) is on: Windows looks for wpad.dat via DHCP/DNS.")
    if wininet and winhttp:
        browser = wininet.server if wininet.enabled else ("PAC" if wininet.pac_url else "direct")
        service = winhttp.server if winhttp.enabled else "direct"
        if browser != service:
            r.add("local.proxy_mismatch", Status.INFO,
                  f"Browsers/desktop apps use {browser}, but WinHTTP (services, Windows Update, many agents) "
                  f"uses {service}. 'Works in the browser, fails in the app/service' tickets often come from this.")
    if ctx.proxy:
        where = ctx.proxy.proxy_url or "DIRECT"
        r.evidence.append(f"Requests to {ctx.target.url or ctx.target.endpoint} go {where} (decided by: {ctx.proxy.source}; {ctx.proxy.detail}).")


def _prefix(netmask: str | None) -> str:
    if not netmask:
        return "?"
    try:
        return str(ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen)
    except ValueError:
        return "?"


def _route_iface(interfaces: list[dict], route: Route) -> dict | None:
    by_ip = interface_for_ip(interfaces, route.interface)
    if by_ip:
        return by_ip
    return next((i for i in interfaces if i["name"] == route.interface), None)


def _iface_label(interfaces: list[dict], value: str) -> str:
    """Windows route tables name the interface by its IP; show the adapter name too."""
    iface = interface_for_ip(interfaces, value)
    return f"{iface['name']} ({value})" if iface else value
