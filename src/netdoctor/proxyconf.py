"""Where does this machine send web traffic? Environment variables, the Windows
per-user (WinINET) proxy that browsers use, the WinHTTP proxy that services use,
PAC files and WPAD. Then decide which proxy a request to the target would take."""

from __future__ import annotations

import fnmatch
import ipaddress
import os
import re
import struct
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from .netutil import IS_WINDOWS
from .target import Target

INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
CONNECTIONS = INTERNET_SETTINGS + r"\Connections"

# DefaultConnectionSettings / WinHttpSettings flag bits
FLAG_DIRECT = 0x01
FLAG_PROXY = 0x02
FLAG_AUTO_CONFIG_URL = 0x04
FLAG_AUTO_DETECT = 0x08


@dataclass
class ProxySetting:
    source: str  # "env" | "wininet" | "winhttp"
    label: str
    enabled: bool = False
    server: str | None = None
    bypass: list[str] = field(default_factory=list)
    pac_url: str | None = None
    auto_detect: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    def describe(self) -> str:
        parts = []
        if self.server and self.enabled:
            parts.append(f"proxy {self.server}")
        if self.pac_url:
            parts.append(f"PAC {self.pac_url}")
        if self.auto_detect:
            parts.append("auto-detect (WPAD)")
        if self.bypass and (self.enabled or self.pac_url):
            parts.append("bypass " + ";".join(self.bypass[:6]) + ("…" if len(self.bypass) > 6 else ""))
        return ", ".join(parts) if parts else "direct (no proxy)"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "label": self.label,
            "enabled": self.enabled,
            "server": self.server,
            "bypass": self.bypass,
            "pac_url": self.pac_url,
            "auto_detect": self.auto_detect,
        }


@dataclass
class PacResult:
    url: str
    fetched: bool = False
    status: int | None = None
    size: int = 0
    error: str | None = None
    has_function: bool = False
    result: str | None = None  # FindProxyForURL() output for the target URL
    engine: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class ProxyDecision:
    proxy_url: str | None  # "http://host:port", or None for DIRECT
    source: str  # what decided it
    detail: str = ""

    @property
    def host_port(self) -> tuple[str, int] | None:
        if not self.proxy_url:
            return None
        parts = urllib.parse.urlsplit(self.proxy_url)
        if not parts.hostname:
            return None
        return parts.hostname, parts.port or (443 if parts.scheme == "https" else 8080 if parts.scheme == "http" else 1080)

    def to_dict(self) -> dict[str, Any]:
        return {"proxy_url": self.proxy_url, "source": self.source, "detail": self.detail}


# ----------------------------------------------------------------- parsing helpers


def parse_connection_blob(blob: bytes) -> dict[str, Any]:
    """Decode a WinINET DefaultConnectionSettings or WinHttpSettings registry blob.

    Layout (little endian): DWORD version, DWORD counter, DWORD flags,
    DWORD len + proxy string, DWORD len + bypass string, then (WinINET only)
    DWORD len + auto-config URL, followed by data we don't need."""
    out: dict[str, Any] = {"flags": 0, "proxy": "", "bypass": "", "pac_url": ""}
    if len(blob) < 12:
        return out
    _version, counter, flags = struct.unpack_from("<III", blob, 0)
    out["counter"] = counter
    out["flags"] = flags
    offset = 12
    for key in ("proxy", "bypass", "pac_url"):
        if offset + 4 > len(blob):
            break
        (length,) = struct.unpack_from("<I", blob, offset)
        offset += 4
        if length > len(blob) - offset:
            break
        out[key] = blob[offset : offset + length].decode("latin-1")
        offset += length
    out["direct"] = bool(flags & FLAG_DIRECT)
    out["proxy_enabled"] = bool(flags & FLAG_PROXY)
    out["auto_config"] = bool(flags & FLAG_AUTO_CONFIG_URL)
    out["auto_detect"] = bool(flags & FLAG_AUTO_DETECT)
    return out


def split_bypass(text: str | None) -> list[str]:
    if not text:
        return []
    return [p.strip() for p in re.split(r"[;,\s]+", text) if p.strip()]


def proxy_for_scheme(server: str | None, scheme: str) -> str | None:
    """WinINET ProxyServer is either "host:port" (all protocols) or
    "http=h1:p1;https=h2:p2;socks=h3:p3". Return a proxy URL for `scheme`."""
    if not server:
        return None
    server = server.strip()
    if "=" not in server:
        return normalize_proxy_url(server)
    table = {}
    for item in server.split(";"):
        if "=" in item:
            k, v = item.split("=", 1)
            table[k.strip().lower()] = v.strip()
    if scheme in table:
        return normalize_proxy_url(table[scheme])
    if "socks" in table:
        return normalize_proxy_url(table["socks"], default_scheme="socks5")
    return None


def normalize_proxy_url(value: str, default_scheme: str = "http") -> str:
    value = value.strip()
    if "://" not in value:
        value = f"{default_scheme}://{value}"
    return value.rstrip("/")


def bypass_match(host: str, patterns: list[str]) -> bool:
    """WinINET ProxyOverride semantics: ';'-separated wildcards, '<local>' = any
    host name without a dot."""
    host = host.lower()
    for pattern in patterns:
        p = pattern.lower()
        if p == "<local>":
            if "." not in host:
                return True
            continue
        if fnmatch.fnmatch(host, p):
            return True
    return False


def no_proxy_match(host: str, no_proxy: str | None) -> bool:
    """NO_PROXY semantics used by curl/requests/httpx: comma list of host suffixes
    (leading dot optional), '*' for everything, and IP/CIDR entries."""
    if not no_proxy:
        return False
    host = host.lower().strip("[]")
    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError:
        host_ip = None
    for entry in (e.strip().lower() for e in no_proxy.split(",")):
        if not entry:
            continue
        if entry == "*":
            return True
        entry = entry.split(":")[0] if entry.count(":") == 1 else entry
        if host_ip is not None:
            try:
                if host_ip in ipaddress.ip_network(entry, strict=False):
                    return True
            except ValueError:
                pass
            continue
        entry = entry.lstrip(".").lstrip("*.")
        if host == entry or host.endswith("." + entry):
            return True
    return False


def parse_pac_result(result: str | None) -> tuple[str | None, str]:
    """'PROXY a:8080; DIRECT' -> ('http://a:8080', 'PROXY a:8080'). First entry wins,
    as browsers only fail over to later entries when the first proxy is down."""
    if not result:
        return None, "DIRECT"
    first = result.split(";")[0].strip()
    kind, _, where = first.partition(" ")
    kind = kind.upper()
    where = where.strip()
    if kind == "DIRECT" or not where:
        return None, "DIRECT"
    if kind in ("PROXY", "HTTP"):
        return normalize_proxy_url(where), first
    if kind == "HTTPS":
        return normalize_proxy_url(where, "https"), first
    if kind in ("SOCKS", "SOCKS5"):
        return normalize_proxy_url(where, "socks5"), first
    if kind == "SOCKS4":
        return normalize_proxy_url(where, "socks4"), first
    return None, first


# ------------------------------------------------------------------ readers


def env_setting() -> ProxySetting:
    def get(name: str) -> str | None:
        return os.environ.get(name.lower()) or os.environ.get(name.upper())

    found = {k: get(k) for k in ("http_proxy", "https_proxy", "all_proxy", "no_proxy")}
    found = {k: v for k, v in found.items() if v}
    server = None
    if found.get("https_proxy") or found.get("http_proxy") or found.get("all_proxy"):
        server = "; ".join(f"{k.upper()}={v}" for k, v in found.items() if k != "no_proxy")
    return ProxySetting(
        source="env",
        label="Environment variables (curl, Python, git, most CLI tools)",
        enabled=server is not None,
        server=server,
        bypass=split_bypass(found.get("no_proxy")),
        raw=found,
    )


def env_proxy_for(target: Target, setting: ProxySetting) -> str | None:
    raw = setting.raw
    if target.scheme == "https":
        value = raw.get("https_proxy") or raw.get("all_proxy")
    else:
        value = raw.get("http_proxy") or raw.get("all_proxy")
    if not value or no_proxy_match(target.host, raw.get("no_proxy")):
        return None
    return normalize_proxy_url(value)


def _read_reg(root: Any, path: str, name: str) -> Any:
    import winreg

    try:
        with winreg.OpenKey(root, path) as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def wininet_setting() -> ProxySetting | None:
    if not IS_WINDOWS:
        return None
    import winreg

    hkcu = winreg.HKEY_CURRENT_USER
    enable = _read_reg(hkcu, INTERNET_SETTINGS, "ProxyEnable")
    server = _read_reg(hkcu, INTERNET_SETTINGS, "ProxyServer")
    override = _read_reg(hkcu, INTERNET_SETTINGS, "ProxyOverride")
    pac = _read_reg(hkcu, INTERNET_SETTINGS, "AutoConfigURL")
    blob = _read_reg(hkcu, CONNECTIONS, "DefaultConnectionSettings")
    parsed = parse_connection_blob(blob) if isinstance(blob, bytes) else {}
    return ProxySetting(
        source="wininet",
        label="WinINET / system proxy (browsers, Office, most desktop apps)",
        enabled=bool(enable) and bool(server),
        server=server or None,
        bypass=split_bypass(override),
        pac_url=pac or None,
        auto_detect=bool(parsed.get("auto_detect")),
        raw={"ProxyEnable": enable, "blob_flags": parsed.get("flags")},
    )


def winhttp_setting() -> ProxySetting | None:
    if not IS_WINDOWS:
        return None
    import winreg

    blob = _read_reg(winreg.HKEY_LOCAL_MACHINE, CONNECTIONS, "WinHttpSettings")
    if not isinstance(blob, bytes):
        return ProxySetting("winhttp", "WinHTTP (Windows services, Windows Update, many agents)", raw={"present": False})
    parsed = parse_connection_blob(blob)
    return ProxySetting(
        source="winhttp",
        label="WinHTTP (Windows services, Windows Update, many agents)",
        enabled=parsed["proxy_enabled"] and bool(parsed["proxy"]),
        server=parsed["proxy"] or None,
        bypass=split_bypass(parsed["bypass"]),
        raw={"flags": parsed["flags"]},
    )


def fetch_pac(url: str, target: Target, timeout: float = 5.0) -> PacResult:
    """Download the PAC file (direct, like browsers do) and, if a JavaScript engine
    is available (pip install netdoctor[pac]), evaluate FindProxyForURL for the target."""
    result = PacResult(url=url)
    text: str | None = None
    try:
        if url.lower().startswith("file:"):
            path = urllib.parse.unquote(urllib.parse.urlsplit(url).path.lstrip("/"))
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            result.fetched, result.status = True, 200
        else:
            import httpx

            resp = httpx.get(url, timeout=timeout, follow_redirects=True, trust_env=False)
            result.status = resp.status_code
            if resp.status_code == 200:
                text = resp.text
                result.fetched = True
            else:
                result.error = f"HTTP {resp.status_code}"
    except Exception as exc:  # noqa: BLE001 - any failure is evidence
        result.error = f"{type(exc).__name__}: {exc}"
    if text is not None:
        result.size = len(text.encode("utf-8", errors="replace"))
        result.has_function = "FindProxyForURL" in text
        if target.url:
            try:
                from pypac.parser import PACFile

                result.result = PACFile(text).find_proxy_for_url(target.url, target.host)
                result.engine = "pypac/dukpy"
            except ImportError:
                result.engine = None
            except Exception as exc:  # noqa: BLE001
                result.error = f"PAC evaluation failed: {exc}"
    return result


def decide(
    target: Target,
    env: ProxySetting,
    wininet: ProxySetting | None,
    pac: PacResult | None,
    cli_proxy: str | None = None,
    cli_no_proxy: bool = False,
) -> ProxyDecision:
    """Which proxy would a request to `target` use? Mirrors what a typical app does:
    explicit override > environment variables > Windows system settings (PAC, then
    manual proxy with its bypass list) > direct."""
    if not target.is_web:
        return ProxyDecision(None, "not HTTP", "proxies only apply to HTTP/HTTPS targets")
    if cli_no_proxy:
        return ProxyDecision(None, "--no-proxy", "forced direct")
    if cli_proxy:
        return ProxyDecision(normalize_proxy_url(cli_proxy), "--proxy", "set on the command line")
    env_url = env_proxy_for(target, env)
    if env_url:
        return ProxyDecision(env_url, "environment", f"{target.scheme.upper()}_PROXY / ALL_PROXY")
    if env.raw.get("no_proxy") and no_proxy_match(target.host, env.raw.get("no_proxy")) and env.enabled:
        return ProxyDecision(None, "environment NO_PROXY", f"{target.host} matches NO_PROXY")
    if wininet:
        if pac and pac.result is not None:
            url, entry = parse_pac_result(pac.result)
            return ProxyDecision(url, "PAC", f"FindProxyForURL returned '{pac.result}' -> using {entry}")
        if wininet.enabled and wininet.server:
            if bypass_match(target.host, wininet.bypass):
                return ProxyDecision(None, "WinINET bypass", f"{target.host} matches ProxyOverride")
            url = proxy_for_scheme(wininet.server, target.scheme)
            if url:
                return ProxyDecision(url, "WinINET manual proxy", wininet.server)
    return ProxyDecision(None, "direct", "no proxy configured for this URL")
