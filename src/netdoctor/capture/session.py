"""Start a packet capture before the checks and stop it after.

Backends:
  dumpcap  Wireshark's capture engine (Windows via Npcap, Linux via libpcap)
  pktmon   built into Windows 10 2004+/11; captures to ETL, converted to pcapng
  tcpdump  Linux

Every backend has a startup timeout, so a capture tool that is blocked (missing
rights, an antivirus holding a new binary) never hangs the diagnosis."""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..netutil import IS_LINUX, IS_WINDOWS, run_command
from . import pcapfile

READY_TIMEOUT = 12.0


class CaptureUnavailable(Exception):
    """Capture can't run here; the message says why and what to do."""


@dataclass
class CaptureSession:
    tool: str
    interface: str
    path: Path
    bpf: str
    started: float
    proc: subprocess.Popen | None = None
    stderr_lines: list[str] = field(default_factory=list)
    temp_files: list[Path] = field(default_factory=list)
    stopped: bool = False
    error: str | None = None

    def info(self) -> dict:
        return {"tool": self.tool, "interface": self.interface, "file": str(self.path), "filter": self.bpf,
                "error": self.error}

    def stop(self) -> dict:
        if self.stopped:
            return self.info()
        self.stopped = True
        time.sleep(0.8)  # let the last replies land in the buffer
        try:
            if self.tool == "pktmon":
                _pktmon_stop(self)
            elif self.proc is not None:
                _stop_process(self.proc)
        except Exception as exc:  # noqa: BLE001 - report, don't crash the run
            self.error = f"stopping {self.tool} failed: {exc}"
        info = self.info()
        info["duration_s"] = round(time.time() - self.started, 1)
        tail = [line for line in self.stderr_lines if line.strip()][-3:]
        if tail:
            info["tool_output"] = tail
        return info


# ------------------------------------------------------------------ helpers


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:  # noqa: BLE001
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def npcap_admin_only() -> bool | None:
    """True if Npcap was installed with 'Restrict Npcap driver's access to Administrators only'."""
    if not IS_WINDOWS:
        return None
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npcap\Parameters") as k:
            return bool(winreg.QueryValueEx(k, "AdminOnly")[0])
    except OSError:
        return None


def npcap_installed() -> bool:
    return IS_WINDOWS and os.path.isdir(os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap"))


def find_dumpcap() -> str | None:
    env = os.environ.get("NETDOCTOR_DUMPCAP")
    if env and os.path.isfile(env):
        return env
    found = shutil.which("dumpcap")
    if found:
        return found
    if IS_WINDOWS:
        candidates = [os.path.join(os.environ.get(v, ""), "Wireshark", "dumpcap.exe")
                      for v in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)") if os.environ.get(v)]
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Wireshark.exe") as k:
                exe = winreg.QueryValueEx(k, "")[0]
                candidates.insert(0, os.path.join(os.path.dirname(exe.strip('"')), "dumpcap.exe"))
        except OSError:
            pass
        for c in candidates:
            if os.path.isfile(c):
                return c
    return None


def build_filter(ips: list[str]) -> str:
    """BPF: DNS, ICMP (traceroute, PMTU, unreachables) and anything to or from the hosts under test."""
    parts = ["icmp", "icmp6", "port 53"] + [f"host {ip}" for ip in dict.fromkeys(ips) if ip]
    return " or ".join(parts)


_DUMPCAP_IFACE = re.compile(r"^\s*(\d+)\.\s+(\S+)(?:\s+\((.*)\))?\s*$")


def parse_dumpcap_interfaces(text: str) -> list[tuple[str, str, str]]:
    """`dumpcap -D` lines: '3. \\Device\\NPF_{GUID} (Wi-Fi)' -> (index, device, friendly)."""
    out = []
    for line in text.splitlines():
        m = _DUMPCAP_IFACE.match(line)
        if m:
            out.append((m.group(1), m.group(2), m.group(3) or ""))
    return out


def egress_interface_name(target_ip: str | None) -> str | None:
    from ..netutil import source_ip_for

    if not target_ip:
        return None
    if target_ip.startswith("127.") or target_ip == "::1":
        return "loopback"
    src = source_ip_for(target_ip)
    if not src:
        return None
    try:
        import psutil

        for name, addrs in psutil.net_if_addrs().items():
            if any(a.address.split("%")[0] == src for a in addrs):
                return name
    except Exception:  # noqa: BLE001
        pass
    return None


def _reader(stream, sink: list[str], ready: threading.Event, markers: tuple[str, ...]) -> None:
    buf = b""
    while True:
        chunk = stream.read1(4096) if hasattr(stream, "read1") else stream.read(4096)
        if not chunk:
            return
        buf += chunk
        while b"\n" in buf or b"\r" in buf:
            line, _, buf = buf.replace(b"\r", b"\n").partition(b"\n")
            text = line.decode("utf-8", errors="replace")
            sink.append(text)
            if any(m in text for m in markers):
                ready.set()


def _launch(cmd: list[str], markers: tuple[str, ...], path: Path) -> tuple[subprocess.Popen, list[str]]:
    # A new process group (so Ctrl+Break reaches only the capture tool) that shares
    # our console: CREATE_NO_WINDOW would detach it and Ctrl+Break would never arrive.
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if IS_WINDOWS else 0
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            creationflags=flags)
    lines: list[str] = []
    ready = threading.Event()
    threading.Thread(target=_reader, args=(proc.stderr, lines, ready, markers), daemon=True).start()
    deadline = time.time() + READY_TIMEOUT
    while time.time() < deadline:
        if ready.is_set() or (path.exists() and path.stat().st_size >= 24):
            time.sleep(0.3)  # the capture filter is live once the header is written
            return proc, lines
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    if proc.poll() is None:
        _stop_process(proc)
        raise CaptureUnavailable(f"{Path(cmd[0]).name} did not start capturing within {READY_TIMEOUT:.0f}s "
                                 "(blocked by an antivirus, or waiting for permission)")
    msg = " ".join(line.strip() for line in lines if line.strip())[-300:]
    raise CaptureUnavailable(f"{Path(cmd[0]).name} exited: {msg or 'no output'}")


def _stop_process(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    try:
        if IS_WINDOWS:
            os.kill(proc.pid, signal.CTRL_BREAK_EVENT)  # dumpcap closes the file cleanly
        else:
            proc.send_signal(signal.SIGINT)
        proc.wait(timeout=6)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        proc.terminate()
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill()


# ------------------------------------------------------------------ backends


def _start_dumpcap(path: Path, bpf: str, target_ip: str | None) -> CaptureSession:
    dumpcap = find_dumpcap()
    if not dumpcap:
        raise CaptureUnavailable("dumpcap not found (install Wireshark, add it to PATH, or set NETDOCTOR_DUMPCAP)")
    iface = "any" if IS_LINUX else None
    if IS_WINDOWS:
        rc, out = run_command([dumpcap, "-D"], timeout=READY_TIMEOUT)
        if rc == 124:
            raise CaptureUnavailable("dumpcap -D did not answer (antivirus holding dumpcap.exe, or Npcap waiting "
                                     "for elevation)")
        devices = parse_dumpcap_interfaces(out)
        wanted = egress_interface_name(target_ip)
        if wanted == "loopback":
            iface = next((d for _i, d, f in devices if "loopback" in (d + f).lower()), None)
        elif wanted:
            iface = next((d for _i, d, f in devices if f.lower() == wanted.lower()), None)
        if not iface:
            if not devices:
                raise CaptureUnavailable(f"dumpcap lists no interfaces: {out.strip()[:200]}")
            iface = devices[0][1]
    cmd = [dumpcap, "-i", iface, "-f", bpf, "-P", "-w", str(path)]
    proc, lines = _launch(cmd, ("Capturing on", "File:"), path)
    return CaptureSession("dumpcap", iface or "?", path, bpf, time.time(), proc, lines)


def _start_tcpdump(path: Path, bpf: str) -> CaptureSession:
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        raise CaptureUnavailable("tcpdump not found (apt install tcpdump)")
    cmd = [tcpdump, "-i", "any", "-s", "0", "-U", "-n", "-w", str(path), bpf]
    try:
        proc, lines = _launch(cmd, ("listening on",), path)
    except CaptureUnavailable as exc:
        if "permission" in str(exc).lower() or "not permitted" in str(exc).lower():
            raise CaptureUnavailable("tcpdump needs root or CAP_NET_RAW (run with sudo)") from exc
        raise
    return CaptureSession("tcpdump", "any", path, bpf, time.time(), proc, lines)


def _pktmon(*args: str, timeout: float = 30.0) -> tuple[int, str]:
    return run_command(["pktmon", *args], timeout=timeout)


def _start_pktmon(path: Path, ips: list[str]) -> CaptureSession:
    if not shutil.which("pktmon"):
        raise CaptureUnavailable("pktmon not available (Windows 10 2004 or later)")
    etl = path.with_suffix(".etl")
    _pktmon("stop")
    _pktmon("filter", "remove")
    for ip in dict.fromkeys(ips):
        _pktmon("filter", "add", "netdoctor", "-i", ip)
    _pktmon("filter", "add", "netdoctor-icmp", "-t", "ICMP")
    _pktmon("filter", "add", "netdoctor-dns", "-p", "53")
    rc, out = _pktmon("start", "--capture", "--comp", "nics", "--pkt-size", "0", "--file-name", str(etl))
    if rc != 0:
        _pktmon("filter", "remove")
        raise CaptureUnavailable(f"pktmon start failed: {out.strip()[:200]}")
    session = CaptureSession("pktmon", "all NICs", path, f"pktmon filters: {', '.join(ips)}, ICMP, port 53",
                             time.time(), temp_files=[etl])
    time.sleep(0.5)
    return session


def _pktmon_stop(session: CaptureSession) -> None:
    etl = session.temp_files[0]
    pcapng = session.path.with_suffix(".pcapng")
    _pktmon("stop", timeout=60)
    _pktmon("filter", "remove")
    rc, out = _pktmon("pcapng", str(etl), "-o", str(pcapng), timeout=120)
    if rc != 0 or not pcapng.exists():
        rc, out = _pktmon("etl2pcap", str(etl), "--out", str(pcapng), timeout=120)
    if not pcapng.exists():
        session.error = f"pktmon conversion failed: {out.strip()[:200]}"
        return
    packets = list(pcapfile.read_packets(pcapng))
    by_link: dict[int, list] = {}
    for p in packets:
        by_link.setdefault(p.linktype, []).append(p)
    main = max(by_link.values(), key=len) if by_link else []
    pcapfile.write_pcap(session.path, main)
    for f in (etl, pcapng):
        try:
            f.unlink()
        except OSError:
            pass


def start_capture(path: Path, ips: list[str], tool: str = "auto", target_ip: str | None = None) -> CaptureSession:
    """Start capturing to `path` (.pcap). Raises CaptureUnavailable with a reason."""
    path.parent.mkdir(parents=True, exist_ok=True)
    bpf = build_filter(ips)
    if IS_WINDOWS:
        admin = is_admin()
        admin_only = npcap_admin_only()
        order = {"auto": ["dumpcap", "pktmon"], "dumpcap": ["dumpcap"], "pktmon": ["pktmon"]}.get(tool)
        if order is None:
            raise CaptureUnavailable(f"capture tool {tool!r} is not available on Windows (use dumpcap or pktmon)")
        if not admin:
            if "dumpcap" in order and npcap_installed() and admin_only is False:
                order = ["dumpcap"]
            else:
                why = ("Npcap is installed with 'Restrict Npcap driver's access to Administrators only'"
                       if admin_only else "pktmon needs administrator rights" if not npcap_installed()
                       else "capturing needs administrator rights here")
                raise CaptureUnavailable(f"{why}: run NetDoctor from an elevated terminal (Run as administrator), "
                                         "or pass --no-capture")
    elif IS_LINUX:
        order = {"auto": ["tcpdump", "dumpcap"], "tcpdump": ["tcpdump"], "dumpcap": ["dumpcap"]}.get(tool)
        if order is None:
            raise CaptureUnavailable(f"capture tool {tool!r} is not available on Linux (use tcpdump or dumpcap)")
    else:
        raise CaptureUnavailable("packet capture is implemented for Windows and Linux")
    errors = []
    for name in order:
        try:
            if name == "dumpcap":
                return _start_dumpcap(path, bpf, target_ip)
            if name == "tcpdump":
                return _start_tcpdump(path, bpf)
            return _start_pktmon(path, ips)
        except CaptureUnavailable as exc:
            errors.append(f"{name}: {exc}")
    raise CaptureUnavailable("; ".join(errors))
