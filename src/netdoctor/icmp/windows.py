"""Windows ICMP prober using IcmpSendEcho from iphlpapi.dll.

This is the API that ping.exe and tracert.exe use. It needs no administrator
rights and lets us set the TTL and the DF flag per probe, and the reply tells
us which router answered and why (TTL expired, packet too big, unreachable)."""

from __future__ import annotations

import ctypes
import socket
import time
from ctypes import wintypes

from .base import Prober, ProbeReply, ProbeStatus

IP_FLAG_DF = 0x02

# Status codes from ipexport.h
IP_SUCCESS = 0
IP_BUF_TOO_SMALL = 11001
IP_DEST_NET_UNREACHABLE = 11002
IP_DEST_HOST_UNREACHABLE = 11003
IP_DEST_PROT_UNREACHABLE = 11004
IP_DEST_PORT_UNREACHABLE = 11005
IP_NO_RESOURCES = 11006
IP_HW_ERROR = 11008
IP_PACKET_TOO_BIG = 11009
IP_REQ_TIMED_OUT = 11010
IP_BAD_REQ = 11011
IP_BAD_ROUTE = 11012
IP_TTL_EXPIRED_TRANSIT = 11013
IP_TTL_EXPIRED_REASSEM = 11014
IP_PARAM_PROBLEM = 11015
IP_SOURCE_QUENCH = 11016
IP_BAD_DESTINATION = 11018
IP_GENERAL_FAILURE = 11050

STATUS_TEXT = {
    IP_DEST_NET_UNREACHABLE: "destination net unreachable",
    IP_DEST_HOST_UNREACHABLE: "destination host unreachable",
    IP_DEST_PROT_UNREACHABLE: "destination protocol unreachable",
    IP_DEST_PORT_UNREACHABLE: "destination port unreachable",
    IP_PACKET_TOO_BIG: "packet needs to be fragmented but DF set",
    IP_REQ_TIMED_OUT: "request timed out",
    IP_TTL_EXPIRED_TRANSIT: "TTL expired in transit",
    IP_TTL_EXPIRED_REASSEM: "TTL expired during reassembly",
    IP_BAD_ROUTE: "bad route",
    IP_BAD_DESTINATION: "bad destination",
    IP_GENERAL_FAILURE: "general failure",
    IP_NO_RESOURCES: "no resources",
    IP_HW_ERROR: "hardware error",
    IP_PARAM_PROBLEM: "parameter problem",
    IP_SOURCE_QUENCH: "source quench",
}


class IP_OPTION_INFORMATION(ctypes.Structure):  # noqa: N801 - Win32 name
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


class ICMP_ECHO_REPLY(ctypes.Structure):  # noqa: N801 - Win32 name
    _fields_ = [
        ("Address", ctypes.c_uint32),
        ("Status", ctypes.c_uint32),
        ("RoundTripTime", ctypes.c_uint32),
        ("DataSize", ctypes.c_uint16),
        ("Reserved", ctypes.c_uint16),
        ("Data", ctypes.c_void_p),
        ("Options", IP_OPTION_INFORMATION),
    ]


_iphlpapi = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)

_IcmpCreateFile = _iphlpapi.IcmpCreateFile
_IcmpCreateFile.argtypes = []
_IcmpCreateFile.restype = wintypes.HANDLE

_IcmpCloseHandle = _iphlpapi.IcmpCloseHandle
_IcmpCloseHandle.argtypes = [wintypes.HANDLE]
_IcmpCloseHandle.restype = wintypes.BOOL

_IcmpSendEcho = _iphlpapi.IcmpSendEcho
_IcmpSendEcho.argtypes = [
    wintypes.HANDLE,
    ctypes.c_uint32,  # IPAddr, network byte order
    ctypes.c_void_p,
    wintypes.WORD,
    ctypes.POINTER(IP_OPTION_INFORMATION),
    ctypes.c_void_p,
    wintypes.DWORD,
    wintypes.DWORD,
]
_IcmpSendEcho.restype = wintypes.DWORD

_INVALID_HANDLE = wintypes.HANDLE(-1).value
_PATTERN = b"NETDOCTOR-PROBE-"


def _ip_to_ulong(ip: str) -> int:
    return int.from_bytes(socket.inet_aton(ip), "little")


def _ulong_to_ip(value: int) -> str:
    return socket.inet_ntoa(value.to_bytes(4, "little"))


class WindowsIcmpProber(Prober):
    name = "windows-iphlpapi (IcmpSendEcho)"

    def probe(self, dst: str, *, ttl: int = 128, size: int = 32, df: bool = False, timeout: float = 1.0) -> ProbeReply:
        handle = _IcmpCreateFile()
        if not handle or handle == _INVALID_HANDLE:
            return ProbeReply(ProbeStatus.ERROR, detail=f"IcmpCreateFile failed (error {ctypes.get_last_error()})")
        try:
            data = (_PATTERN * (size // len(_PATTERN) + 1))[:size]
            request = ctypes.create_string_buffer(data, size) if size else None
            options = IP_OPTION_INFORMATION(ttl, 0, IP_FLAG_DF if df else 0, 0, None)
            reply_size = ctypes.sizeof(ICMP_ECHO_REPLY) + size + 8 + 256
            reply_buf = ctypes.create_string_buffer(reply_size)
            started = time.perf_counter()
            count = _IcmpSendEcho(
                handle,
                _ip_to_ulong(dst),
                request,
                size,
                ctypes.byref(options),
                reply_buf,
                reply_size,
                max(1, int(timeout * 1000)),
            )
            elapsed = (time.perf_counter() - started) * 1000.0
            last_error = ctypes.get_last_error()
            reply = ICMP_ECHO_REPLY.from_buffer(reply_buf)
        finally:
            _IcmpCloseHandle(handle)

        if count == 0:
            status = last_error or reply.Status
            if status == IP_REQ_TIMED_OUT or status == 0:
                return ProbeReply(ProbeStatus.TIMEOUT, code=status)
            if status == IP_PACKET_TOO_BIG:
                return ProbeReply(ProbeStatus.LOCAL_TOO_BIG, code=status, detail=STATUS_TEXT[status])
            return ProbeReply(ProbeStatus.ERROR, code=status, detail=STATUS_TEXT.get(status, f"status {status}"))

        status = reply.Status
        responder = _ulong_to_ip(reply.Address) if reply.Address else None
        rtt = max(float(reply.RoundTripTime), 0.0)
        # RoundTripTime has 1 ms resolution; our own timer is finer and includes only
        # a few microseconds of call overhead, so prefer it unless it is smaller.
        rtt = elapsed if elapsed >= rtt else rtt
        reply_ttl = reply.Options.Ttl or None
        if status == IP_SUCCESS:
            return ProbeReply(ProbeStatus.REPLY, rtt, responder, ttl=reply_ttl, code=status)
        if status in (IP_TTL_EXPIRED_TRANSIT, IP_TTL_EXPIRED_REASSEM):
            return ProbeReply(ProbeStatus.TTL_EXCEEDED, rtt, responder, ttl=reply_ttl, code=status)
        if status == IP_PACKET_TOO_BIG:
            if responder is None:
                return ProbeReply(ProbeStatus.LOCAL_TOO_BIG, code=status, detail=STATUS_TEXT[status])
            return ProbeReply(ProbeStatus.FRAG_NEEDED, rtt, responder, code=status, detail=STATUS_TEXT[status])
        if status in (IP_DEST_NET_UNREACHABLE, IP_DEST_HOST_UNREACHABLE, IP_DEST_PROT_UNREACHABLE, IP_DEST_PORT_UNREACHABLE, IP_BAD_DESTINATION, IP_BAD_ROUTE):
            return ProbeReply(ProbeStatus.UNREACHABLE, rtt, responder, code=status, detail=STATUS_TEXT.get(status, ""))
        if status == IP_REQ_TIMED_OUT:
            return ProbeReply(ProbeStatus.TIMEOUT, code=status)
        return ProbeReply(ProbeStatus.ERROR, rtt, responder, code=status, detail=STATUS_TEXT.get(status, f"status {status}"))
