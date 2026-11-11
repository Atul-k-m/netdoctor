"""Read pcap and pcapng files, and write pcap, in pure Python.

pcap (libpcap format): a 24-byte global header, then one 16-byte record header
per packet. The magic number says the byte order and whether timestamps are in
micro- or nanoseconds.

pcapng: a sequence of blocks (type, length, body, length). A Section Header
Block sets the byte order; Interface Description Blocks give each interface's
link type and timestamp resolution; Enhanced/Simple Packet Blocks hold packets.
pktmon's etl2pcap and Wireshark's default output are pcapng."""

from __future__ import annotations

import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
LINKTYPE_LINUX_SLL2 = 276

PCAPNG_SHB = 0x0A0D0D0A
PCAPNG_IDB = 0x00000001
PCAPNG_OPB = 0x00000002
PCAPNG_SPB = 0x00000003
PCAPNG_EPB = 0x00000006
BYTE_ORDER_MAGIC = 0x1A2B3C4D


class PcapError(ValueError):
    pass


@dataclass
class Packet:
    ts: float  # seconds since the epoch
    linktype: int
    data: bytes
    orig_len: int


@dataclass
class ReadStats:
    format: str = "?"
    truncated: bool = False  # the file ended in the middle of a record (capture killed)
    packets: int = 0


def read_packets(path: str | Path, stats: ReadStats | None = None) -> Iterator[Packet]:
    stats = stats if stats is not None else ReadStats()
    with open(path, "rb") as fh:
        head = fh.read(4)
        fh.seek(0)
        if len(head) < 4:
            raise PcapError("file too short to be a capture")
        if struct.unpack("<I", head)[0] == PCAPNG_SHB:
            stats.format = "pcapng"
            yield from _read_pcapng(fh, stats)
        else:
            stats.format = "pcap"
            yield from _read_pcap(fh, stats)


def _read_pcap(fh, stats: ReadStats) -> Iterator[Packet]:
    header = fh.read(24)
    if len(header) < 24:
        raise PcapError("truncated pcap global header")
    magic = header[:4]
    table = {
        b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
        b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
        b"\xa1\xb2\xc3\xd4": (">", 1e-6),
        b"\xa1\xb2\x3c\x4d": (">", 1e-9),
    }
    if magic not in table:
        raise PcapError(f"not a pcap or pcapng file (magic {magic.hex()})")
    endian, resolution = table[magic]
    linktype = struct.unpack(endian + "I", header[20:24])[0] & 0x0FFFFFFF
    rec = struct.Struct(endian + "IIII")
    while True:
        raw = fh.read(16)
        if not raw:
            return
        if len(raw) < 16:
            stats.truncated = True
            return
        sec, frac, incl, orig = rec.unpack(raw)
        data = fh.read(incl)
        if len(data) < incl:
            stats.truncated = True
            return
        stats.packets += 1
        yield Packet(sec + frac * resolution, linktype, data, orig)


def _read_pcapng(fh, stats: ReadStats) -> Iterator[Packet]:
    endian = "<"
    interfaces: list[tuple[int, float]] = []  # (linktype, seconds per tick)
    while True:
        head = fh.read(8)
        if not head:
            return
        if len(head) < 8:
            stats.truncated = True
            return
        btype_le = struct.unpack("<I", head[:4])[0]
        if btype_le == PCAPNG_SHB:
            # Byte order comes from the magic inside the SHB body.
            bom = fh.read(4)
            if len(bom) < 4:
                stats.truncated = True
                return
            endian = "<" if struct.unpack("<I", bom)[0] == BYTE_ORDER_MAGIC else ">"
            total = struct.unpack(endian + "I", head[4:8])[0]
            body = bom + fh.read(total - 12)
            interfaces = []  # interface IDs are per section
            continue
        btype, total = struct.unpack(endian + "II", head)
        if total < 12 or total % 4:
            raise PcapError(f"corrupt pcapng block length {total}")
        body = fh.read(total - 8)
        if len(body) < total - 8:
            stats.truncated = True
            return
        body = body[:-4]  # trailing copy of the length
        if btype == PCAPNG_IDB:
            linktype = struct.unpack(endian + "H", body[:2])[0]
            interfaces.append((linktype, _tsresol(body[8:], endian)))
        elif btype == PCAPNG_EPB:
            if len(body) < 20:
                continue
            iface, ts_hi, ts_lo, cap, orig = struct.unpack(endian + "IIIII", body[:20])
            if iface >= len(interfaces):
                continue
            linktype, tick = interfaces[iface]
            stats.packets += 1
            yield Packet(((ts_hi << 32) | ts_lo) * tick, linktype, body[20 : 20 + cap], orig)
        elif btype == PCAPNG_SPB:
            if not interfaces or len(body) < 4:
                continue
            orig = struct.unpack(endian + "I", body[:4])[0]
            stats.packets += 1
            yield Packet(0.0, interfaces[0][0], body[4 : 4 + orig], orig)
        elif btype == PCAPNG_OPB:
            if len(body) < 20:
                continue
            iface, _drops, ts_hi, ts_lo, cap, orig = struct.unpack(endian + "HHIIII", body[:20])
            if iface >= len(interfaces):
                continue
            linktype, tick = interfaces[iface]
            stats.packets += 1
            yield Packet(((ts_hi << 32) | ts_lo) * tick, linktype, body[20 : 20 + cap], orig)
        # other block types (name resolution, statistics, custom) are skipped


def _tsresol(options: bytes, endian: str) -> float:
    """if_tsresol (option 9): MSB clear = 10^-n, set = 2^-n. Default microseconds."""
    off = 0
    while off + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[off : off + 4])
        if code == 0:
            break
        value = options[off + 4 : off + 4 + length]
        if code == 9 and value:
            v = value[0]
            return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
        off += 4 + length + (-length % 4)
    return 1e-6


def write_pcap(path: str | Path, packets: list[Packet], snaplen: int = 262144) -> int:
    """Write little-endian microsecond pcap. All packets must share one link type."""
    linktypes = {p.linktype for p in packets}
    if len(linktypes) > 1:
        raise PcapError(f"pcap holds one link type, got {sorted(linktypes)}")
    linktype = linktypes.pop() if linktypes else LINKTYPE_ETHERNET
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
        for p in packets:
            sec = int(p.ts)
            usec = int(round((p.ts - sec) * 1e6))
            if usec >= 1_000_000:
                sec, usec = sec + 1, usec - 1_000_000
            data = p.data[:snaplen]
            fh.write(struct.pack("<IIII", sec, usec, len(data), max(p.orig_len, len(data))))
            fh.write(data)
    return len(packets)
