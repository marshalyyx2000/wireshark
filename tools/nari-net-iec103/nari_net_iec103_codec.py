#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""NARI network IEC 103 (Ethernet) message builders — raw ASDU over TCP, UDP broadcast."""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Optional, Sequence, Tuple

TCP_PORT = 1048
UDP_PORT = 1032
UDP_BCAST_LEN = 41

FUN_GLB = 255
FUN_GEN = 254
INF_GEN_READ_GROUP = 241

COT_GI = 9
COT_GEN_READ = 42
COT_GEN_WRITE = 40
COT_CYCLE = 2
COT_SPONT = 1


def cp56time2a(dt: Optional[datetime] = None) -> bytes:
    """Seven-octet CP56Time2a (local time, little-endian ms)."""
    if dt is None:
        dt = datetime.now()
    ms = dt.microsecond // 1000 + dt.second * 1000
    dow = dt.isoweekday() % 7  # 1..7, 0 = invalid in spec
    day = dt.day & 0x1f
    day_dow = day | ((dow & 0x07) << 5)
    return struct.pack(
        "<HBBBBB",
        ms,
        dt.minute & 0x3f,
        dt.hour & 0x1f,
        day_dow,
        dt.month & 0x0f,
        dt.year % 100,
    )


def asdu_header(
    typ: int,
    cot: int,
    addr: int,
    fun: int,
    inf: int,
    vsq: int = 0x81,
) -> bytes:
    return bytes((typ & 0xff, vsq & 0xff, cot & 0xff, addr & 0xff, fun & 0xff, inf & 0xff))


def asdu_identification(addr: int = 1, cot: int = 5) -> bytes:
    """ASDU5 — device identification."""
    name = b"NARI-TEST" + b" " * 7
    name = name[:8]
    body = bytes((3,)) + name + bytes((0x01, 0x11, 0x22, 0x33, 0x44, 0x01, 0x02))
    return asdu_header(5, cot, addr, FUN_GLB, 0) + body


def asdu_time_sync(addr: int = 255) -> bytes:
    """ASDU6 — time synchronization."""
    return asdu_header(6, 8, addr, FUN_GLB, 0) + cp56time2a()


def asdu_general_interrogation(addr: int = 1, scn: int = 0) -> bytes:
    """ASDU7 — general interrogation (master → slave)."""
    return asdu_header(7, COT_GI, addr, FUN_GLB, 0) + bytes((scn & 0xff,))


def asdu_gen_read_group(
    addr: int,
    group: int,
    entry: int = 0,
    kod: int = 10,
    inf: int = INF_GEN_READ_GROUP,
    rii: int = 0,
) -> bytes:
    """ASDU21 — generic classification read (e.g. read group descriptions)."""
    body = bytes((rii & 0xff, 1, group & 0xff, entry & 0xff, kod & 0xff))
    return asdu_header(21, COT_GEN_READ, addr, FUN_GEN, inf) + body


def asdu_gen_read_entry(
    addr: int,
    group: int,
    entry: int,
    kod: int = 1,
    rii: int = 0,
) -> bytes:
    """ASDU21 — read one entry actual value."""
    body = bytes((rii & 0xff, 1, group & 0xff, entry & 0xff, kod & 0xff))
    return asdu_header(21, COT_GEN_READ, addr, FUN_GEN, 0) + body


def _gdd_gid(datatype: int, width: int, number: int, gid: bytes) -> bytes:
    return bytes((datatype & 0xff, width & 0xff, number & 0xff)) + gid


def asdu_gen_data_entry(
    addr: int,
    group: int,
    entry: int,
    kod: int,
    datatype: int,
    width: int,
    number: int,
    gid: bytes,
    cot: int = COT_GEN_READ,
    inf: int = INF_GEN_READ_GROUP,
    rii: int = 0,
) -> bytes:
    """One NGD=1 ASDU10 generic data response."""
    ngd = 1
    payload = (
        bytes((rii & 0xff, ngd & 0x3f))
        + bytes((group & 0xff, entry & 0xff, kod & 0xff))
        + _gdd_gid(datatype, width, number, gid)
    )
    return asdu_header(10, cot, addr, FUN_GEN, inf) + payload


def asdu_protection_measurements(addr: int = 1, rii: int = 0) -> bytes:
    """ASDU10 — cyclic protection measurements (group 06), matches field capture layout."""
    entries: List[Tuple[int, float]] = [(1, 1.0), (2, 2.0), (3, 3.0)]
    parts = [bytes((rii & 0xff, len(entries) & 0x3f))]
    for entry, fval in entries:
        gid = struct.pack("<f", fval)
        parts.append(bytes((6, entry & 0xff, 1)) + _gdd_gid(7, 4, 1, gid))
    return asdu_header(10, COT_CYCLE, addr, FUN_GEN, 0xF4) + b"".join(parts)


def asdu_disturbance_values(
    addr: int = 1,
    fan: int = 1,
    acc: int = 1,
    ndv: int = 4,
    nfe: int = 0,
    samples: Optional[Sequence[int]] = None,
) -> bytes:
    """ASDU30 — disturbance value transfer."""
    if samples is None:
        samples = [0x0100, 0x0200, 0x0300, 0x0400][:ndv]
    sdv = b"".join(struct.pack("<h", s) for s in samples[:ndv])
    body = (
        b"\x00\x00"
        + bytes((1,))  # TOV instantaneous
        + struct.pack("<H", fan)
        + bytes((acc & 0xff,))
        + struct.pack("<H", ndv)
        + struct.pack("<H", nfe)
        + sdv
    )
    return asdu_header(30, 0x1F, addr, FUN_GLB, 0) + body


def asdu_disturbance_table(addr: int = 1, count: int = 1, fan: int = 1) -> bytes:
    """ASDU23 — NARI disturbance list (i entries × 10 bytes, FUN=255 INF=0)."""
    vsq = count & 0x7f
    body = b"".join(
        struct.pack("<H", fan + i) + bytes((0,)) + cp56time2a()
        for i in range(count)
    )
    return asdu_header(23, COT_GI, addr, FUN_GLB, 0, vsq=vsq) + body


def udp_master_online(include_time: bool = True, name: str = "NARI-MASTER") -> bytes:
    """41-byte UDP master on-line broadcast (spec section 8.2)."""
    buf = bytearray(UDP_BCAST_LEN)
    buf[0] = 0xFF
    buf[1] = 0x01 if include_time else 0x00
    if include_time:
        buf[2:9] = cp56time2a()
    nb = name.encode("ascii", errors="replace")[:16]
    buf[9 : 9 + len(nb)] = nb
    return bytes(buf)


@dataclass
class ParsedAsdu:
    typ: int
    vsq: int
    cot: int
    addr: int
    fun: int
    inf: int
    payload: bytes

    @classmethod
    def parse(cls, data: bytes) -> Optional["ParsedAsdu"]:
        if len(data) < 6:
            return None
        return cls(
            typ=data[0],
            vsq=data[1],
            cot=data[2],
            addr=data[3],
            fun=data[4],
            inf=data[5],
            payload=data[6:],
        )

    def __str__(self) -> str:
        return (
            f"ASDU{self.typ} addr={self.addr} COT={self.cot} "
            f"FUN={self.fun} INF={self.inf} len={len(self.payload)}"
        )


def split_asdu_stream(buffer: bytearray) -> Tuple[List[bytes], bytearray]:
    """Best-effort split of concatenated ASDUs (for demo logging only)."""
    frames: List[bytes] = []
    i = 0
    while i + 6 <= len(buffer):
        typ = buffer[i]
        length = guess_asdu_length(bytes(buffer[i:]))
        if length <= 0 or i + length > len(buffer):
            break
        frames.append(bytes(buffer[i : i + length]))
        i += length
    rest = bytearray(buffer[i:])
    return frames, rest


def guess_asdu_length(data: bytes) -> int:
    """Mirror dissector length rules for common types."""
    if len(data) < 6:
        return -1
    typ = data[0]
    fixed = {
        5: 6 + 25,
        6: 6 + 7,
        7: 6 + 1,
        8: 6 + 1,
        20: 6 + 2,
        24: 6 + 5,
        25: 6 + 5,
        26: 6 + 14,
        27: 6 + 17,
        28: 6 + 4,
        31: 6 + 5,
    }
    if typ == 23 and len(data) >= 7:
        num = data[1] & 0x7f
        return 6 + num * 10
    if typ == 29 and len(data) >= 9:
        pos = 9
        while pos + 5 <= len(data) and data[pos] == 0xFF:
            pos += 5
        return pos
    if typ in fixed:
        return fixed[typ]
    if typ == 21 and len(data) >= 8:
        nog = data[7]
        return 8 + nog * 3
    if typ == 30 and len(data) >= 16:
        ndv = struct.unpack_from("<H", data, 12)[0]
        total = 6 + 10 + ndv * 2
        if total <= len(data):
            return total
        return len(data)
    if typ == 10 and len(data) >= 8:
        return len(data)  # variable; assume one TCP segment per ASDU in tests
    return len(data)
