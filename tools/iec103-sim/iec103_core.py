# -*- coding: utf-8 -*-
"""IEC 60870-5-103 shared codec used by the vendor simulators.

FT1.2 framing, ASDU builders and a small point-table reader. No third-party
dependencies so the same module can generate reference pcaps offline.
"""
from __future__ import annotations

import csv
import struct
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

VAR = 0x68
FIXED = 0x10
SINGLE = 0xE5
STOP = 0x16

# FT1.2 function codes (control direction).
FC_RESET_CU = 0
FC_SEND_CONFIRM = 3
FC_SEND_NOCONF = 4
FC_RESET_FCB = 7
FC_REQ_LINK_STATUS = 9
FC_REQ_CLASS1 = 10
FC_REQ_CLASS2 = 11

# FT1.2 function codes (monitor direction).
FC_CONFIRM = 0
FC_BUSY = 1
FC_RESP_DATA = 8
FC_NO_DATA = 9
FC_LINK_STATUS = 11

# ASDU types.
ASDU_TIME_TAGGED = 1
ASDU_PROTECTION_EVENT = 2
ASDU_MEASURED = 3
ASDU_IDENT = 5
ASDU_TIME_SYNC = 6
ASDU_GI_START = 7
ASDU_GI_END = 8
ASDU_GENERIC_DATA = 10
ASDU_COMMAND = 20
ASDU_GENERIC_CMD = 21
ASDU_DIST_HEADER = 23
ASDU_DIST_CMD = 24
ASDU_DIST_ACK = 25
ASDU_DIST_READY = 26
ASDU_CHAN_READY = 27
ASDU_FLAG_READY = 28
ASDU_FLAG_DATA = 29
ASDU_DIST_DATA = 30
ASDU_DIST_END = 31

# COT values.
COT_SPONT = 1
COT_CYCLIC = 2
COT_RESET_FCB = 3
COT_RESET_CU = 4
COT_START = 5
COT_POWER_ON = 6
COT_TEST = 7
COT_TIME_SYNC = 8
COT_GI = 9
COT_GI_END = 10
COT_LOCAL = 11
COT_REMOTE = 12
COT_ACK_POS = 20
COT_ACK_NEG = 21
COT_DIST = 31

# FUN (function type).
FUN_DISTANCE = 128
FUN_OVERCURRENT = 160
FUN_TRAFO_DIFF = 176
FUN_LINE_DIFF = 192
FUN_GENERIC = 254
FUN_GLOBAL = 255


def checksum(data: bytes) -> int:
    return sum(data) & 0xFF


def frame_fixed(ctrl: int, addr: int) -> bytes:
    body = bytes((ctrl & 0xFF, addr & 0xFF))
    return bytes((FIXED,)) + body + bytes((checksum(body), STOP))


def frame_var(ctrl: int, addr: int, asdu: bytes) -> bytes:
    mid = bytes((ctrl & 0xFF, addr & 0xFF)) + asdu
    length = len(mid)
    if length > 255:
        raise ValueError("FT1.2 L exceeds 255")
    return (bytes((VAR, length, length, VAR)) + mid
            + bytes((checksum(mid), STOP)))


def frame_single() -> bytes:
    return bytes((SINGLE,))


def asdu_header(typ: int, cot: int, addr: int, fun: int, inf: int,
                vsq: int = 0x81) -> bytes:
    return bytes((typ & 0xFF, vsq & 0xFF, cot & 0xFF, addr & 0xFF,
                  fun & 0xFF, inf & 0xFF))


def cp32(dt: Optional[datetime] = None) -> bytes:
    dt = dt or datetime(2026, 11, 7, 8, 0, 0, 123000)
    ms = dt.microsecond // 1000 + dt.second * 1000
    return struct.pack("<HBB", ms, dt.minute & 0x3F, dt.hour & 0x1F)


def cp56(dt: Optional[datetime] = None) -> bytes:
    dt = dt or datetime(2026, 11, 7, 8, 0, 0, 123000)
    ms = dt.microsecond // 1000 + dt.second * 1000
    dow = dt.isoweekday() % 7
    day_dow = (dt.day & 0x1F) | ((dow & 0x7) << 5)
    return struct.pack("<HBBBBB", ms, dt.minute & 0x3F, dt.hour & 0x1F,
                       day_dow, dt.month & 0x0F, dt.year % 100)


# --------------------------------------------------------------------------
# ASDU builders
# --------------------------------------------------------------------------

def asdu_ident(addr: int, col: int = 0x01, fun: int = FUN_GLOBAL,
               inf: int = 4, cot: int = COT_RESET_CU,
               desc: bytes = b"SF-SIM  V1.00") -> bytes:
    body = bytes((col & 0xFF,)) + desc
    return asdu_header(ASDU_IDENT, cot, addr, fun, inf) + body


def asdu_time_sync(addr: int, dt: Optional[datetime] = None,
                   fun: int = FUN_GLOBAL, inf: int = 1) -> bytes:
    return asdu_header(ASDU_TIME_SYNC, COT_TIME_SYNC, addr, fun, inf) + cp56(dt)


def asdu_gi_start(addr: int, scn: int = 1, fun: int = FUN_GLOBAL, inf: int = 2) -> bytes:
    return asdu_header(ASDU_GI_START, COT_GI, addr, fun, inf) + bytes((scn & 0xFF,))


def asdu_gi_end(addr: int, scn: int = 1, fun: int = FUN_GLOBAL, inf: int = 3) -> bytes:
    return asdu_header(ASDU_GI_END, COT_GI_END, addr, fun, inf) + bytes((scn & 0xFF,))


def asdu_protection_event(addr: int, fun: int, inf: int, dpi: int = 2,
                          ret_ms: int = 15, fan: int = 7,
                          dt: Optional[datetime] = None) -> bytes:
    body = bytes((dpi & 0xFF,)) + struct.pack("<H", ret_ms) + struct.pack("<H", fan) + cp56(dt)
    return asdu_header(ASDU_PROTECTION_EVENT, COT_SPONT, addr, fun, inf) + body


def asdu_time_tagged(addr: int, fun: int, inf: int, dpi: int = 2,
                     dt: Optional[datetime] = None) -> bytes:
    body = bytes((dpi & 0xFF,)) + cp32(dt)
    return asdu_header(ASDU_TIME_TAGGED, COT_SPONT, addr, fun, inf) + body


def asdu_measured(addr: int, fun: int, inf: int, values: Iterable[float],
                  cot: int = COT_GI) -> bytes:
    body = b"".join(struct.pack(">f", v) for v in values)
    vsq = 0x80 | (len(list(values)) & 0x7F)
    return asdu_header(ASDU_MEASURED, cot, addr, fun, inf, vsq) + body


def asdu_command(addr: int, dco: int = 0x02, rii: int = 3,
                 fun: int = FUN_GLOBAL, inf: int = 16) -> bytes:
    return asdu_header(ASDU_COMMAND, COT_REMOTE, addr, fun, inf) + bytes((dco, rii))


def gdd_entry(group: int, entry: int, kod: int, datatype: int, datasize: int,
              payload: bytes, number: Optional[int] = None) -> bytes:
    if number is None:
        number = (len(payload) // datasize) if datasize else 0
        if number == 0 and payload:
            number = 1
    if datatype == 0 or datasize == 0:
        payload = b""
        number = 0
    return (bytes((group & 0xFF, entry & 0xFF, kod & 0xFF,
                   datatype & 0xFF, datasize & 0xFF, number & 0x7F))
            + payload)


def asdu_generic(addr: int, entries: List[bytes], cont: bool = False,
                 fun: int = FUN_GENERIC, inf: int = 0, cot: int = COT_GI) -> bytes:
    if not entries:
        raise ValueError("generic ASDU needs at least one entry")
    ngd = (0x80 if cont else 0x00) | (len(entries) & 0x3F)
    return asdu_header(ASDU_GENERIC_DATA, cot, addr, fun, inf) + bytes((ngd,)) + b"".join(entries)


def asdu_generic_cmd(addr: int, nog: int, entries: List[bytes],
                     fun: int = FUN_GENERIC, inf: int = 0,
                     cot: int = COT_GI) -> bytes:
    ngd = len(entries) & 0x3F
    return (asdu_header(ASDU_GENERIC_CMD, cot, addr, fun, inf)
            + bytes((ngd, nog & 0xFF)) + b"".join(entries))


def asdu_dist_header(addr: int, nof: int, faults: List[Tuple[int, int, Optional[datetime]]],
                     fun: int = FUN_GLOBAL, inf: int = 23) -> bytes:
    body = struct.pack("<H", nof)
    for fan, sof, dt in faults:
        body += struct.pack("<H", fan) + bytes((sof & 0xFF,)) + cp56(dt)
    vsq = 0x80 | (len(faults) & 0x7F)
    return asdu_header(ASDU_DIST_HEADER, COT_SPONT, addr, fun, inf, vsq) + body


def asdu_dist_cmd(addr: int, too: int, fun: int = FUN_GLOBAL, inf: int = 19,
                  cot: int = COT_DIST) -> bytes:
    return asdu_header(ASDU_DIST_CMD, cot, addr, fun, inf) + bytes((too & 0xFF,))


def asdu_dist_ack(addr: int, too: int, fun: int = FUN_GLOBAL, inf: int = 20) -> bytes:
    return asdu_header(ASDU_DIST_ACK, COT_DIST, addr, fun, inf) + bytes((too & 0xFF,))


def asdu_dist_ready(addr: int, tov: int, fan: int, nof: int, acc: int,
                    nfe: int, fun: int = FUN_GLOBAL, inf: int = 24) -> bytes:
    body = (bytes((tov & 0xFF,)) + struct.pack("<H", fan) + struct.pack("<H", nof)
            + bytes((acc & 0xFF,)) + struct.pack("<H", nfe))
    return asdu_header(ASDU_DIST_READY, COT_DIST, addr, fun, inf) + body


def asdu_chan_ready(addr: int, tov: int, fan: int, acc: int,
                    rpv: float, rsv: float, rfa: float,
                    fun: int = FUN_GLOBAL, inf: int = 25) -> bytes:
    body = (bytes((tov & 0xFF,)) + struct.pack("<H", fan) + bytes((acc & 0xFF,))
            + struct.pack(">f", rpv) + struct.pack(">f", rsv) + struct.pack(">f", rfa))
    return asdu_header(ASDU_CHAN_READY, COT_DIST, addr, fun, inf) + body


def asdu_flag_ready(addr: int, tov: int, fan: int, not_count: int,
                    fun: int = FUN_GLOBAL, inf: int = 26) -> bytes:
    body = bytes((tov & 0xFF,)) + struct.pack("<H", fan) + bytes((not_count & 0xFF,))
    return asdu_header(ASDU_FLAG_READY, COT_DIST, addr, fun, inf) + body


def asdu_flag_data(addr: int, spi: int = 1, fun: int = FUN_GLOBAL, inf: int = 27) -> bytes:
    return asdu_header(ASDU_FLAG_DATA, COT_DIST, addr, fun, inf) + bytes((spi & 0xFF,))


def asdu_dist_data(addr: int, samples: Iterable[int], fun: int = FUN_GLOBAL,
                   inf: int = 28) -> bytes:
    samples = list(samples)
    body = bytes((len(samples) & 0xFF,)) + b"".join(struct.pack("<h", s) for s in samples)
    return asdu_header(ASDU_DIST_DATA, COT_DIST, addr, fun, inf) + body


def asdu_dist_end(addr: int, too: int = 32, fun: int = FUN_GLOBAL, inf: int = 31) -> bytes:
    return asdu_header(ASDU_DIST_END, COT_DIST, addr, fun, inf) + bytes((too & 0xFF,))


# --------------------------------------------------------------------------
# Point tables
# --------------------------------------------------------------------------

@dataclass
class Point:
    fun: int
    inf: int
    name: str
    asdu: int = 0
    datatype: str = ""
    unit: str = ""
    source: str = ""


def load_points(vendor: str, repo_root: Optional[Path] = None) -> List[Point]:
    if repo_root is None:
        repo_root = Path(__file__).resolve().parents[2]
    path = repo_root / "resources" / "share" / "wireshark" / "iec103" / "points" / f"{vendor}.csv"
    if not path.exists():
        return []
    points: List[Point] = []
    with path.open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row.get("vendor") != vendor:
                continue
            try:
                points.append(Point(
                    fun=int(row["fun"]), inf=int(row["inf"]), name=row["name"],
                    asdu=int(row.get("asdu") or 0), datatype=row.get("datatype", ""),
                    unit=row.get("unit", ""), source=row.get("source", "")))
            except (KeyError, ValueError):
                continue
    return points


def point_name(points: List[Point], fun: int, inf: int) -> str:
    for p in points:
        if p.fun == fun and p.inf == inf:
            return p.name
    return ""


# --------------------------------------------------------------------------
# Capture helpers
# --------------------------------------------------------------------------

def write_pcap(path: Path, records: List[Tuple[float, bytes, str]]) -> None:
    """Write a classic pcap with one Exported PDU record per frame.

    records: (timestamp_seconds, payload_bytes, dissector_name)
    Link type 252 = WTAP_ENCAP_WIRESHARK_UPPER_PDU (exported PDU).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 252))
        for ts, payload, proto in records:
            tag = 12  # EXP_PDU_TAG_DISSECTOR_NAME
            name = proto.encode("ascii") + b"\x00"
            name += b"\x00" * ((4 - len(name) % 4) % 4)
            body = struct.pack(">HH", tag, len(name)) + name
            body += struct.pack(">HH", 0, 0)  # end of options
            body += payload
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            fh.write(struct.pack("<IIII", sec, usec, len(body), len(body)))
            fh.write(body)
