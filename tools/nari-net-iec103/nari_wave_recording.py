#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""NARI network 103 disturbance (录波) list + full waveform transfer — mirrors 171_nz_103_net.txt."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from nari_net_iec103_codec import (
    COT_GI,
    FUN_GLB,
    asdu_header,
    cp56time2a,
)

COT_DISTURB = 0x1F
FUN_DIST = 0xFE
INF_DIST = 0

TOO_LIST_DISTURBANCES = 0x18
TOO_SELECT_FAULT = 0x01
TOO_CHANNEL_TAGS = 0x10
TOO_ACK_DATA = 0x08
TOO_SELECT_CHANNEL = 0x44

# Channel / segment sizes taken from field capture (ASDU30 NDV).
NDV_FIRST_SEGMENT = 0x8C
NDV_MID_SEGMENT = 0xC8


def asdu_dist_cmd_body(too: int, tov: int, fan: int, acc: int = 0) -> bytes:
    """ASDU24/25/31 body: TOO + TOV + FAN(2 LE) + ACC (B.6.26, B.6.27, B.6.6, B.6.1)."""
    return bytes((too & 0xff, tov & 0xff)) + struct.pack("<H", fan & 0xffff) + bytes((acc & 0xff,))


def asdu_disturb_hdr(
    typ: int,
    addr: int,
    inf: int = INF_DIST,
    cot: int = COT_DISTURB,
    vsq: int = 0x81,
) -> bytes:
    return asdu_header(typ, cot, addr, FUN_DIST, inf, vsq=vsq)


def asdu24_list_request(addr: int, fan: int = 0) -> bytes:
    """ASDU24 — request recorded disturbance list (TOO=24)."""
    return asdu_disturb_hdr(24, addr) + asdu_dist_cmd_body(TOO_LIST_DISTURBANCES, 1, fan, 0)


def asdu24_select_fault(addr: int, fan: int) -> bytes:
    """ASDU24 — select disturbance FAN for transfer (TOO=1)."""
    return asdu_disturb_hdr(24, addr) + asdu_dist_cmd_body(TOO_SELECT_FAULT, 1, fan, 0)


def asdu24_channel_tags(addr: int, fan: int) -> bytes:
    """ASDU24 — request channel list and status tags (TOO=16)."""
    return asdu_disturb_hdr(24, addr) + asdu_dist_cmd_body(TOO_CHANNEL_TAGS, 1, fan, 0)


def asdu24_ack_segment(addr: int, fan: int, acc: int) -> bytes:
    """ASDU24 — positive acknowledgement of disturbance data (TOO=8)."""
    return asdu_disturb_hdr(24, addr) + asdu_dist_cmd_body(TOO_ACK_DATA, 1, fan, acc)


def asdu25_select_channel(addr: int, fan: int, acc: int) -> bytes:
    """ASDU25 — ready for transmission of channel ACC."""
    return asdu_disturb_hdr(25, addr) + asdu_dist_cmd_body(TOO_SELECT_CHANNEL, 1, fan, acc)


def asdu23_entry(fan: int, fault_status: int, fault_time: bytes) -> bytes:
    """One 10-byte disturbance list row: FAN(2) + status(1) + CP56Time2a(7)."""
    return struct.pack("<H", fan) + bytes((fault_status & 0xff,)) + fault_time[:7].ljust(7, b"\x00")


def asdu23_disturbance_list(
    addr: int,
    entries: Sequence[Tuple[int, int, bytes]],
    cot: int = COT_GI,
) -> bytes:
    """ASDU23 — 被记录的扰动表 (FUN=254/255, INF=0, i rows × 10 bytes)."""
    vsq = len(entries) & 0x7f
    body = b"".join(asdu23_entry(fan, status, t) for fan, status, t in entries)
    return asdu_disturb_hdr(23, addr, cot=cot, vsq=vsq) + body


def asdu26_ready_values(
    addr: int,
    fan: int,
    tov: int = 1,
    nof: int = 0,
    noc: int = 9,
    ch_info: int = 0xE4,
    noe: int = 2,
    int_val: int = 0x03E8,
    binary_time: int = 0xFFFFFFFF,
) -> bytes:
    """ASDU26 — disturbance data transmission ready (图10)."""
    body = (
        b"\x00\x00"
        + bytes((tov & 0xff,))
        + struct.pack("<H", fan & 0xffff)
        + struct.pack("<H", nof & 0xffff)
        + bytes((noc & 0xff, ch_info & 0xff, noe & 0xff))
        + struct.pack("<H", int_val & 0xffff)
        + struct.pack("<I", binary_time & 0xFFFFFFFF)
    )
    return asdu_disturb_hdr(26, addr) + body


def asdu27_channel_ready(
    addr: int,
    fan: int,
    acc: int,
    tov: int = 1,
    rpv: float = 1.0,
    rdv: float = 1.0,
    rfa: float = 287.44,
) -> bytes:
    """ASDU27 — recorded channel ready (RPV/RDV/RFA as IEEE754, B.6.16–18)."""
    body = (
        b"\x00\x00"
        + bytes((tov & 0xff,))
        + struct.pack("<H", fan & 0xffff)
        + bytes((acc & 0xff,))
        + struct.pack("<fff", rpv, rdv, rfa)
    )
    return asdu_disturb_hdr(27, addr) + body


def asdu28_tags_ready(addr: int, fan: int) -> bytes:
    """ASDU28 — ready for transmission of tagged status changes."""
    body = b"\x00\x00" + struct.pack("<H", fan & 0xffff)
    return asdu_disturb_hdr(28, addr) + body


def asdu29_tag_entry(tap: int, fun: int, inf: int, dpi: int) -> bytes:
    """One 5-byte tagged status change: TAP(2) + FUN + INF + DPI (B.6.25, B.6.5)."""
    return struct.pack("<HBB", tap & 0xffff, fun & 0xff, inf & 0xff) + bytes((dpi & 0x03,))


def asdu29_channel_list(
    addr: int,
    fan: int,
    channels: Sequence[Tuple[int, int]],
) -> bytes:
    """ASDU29 — tagged status changes for channel list (图13)."""
    tags = [
        asdu29_tag_entry(acc, FUN_GLB, 0, dpi)
        for acc, dpi in channels
    ]
    body = struct.pack("<HB", fan & 0xffff, len(tags)) + b"".join(tags)
    return asdu_disturb_hdr(29, addr) + body


def asdu29_end_of_tags(addr: int, fan: int) -> bytes:
    """ASDU29 — end of tag transmission (NOT=0)."""
    body = struct.pack("<HB", fan & 0xffff, 0)
    return asdu_disturb_hdr(29, addr) + body


def asdu30_disturbance_data(
    addr: int,
    fan: int,
    acc: int,
    nfe: int,
    samples: Sequence[int],
    tov: int = 1,
) -> bytes:
    """ASDU30 — disturbance value block."""
    ndv = len(samples)
    sdv = b"".join(struct.pack("<h", s) for s in samples)
    body = (
        b"\x00\x00"
        + bytes((tov & 0xff,))
        + struct.pack("<H", fan)
        + bytes((acc & 0xff,))
        + struct.pack("<HH", ndv, nfe)
        + sdv
    )
    return asdu_disturb_hdr(30, addr) + body


def asdu31_channel_done(addr: int, fan: int, acc: int, too: int = TOO_ACK_DATA, tov: int = 1) -> bytes:
    """ASDU31 — end of channel transmission (图14)."""
    return asdu_disturb_hdr(31, addr) + asdu_dist_cmd_body(too, tov, fan, acc)


def asdu31_ready_next(addr: int, fan: int, too: int = 0x28, tov: int = 1) -> bytes:
    """ASDU31 — ready for next disturbance value transfer."""
    return asdu_disturb_hdr(31, addr) + asdu_dist_cmd_body(too, tov, fan, 0)


def synthetic_samples(count: int, seed: int, base: int = -0x200) -> List[int]:
    """Generate repeatable 16-bit disturbance samples."""
    out: List[int] = []
    v = base + seed
    for i in range(count):
        v = (v + ((i * 17 + seed * 3) % 31) - 15) & 0xFFFF
        if v >= 0x8000:
            v -= 0x10000
        out.append(v)
    return out


@dataclass
class DisturbanceRecord:
    """One ASDU23 row: FAN + SOF + CP56Time2a (10 bytes)."""

    fan: int = 7
    sof: int = 0
    fault_time: bytes = field(
        default_factory=lambda: cp56time2a(datetime(2008, 4, 28, 7, 20, 48))
    )


@dataclass
class WaveCatalog:
    """Per-address disturbance list entries (subset of 171_nz_103_net.txt)."""

    by_addr: Dict[int, List[DisturbanceRecord]] = field(default_factory=dict)

    @classmethod
    def demo(cls) -> "WaveCatalog":
        # Samples aligned with 171_nz_103_net.txt (FAN + SOF + 7-octet time).
        t_a = bytes.fromhex("34 2D 09 16 04 08 02")
        t_b = bytes.fromhex("23 A4 2C 09 16 04 08")
        t_c = bytes.fromhex("CF BA 2B 09 16 04 08")
        t_d = bytes.fromhex("11 6B 16 0C 19 04 08")
        return cls(
            by_addr={
                1: [
                    DisturbanceRecord(fan=7, sof=0x3B, fault_time=t_a),
                    DisturbanceRecord(fan=7, sof=0x00, fault_time=t_b),
                    DisturbanceRecord(fan=0x12, sof=0x07, fault_time=t_c),
                ],
                2: [
                    DisturbanceRecord(fan=0x1B, sof=0x00, fault_time=t_b),
                    DisturbanceRecord(fan=0x1A, sof=0x00, fault_time=t_b),
                ],
                3: [
                    DisturbanceRecord(fan=0x43, sof=0x07, fault_time=t_d),
                    DisturbanceRecord(fan=0x44, sof=0x07, fault_time=t_d),
                    DisturbanceRecord(fan=0x45, sof=0x07, fault_time=t_d),
                ],
            }
        )

    def entries_for(self, addr: int) -> List[DisturbanceRecord]:
        return self.by_addr.get(addr, [DisturbanceRecord(fan=1)])

    def asdu23_for(self, addr: int) -> bytes:
        recs = self.entries_for(addr)
        tuples = [(r.fan, r.sof, r.fault_time) for r in recs]
        return asdu23_disturbance_list(addr, tuples)


@dataclass
class ChannelPlan:
    """Channels to transfer after list/tags phase."""

    channels: List[Tuple[int, int]] = field(
        default_factory=lambda: [(1, 1), (2, 1), (3, 1), (4, 1), (5, 1), (6, 1), (7, 1)]
    )
    segments_per_channel: int = 3

    def sample_count(self, seg_idx: int) -> int:
        if seg_idx == 0:
            return NDV_FIRST_SEGMENT
        return NDV_MID_SEGMENT

    def nfe_for(self, seg_idx: int) -> int:
        if seg_idx == 0:
            return 0
        if seg_idx == 1:
            return 0x25
        return 0x5F if seg_idx == 2 else 0x33


def parse_dist_cmd(payload: bytes) -> Optional[Tuple[int, int, int, int]]:
    """Parse 5-byte ASDU24/25/31 body → (TOO, TOV, FAN, ACC)."""
    if len(payload) < 5:
        return None
    too, tov = payload[0], payload[1]
    fan = struct.unpack_from("<H", payload, 2)[0]
    acc = payload[4]
    return too, tov, fan, acc


def fan_from_dist_body(payload: bytes) -> int:
    if len(payload) >= 4:
        return struct.unpack_from("<H", payload, 2)[0]
    return 1
