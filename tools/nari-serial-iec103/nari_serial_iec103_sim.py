#!/usr/bin/env python3
"""NARI serial IEC 60870-5-103 FT1.2 frame builder / demo conversation."""
from __future__ import annotations
import argparse
import struct
from datetime import datetime
from pathlib import Path
from typing import List

ADDR = 0x0F


def cs8(data: bytes) -> int:
    return sum(data) & 0xFF


def frame_fixed(ctrl: int, addr: int = ADDR) -> bytes:
    body = bytes((ctrl & 0xFF, addr & 0xFF))
    return bytes((0x10,)) + body + bytes((cs8(body), 0x16))


def frame_var(ctrl: int, asdu: bytes, addr: int = ADDR) -> bytes:
    mid = bytes((ctrl & 0xFF, addr & 0xFF)) + asdu
    L = len(mid)
    return bytes((0x68, L, L, 0x68)) + mid + bytes((cs8(mid), 0x16))


def asdu_hdr(typ: int, cot: int, addr: int = ADDR, fun: int = 1, inf: int = 0, vsq: int = 0x81) -> bytes:
    return bytes((typ & 0xFF, vsq & 0xFF, cot & 0xFF, addr & 0xFF, fun & 0xFF, inf & 0xFF))


def cp56(dt: datetime | None = None) -> bytes:
    if dt is None:
        dt = datetime(2024, 11, 6, 10, 30, 0)
    ms = dt.microsecond // 1000 + dt.second * 1000
    dow = dt.isoweekday() % 7
    day_dow = (dt.day & 0x1F) | ((dow & 7) << 5)
    return struct.pack("<HBBBBB", ms, dt.minute & 0x3F, dt.hour & 0x1F, day_dow, dt.month & 0x0F, dt.year % 100)


def cp32(dt: datetime | None = None) -> bytes:
    if dt is None:
        dt = datetime(2024, 11, 6, 10, 30, 0)
    ms = dt.microsecond // 1000 + dt.second * 1000
    return struct.pack("<HBB", ms, dt.minute & 0x3F, dt.hour & 0x1F)


def build_conversation(addr: int = ADDR) -> List[bytes]:
    frames: List[bytes] = []
    fcb = 0x20

    def m_ctrl(fc: int, fcv: int = 0, toggle: bool = False) -> int:
        nonlocal fcb
        c = 0x40 | (fc & 0x0F)
        if fcv:
            c |= 0x10 | fcb
            if toggle:
                fcb ^= 0x20
        return c

    def s_ctrl(fc: int, acd: int = 0) -> int:
        return (acd & 0x20) | (fc & 0x0F)

    # Doc 8.1 / 8.2 / 8.3
    frames.append(bytes.fromhex("105B0F6A16"))  # class2 poll
    frames.append(bytes.fromhex("10090F1816"))  # no data
    frames.append(bytes.fromhex("10490F5816"))  # ACD=1

    # Class1 -> ASDU1 SPI+CP56
    frames.append(frame_fixed(m_ctrl(10, fcv=1, toggle=True), addr))
    frames.append(frame_var(s_ctrl(8), asdu_hdr(1, 1, addr, fun=1, inf=149) + b"\x01" + cp56(), addr))

    # GI ASDU8 COT=9 / ASDU9 meas / ASDU8 COT=10
    frames.append(frame_var(m_ctrl(3, fcv=1, toggle=True), asdu_hdr(8, 9, addr) + b"\x01", addr))
    frames.append(frame_fixed(s_ctrl(0, acd=0x20), addr))
    frames.append(frame_fixed(m_ctrl(10, fcv=1, toggle=True), addr))
    meas = struct.pack("<hhhh", 1000, 1100, 1200, 5000)
    frames.append(frame_var(s_ctrl(8, acd=0x20), asdu_hdr(9, 9, addr, fun=1, inf=92, vsq=4) + meas, addr))
    frames.append(frame_fixed(m_ctrl(10, fcv=1, toggle=True), addr))
    frames.append(frame_var(s_ctrl(8), asdu_hdr(8, 10, addr) + b"\x01", addr))

    # ASDU10 generic: RII + NGD(1) + GIN + KOD + GDD(R32) + float
    gid = struct.pack("<f", 12.5)
    gdd = bytes((7, 4, 1)) + gid  # R32, size4, num1
    gen = bytes((0x11, 0x01, 0x01, 0x01, 0x01)) + gdd  # RII, NGD=1, group1 entry1 KOD=value
    frames.append(frame_var(s_ctrl(8), asdu_hdr(10, 1, addr, fun=254, inf=0) + gen, addr))

    # Disturbance sequence for wave tap / COMTRADE
    fan = 0x43
    frames.append(
        frame_var(
            m_ctrl(3, fcv=1, toggle=True),
            asdu_hdr(24, 31, addr, fun=254) + bytes((0x18, 0x01)) + struct.pack("<H", 0) + b"\x00",
            addr,
        )
    )
    frames.append(frame_fixed(s_ctrl(0, acd=0x20), addr))
    frames.append(frame_fixed(m_ctrl(10, fcv=1, toggle=True), addr))
    t = cp56()
    rows = struct.pack("<H", fan) + bytes((0x07,)) + t
    frames.append(frame_var(s_ctrl(8, acd=0x20), asdu_hdr(23, 31, addr, fun=254, vsq=1) + rows, addr))

    # ASDU26 ready
    asdu26 = bytes((0, 0, 1)) + struct.pack("<H", fan) + struct.pack("<H", 1) + bytes((1, 0, 8)) + struct.pack("<H", 1000) + struct.pack("<I", 0)
    frames.append(frame_var(s_ctrl(8, acd=0x20), asdu_hdr(26, 31, addr, fun=254) + asdu26, addr))

    # ASDU27 channel scale ACC=1
    asdu27 = bytes((0, 0, 1)) + struct.pack("<H", fan) + bytes((1,)) + struct.pack("<fff", 100.0, 5.0, 1.0)
    frames.append(frame_var(s_ctrl(8, acd=0x20), asdu_hdr(27, 31, addr, fun=254) + asdu27, addr))

    # ASDU30 NDV=4
    sdv = struct.pack("<hhhh", 1000, 2000, -1000, 0)
    asdu30 = bytes((0, 0, 1)) + struct.pack("<H", fan) + bytes((1,)) + struct.pack("<HH", 4, 0) + sdv
    frames.append(frame_var(s_ctrl(8), asdu_hdr(30, 31, addr, fun=254) + asdu30, addr))

    return frames


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hex", action="store_true", help="print hex frames")
    ap.add_argument("--bin", type=Path, help="write concatenated frames to binary file")
    args = ap.parse_args()
    frames = build_conversation()
    if args.hex or not args.bin:
        for i, f in enumerate(frames, 1):
            print(f"{i:02d}: {f.hex()}")
    if args.bin:
        args.bin.write_bytes(b"".join(frames))
        print(f"wrote {args.bin} ({sum(len(f) for f in frames)} bytes)")


if __name__ == "__main__":
    main()
