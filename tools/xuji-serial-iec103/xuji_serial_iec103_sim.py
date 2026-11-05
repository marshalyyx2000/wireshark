#!/usr/bin/env python3
"""Xuji serial IEC 60870-5-103 FT1.2 simulator (9600 8E1).

Modes:
  both  - master on --port, slave on --peer (interactive)
  wire  - emit full master+slave conversation on --port for serialdump peer
"""

from __future__ import annotations

import argparse
import struct
import sys
import threading
import time
from datetime import datetime
from typing import List, Sequence

try:
    import serial
except ImportError:
    print("pip install pyserial", file=sys.stderr)
    raise

ADDR = 0x19  # demo device address (from public examples)


def cs8(data: bytes) -> int:
    return sum(data) & 0xFF


def frame_fixed(ctrl: int, addr: int = ADDR) -> bytes:
    body = bytes((ctrl & 0xFF, addr & 0xFF))
    return bytes((0x10,)) + body + bytes((cs8(body), 0x16))


def frame_var(ctrl: int, asdu: bytes, addr: int = ADDR) -> bytes:
    mid = bytes((ctrl & 0xFF, addr & 0xFF)) + asdu
    L = len(mid)
    return bytes((0x68, L, L, 0x68)) + mid + bytes((cs8(mid), 0x16))


def asdu_hdr(typ: int, cot: int, addr: int = ADDR, fun: int = 255, inf: int = 0, vsq: int = 0x81) -> bytes:
    return bytes((typ & 0xFF, vsq & 0xFF, cot & 0xFF, addr & 0xFF, fun & 0xFF, inf & 0xFF))


def cp56(dt: datetime | None = None) -> bytes:
    """CP56Time2a — used by ASDU6 time sync (规约表7)."""
    if dt is None:
        dt = datetime(2008, 4, 28, 7, 20, 48)
    ms = dt.microsecond // 1000 + dt.second * 1000
    dow = dt.isoweekday() % 7
    day_dow = (dt.day & 0x1F) | ((dow & 7) << 5)
    return struct.pack(
        "<HBBBBB", ms, dt.minute & 0x3F, dt.hour & 0x1F, day_dow, dt.month & 0x0F, dt.year % 100
    )


def cp32(dt: datetime | None = None) -> bytes:
    """CP32Time2a — used by ASDU1/2/43 teleindication (规约表10)."""
    if dt is None:
        dt = datetime(2008, 4, 28, 7, 20, 48)
    ms = dt.microsecond // 1000 + dt.second * 1000
    return struct.pack("<HBB", ms, dt.minute & 0x3F, dt.hour & 0x1F)


def open_port(name: str, baud: int = 9600) -> serial.Serial:
    path = name if name.startswith("\\\\.\\") else f"\\\\.\\{name}"
    return serial.Serial(
        path,
        baudrate=baud,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_EVEN,
        stopbits=serial.STOPBITS_ONE,
        timeout=0.3,
        write_timeout=2.0,
    )


def build_conversation(addr: int = ADDR) -> List[bytes]:
    """Full init + GI + disturbance list/transfer frames (both directions)."""
    frames: List[bytes] = []
    fcb = 0x20

    def m_ctrl(fc: int, fcv: int = 0, toggle: bool = False) -> int:
        nonlocal fcb
        # PRM=1
        c = 0x40 | (fc & 0x0F)
        if fcv:
            c |= 0x10 | fcb
            if toggle:
                fcb ^= 0x20
        return c

    def s_ctrl(fc: int, acd: int = 0) -> int:
        # PRM=0
        return (acd & 0x20) | (fc & 0x0F)

    # Reset FCB
    frames.append(frame_fixed(m_ctrl(7), addr))
    frames.append(frame_fixed(s_ctrl(0, acd=0x20), addr))  # ACK + ACD
    # Class 1 -> ASDU5 identification
    frames.append(frame_fixed(m_ctrl(10, fcv=1, toggle=True), addr))
    # ASDU5: COL + 8 ASCII model + BCD ver(frac,int) + CRC ROM (规约表6)
    asdu5 = asdu_hdr(5, 5, addr) + bytes((3,)) + b"XUJI103\x00" + bytes((0x10, 0x01, 0x34, 0x12))
    frames.append(frame_var(s_ctrl(8), asdu5, addr))
    # Reset CU
    frames.append(frame_fixed(m_ctrl(0), addr))
    frames.append(frame_fixed(s_ctrl(0), addr))
    # Link status
    frames.append(frame_fixed(m_ctrl(9), addr))
    frames.append(frame_fixed(s_ctrl(11), addr))
    # Time sync ASDU6
    frames.append(frame_var(m_ctrl(3, fcv=1, toggle=True), asdu_hdr(6, 8, addr) + cp56(), addr))
    frames.append(frame_fixed(s_ctrl(0), addr))
    # General interrogation ASDU7
    frames.append(frame_var(m_ctrl(3, fcv=1, toggle=True), asdu_hdr(7, 9, addr) + b"\x00", addr))
    frames.append(frame_fixed(s_ctrl(0, acd=0x20), addr))
    # Class1: ASDU1 spontaneous + ASDU8 GI end
    frames.append(frame_fixed(m_ctrl(10, fcv=1, toggle=True), addr))
    # ASDU1: DPI(合=2) + CP32Time2a (+ SCN) — 规约表10
    frames.append(
        frame_var(
            s_ctrl(8, acd=0x20),
            asdu_hdr(1, 1, addr, fun=178, inf=1) + b"\x02" + cp32() + b"\x00",
            addr,
        )
    )
    frames.append(frame_fixed(m_ctrl(10, fcv=1, toggle=True), addr))
    frames.append(frame_var(s_ctrl(8), asdu_hdr(8, 10, addr) + b"\x00", addr))

    # Disturbance: ASDU24 list request / ASDU23 list / select / ASDU26 / channels / ASDU30
    fan = 0x43
    frames.append(
        frame_var(
            m_ctrl(3, fcv=1, toggle=True),
            asdu_hdr(24, 31, addr, fun=254)
            + bytes((0x18, 0x01))
            + struct.pack("<H", 0)
            + b"\x00",
            addr,
        )
    )
    frames.append(frame_fixed(s_ctrl(0, acd=0x20), addr))
    frames.append(frame_fixed(m_ctrl(10, fcv=1, toggle=True), addr))
    t = bytes.fromhex("342D0916040802")
    rows = b"".join(struct.pack("<H", f) + bytes((sof,)) + t for f, sof in ((0x43, 7), (0x44, 7), (0x45, 0)))
    frames.append(frame_var(s_ctrl(8, acd=0x20), asdu_hdr(23, 9, addr, fun=254, vsq=3) + rows, addr))

    frames.append(
        frame_var(
            m_ctrl(3, fcv=1, toggle=True),
            asdu_hdr(24, 31, addr, fun=254) + bytes((0x01, 0x01)) + struct.pack("<H", fan) + b"\x00",
            addr,
        )
    )
    frames.append(frame_fixed(s_ctrl(0, acd=0x20), addr))
    frames.append(frame_fixed(m_ctrl(10, fcv=1, toggle=True), addr))
    # ASDU26 表41: 未用 + TOV + FAN + NOF + NOC + NOE + INT(µs) + CP32
    asdu26 = (
        asdu_hdr(26, 31, addr, fun=254)
        + b"\x00\x01"
        + struct.pack("<H", fan)
        + struct.pack("<H", 9)  # NOF
        + bytes((4,))  # NOC
        + struct.pack("<H", 60)  # NOE
        + struct.pack("<H", 1000)  # INT µs
        + cp32()
    )
    frames.append(frame_var(s_ctrl(8), asdu26, addr))

    # 4 channels of values (ACC 1..4 = IA..3I0)
    for acc in range(1, 5):
        frames.append(
            frame_var(
                m_ctrl(3, fcv=1, toggle=True),
                asdu_hdr(24, 31, addr, fun=254) + bytes((0x08, 0x01)) + struct.pack("<H", fan) + bytes((acc,)),
                addr,
            )
        )
        frames.append(frame_fixed(s_ctrl(0, acd=0x20), addr))
        frames.append(frame_fixed(m_ctrl(10, fcv=1, toggle=True), addr))
        # ASDU27 表49: 未用 + TOV + FAN + ACC + RPV + RDV + RFA
        asdu27 = (
            asdu_hdr(27, 31, addr, fun=254)
            + b"\x00\x01"
            + struct.pack("<H", fan)
            + bytes((acc,))
            + struct.pack("<fff", 1.0, 1.0, 100.0)
        )
        frames.append(frame_var(s_ctrl(8, acd=0x20), asdu27, addr))
        for seg in range(3):
            frames.append(frame_fixed(m_ctrl(10, fcv=1, toggle=True), addr))
            ndv = 20  # 规约表51: NDV ≤ 25
            sdv = b"".join(struct.pack("<h", (acc * 100 + seg * 10 + i) % 2000 - 1000) for i in range(ndv))
            # ASDU30 表51: 未用×2 + TOV + FAN + ACC + NDV + NFE + SDV×NDV
            asdu30 = (
                asdu_hdr(30, 31, addr, fun=254)
                + b"\x00\x00\x01"
                + struct.pack("<H", fan)
                + bytes((acc, ndv))
                + struct.pack("<H", seg * 20)
                + sdv
            )
            frames.append(frame_var(s_ctrl(8, acd=0x20 if seg < 2 else 0), asdu30, addr))
        frames.append(frame_fixed(m_ctrl(10, fcv=1, toggle=True), addr))
        frames.append(
            frame_var(
                s_ctrl(8),
                asdu_hdr(31, 31, addr, fun=254) + bytes((0x23, 0x01)) + struct.pack("<H", fan) + bytes((acc,)),
                addr,
            )
        )

    # Class 2 empty
    frames.append(frame_fixed(m_ctrl(11, fcv=1, toggle=True), addr))
    frames.append(frame_fixed(s_ctrl(9), addr))
    return frames


def run_wire(port: str, baud: int, rounds: int = 1) -> None:
    frames = build_conversation()
    ser = open_port(port, baud)
    print(f"[wire] {ser.name} frames={len(frames)*rounds}", flush=True)
    try:
        for r in range(rounds):
            for i, fr in enumerate(frames):
                ser.write(fr)
                ser.flush()
                print(f"[wire {r+1}.{i+1}] {fr.hex(' ')}", flush=True)
                time.sleep(0.04)
    finally:
        ser.close()


def run_both(port: str, peer: str, baud: int) -> None:
    """Slave on peer, master on port — interactive short session."""
    slave_done = threading.Event()

    def slave() -> None:
        s = open_port(peer, baud)
        print(f"[slave] {s.name}", flush=True)
        buf = bytearray()
        try:
            while not slave_done.is_set():
                chunk = s.read(256)
                if not chunk:
                    continue
                buf += chunk
                # Very small reactive slave: ACK fixed frames, echo class1 empty
                while True:
                    if len(buf) >= 1 and buf[0] == 0xE5:
                        del buf[0]
                        continue
                    if len(buf) >= 5 and buf[0] == 0x10 and buf[4] == 0x16:
                        fr = bytes(buf[:5])
                        del buf[:5]
                        ctrl = fr[1]
                        fc = ctrl & 0x0F
                        if fc in (0, 7, 9):
                            s.write(frame_fixed(0x00 if fc != 9 else 0x0B))
                        elif fc in (10, 11):
                            s.write(frame_fixed(0x09))  # no data
                        print(f"[slave] fixed fc={fc}", flush=True)
                        continue
                    if len(buf) >= 6 and buf[0] == 0x68 and buf[3] == 0x68:
                        L = buf[1]
                        need = L + 6
                        if len(buf) < need:
                            break
                        fr = bytes(buf[:need])
                        del buf[:need]
                        s.write(frame_fixed(0x00))
                        print(f"[slave] var L={L}", flush=True)
                        continue
                    if len(buf) > 0 and buf[0] not in (0x10, 0x68, 0xE5):
                        del buf[0]
                        continue
                    break
        finally:
            s.close()

    t = threading.Thread(target=slave, daemon=True)
    t.start()
    time.sleep(0.2)
    m = open_port(port, baud)
    print(f"[master] {m.name}", flush=True)
    try:
        for fr in build_conversation()[:12]:
            m.write(fr)
            m.flush()
            time.sleep(0.05)
            rsp = m.read(256)
            print(f"[master] tx={fr.hex(' ')} rx={rsp.hex(' ') if rsp else ''}", flush=True)
    finally:
        slave_done.set()
        m.close()
        time.sleep(0.2)


def main() -> None:
    ap = argparse.ArgumentParser(description="Xuji serial IEC103 FT1.2 simulator")
    ap.add_argument("--mode", choices=("wire", "both"), default="wire")
    ap.add_argument("--port", default="CNCA0")
    ap.add_argument("--peer", default="CNCB0")
    ap.add_argument("--baud", type=int, default=9600)
    ap.add_argument("--rounds", type=int, default=1)
    args = ap.parse_args()
    if args.mode == "wire":
        run_wire(args.port, args.baud, args.rounds)
    else:
        run_both(args.port, args.peer, args.baud)


if __name__ == "__main__":
    main()