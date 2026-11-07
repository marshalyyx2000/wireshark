# -*- coding: utf-8 -*-
"""Vendor simulator: 四方 (sifang) / 深圳南瑞 (sznari) serial IEC 60870-5-103.

Runs a simulated protection relay (slave) and a simulated master (client) over a
com0com virtual serial pair, exchanging the full 103 interaction:

    reset CU -> ident (ASDU5) -> GI (ASDU7) -> GI data (ASDU2/3)
    -> time sync (ASDU6) -> disturbance sequence (ASDU23..31)

Usage
    python iec103_serial_sim.py --vendor sifang --mode both --port COM6 --peer COM7
    python iec103_serial_sim.py --vendor sifang --mode protection --port COM7
    python iec103_serial_sim.py --vendor sznari --mode wire --port COM6 --pcap out.pcap

`--mode wire` emits the whole conversation on one port (for serialdump capture)
and optionally writes an Exported PDU pcap with the vendor dissector name.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import iec103_core as c103  # noqa: E402

try:
    import serial  # type: ignore
except ImportError:  # wire/pcap modes work without pyserial
    serial = None

DEFAULT_ADDR = 0x03

VENDORS = {
    "sifang": {
        "dissector": "sifang_serial_iec103",
        "fun": c103.FUN_DISTANCE,
        "desc": b"SIFANG  CSC-103  V1.02",
        "point_points": [
            (c103.FUN_DISTANCE, 16, "距离I段动作"),
            (c103.FUN_DISTANCE, 17, "距离II段动作"),
            (c103.FUN_OVERCURRENT, 16, "过流I段动作"),
            (c103.FUN_GENERIC, 1, "定值组"),
        ],
    },
    "sznari": {
        "dissector": "sznari_serial_iec103",
        "fun": c103.FUN_OVERCURRENT,
        "desc": b"SZNARI  PRS-103  V2.00",
        "point_points": [
            (c103.FUN_DISTANCE, 16, "距离I段动作"),
            (c103.FUN_OVERCURRENT, 16, "过流I段动作"),
            (c103.FUN_OVERCURRENT, 17, "过流II段动作"),
            (c103.FUN_GENERIC, 2, "测量值组"),
        ],
    },
}


def open_port(name: str, baud: int = 9600):
    if serial is None:
        raise SystemExit("pyserial required for serial modes: pip install pyserial")
    path = name if name.startswith("\\\\.\\") else f"\\\\.\\{name}"
    return serial.Serial(path, baudrate=baud, bytesize=8, parity="E",
                         stopbits=1, timeout=0.2, write_timeout=1)


def recv_frame(port) -> Optional[bytes]:
    """Read one FT1.2 frame from the serial port."""
    start = port.read(1)
    if not start:
        return None
    if start == bytes((c103.SINGLE,)):
        return start
    if start == bytes((c103.FIXED,)):
        rest = port.read(4)
        return start + rest if len(rest) == 4 else None
    if start == bytes((c103.VAR,)):
        head = port.read(3)
        if len(head) != 3:
            return None
        length = head[0]
        rest = port.read(length + 2)
        return start + head + rest if len(rest) == length + 2 else None
    return None


# --------------------------------------------------------------------------

def build_conversation(vendor: str, addr: int) -> List[Tuple[str, bytes]]:
    """Return [(direction, ft1.2 frame)] for one full master/slave exchange."""
    cfg = VENDORS[vendor]
    fun = cfg["fun"]
    frames: List[Tuple[str, bytes]] = []

    def m2s(ctrl_fc: int, asdu: Optional[bytes] = None, fcb: int = 1) -> None:
        ctrl = 0x40 | ((fcb & 1) << 5) | (0x10 if asdu else 0x00) | (ctrl_fc & 0x0F)
        frame = c103.frame_fixed(ctrl, addr) if asdu is None else c103.frame_var(ctrl, addr, asdu)
        frames.append(("master", frame))

    def s2m(ctrl_fc: int, asdu: Optional[bytes] = None, acd: bool = False) -> None:
        ctrl = ((0x20 if acd else 0x00)) | (ctrl_fc & 0x0F)
        frame = c103.frame_fixed(ctrl, addr) if asdu is None else c103.frame_var(ctrl, addr, asdu)
        frames.append(("slave", frame))

    # 1. reset communication unit
    m2s(c103.FC_RESET_CU, None, fcb=0)
    s2m(c103.FC_CONFIRM, None, acd=True)

    # 2. class 1 poll -> ident
    m2s(c103.FC_REQ_CLASS1, None)
    s2m(c103.FC_RESP_DATA, c103.asdu_ident(addr, desc=cfg["desc"]), acd=True)
    m2s(c103.FC_REQ_CLASS1, None)
    s2m(c103.FC_NO_DATA, None)

    # 3. general interrogation
    m2s(c103.FC_SEND_CONFIRM, c103.asdu_gi_start(addr, scn=1))
    s2m(c103.FC_CONFIRM, None, acd=True)

    m2s(c103.FC_REQ_CLASS2, None)
    s2m(c103.FC_RESP_DATA, c103.asdu_protection_event(
        addr, c103.FUN_DISTANCE, 16, dpi=2), acd=True)

    m2s(c103.FC_REQ_CLASS2, None)
    s2m(c103.FC_RESP_DATA, c103.asdu_protection_event(
        addr, c103.FUN_OVERCURRENT, 16, dpi=2), acd=False)

    m2s(c103.FC_REQ_CLASS2, None)
    s2m(c103.FC_RESP_DATA, c103.asdu_time_tagged(
        addr, c103.FUN_DISTANCE, 18, dpi=1), acd=False)

    m2s(c103.FC_REQ_CLASS2, None)
    s2m(c103.FC_RESP_DATA, c103.asdu_measured(
        addr, fun, 0, [1.732, 2.045, 1.998]), acd=False)

    m2s(c103.FC_REQ_CLASS2, None)
    s2m(c103.FC_RESP_DATA, c103.asdu_generic(addr, [
        c103.gdd_entry(1, 1, 0x01, 7, 4, b"\x41\x20\x00\x00"),   # 定值 10.0
        c103.gdd_entry(1, 2, 0x01, 7, 4, b"\x41\x10\x00\x00"),   # 定值 9.0
    ], cot=c103.COT_GI, fun=c103.FUN_GENERIC, inf=1), acd=False)

    m2s(c103.FC_REQ_CLASS2, None)
    s2m(c103.FC_RESP_DATA, c103.asdu_gi_end(addr, scn=1), acd=False)

    # 4. time sync (broadcast style, FCV=0)
    m2s(c103.FC_SEND_NOCONF, c103.asdu_time_sync(addr), fcb=0)
    s2m(c103.FC_CONFIRM, None)

    # 5. disturbance data sequence
    m2s(c103.FC_SEND_CONFIRM, c103.asdu_dist_cmd(addr, 24))
    s2m(c103.FC_CONFIRM, None, acd=True)
    m2s(c103.FC_REQ_CLASS1, None)
    s2m(c103.FC_RESP_DATA, c103.asdu_dist_header(addr, 1, [(7, 0x03, None)]), acd=True)

    m2s(c103.FC_SEND_CONFIRM, c103.asdu_dist_cmd(addr, 1))
    s2m(c103.FC_CONFIRM, None, acd=True)
    m2s(c103.FC_REQ_CLASS1, None)
    s2m(c103.FC_RESP_DATA, c103.asdu_dist_ready(addr, 1, 7, 1, 1, 0), acd=True)
    m2s(c103.FC_SEND_CONFIRM, c103.asdu_dist_ack(addr, 64))
    s2m(c103.FC_CONFIRM, None, acd=True)

    m2s(c103.FC_REQ_CLASS1, None)
    s2m(c103.FC_RESP_DATA, c103.asdu_chan_ready(addr, 1, 7, 1, 100.0, 1.0, 0.01), acd=True)
    m2s(c103.FC_SEND_CONFIRM, c103.asdu_dist_ack(addr, 64))
    s2m(c103.FC_CONFIRM, None, acd=True)

    m2s(c103.FC_REQ_CLASS1, None)
    s2m(c103.FC_RESP_DATA, c103.asdu_flag_ready(addr, 1, 7, 2), acd=True)
    m2s(c103.FC_SEND_CONFIRM, c103.asdu_dist_ack(addr, 64))
    s2m(c103.FC_CONFIRM, None, acd=True)

    m2s(c103.FC_REQ_CLASS1, None)
    s2m(c103.FC_RESP_DATA, c103.asdu_flag_data(addr, 1), acd=True)
    m2s(c103.FC_SEND_CONFIRM, c103.asdu_dist_ack(addr, 64))
    s2m(c103.FC_CONFIRM, None, acd=True)

    m2s(c103.FC_REQ_CLASS1, None)
    s2m(c103.FC_RESP_DATA, c103.asdu_dist_data(
        addr, [1000, 1200, 1400, 1600, 1800, 2000, 1800, 1600]), acd=True)
    m2s(c103.FC_SEND_CONFIRM, c103.asdu_dist_ack(addr, 64))
    s2m(c103.FC_CONFIRM, None, acd=True)

    m2s(c103.FC_REQ_CLASS1, None)
    s2m(c103.FC_RESP_DATA, c103.asdu_dist_end(addr, 32), acd=True)
    m2s(c103.FC_SEND_CONFIRM, c103.asdu_dist_ack(addr, 64))
    s2m(c103.FC_CONFIRM, None)

    return frames


# --------------------------------------------------------------------------

def run_pair(vendor: str, master_port: str, slave_port: str, addr: int,
             pcap: Optional[Path], duration: float, neutral: bool = True) -> int:
    """Play the recorded conversation in order over a real serial pair.

    Each step writes the next frame on the correct port and drains the peer so
    both directions stay in sync and every frame is captured. With
    ``neutral=True`` every record is tagged ``serial_raw`` so the file carries no
    protocol hint; the GUI menu selects the actual dissector.
    """
    frames = build_conversation(vendor, addr)
    master = open_port(master_port)
    slave = open_port(slave_port)
    records: List[Tuple[float, bytes, str]] = []
    start = time.time()
    tag = "serial_raw" if neutral else VENDORS[vendor]["dissector"]
    written = {"master": 0, "slave": 0}

    try:
        for direction, frame in frames:
            if (time.time() - start) > duration:
                break
            port, peer = (master, slave) if direction == "master" else (slave, master)
            port.reset_input_buffer()
            port.write(frame)
            port.flush()
            records.append((time.time() - start, frame, tag))
            written[direction] += 1

            # Wait briefly for the peer's answer, then drain it so the next
            # step starts from a clean buffer.
            time.sleep(0.03)
            drain = recv_frame(peer)
            if drain:
                records.append((time.time() - start, drain, tag))
            time.sleep(0.01)
    finally:
        master.close()
        slave.close()

    if pcap:
        c103.write_pcap(pcap, records)
        print(f"pcap: {pcap} ({len(records)} frames, "
              f"master={written['master']} slave={written['slave']})")
    return 0


def run_wire(vendor: str, port: str, addr: int, pcap: Optional[Path],
             duration: float, delay: float, neutral: bool = True) -> int:
    frames = build_conversation(vendor, addr)
    records: List[Tuple[float, bytes, str]] = []
    start = time.time()
    tag = "serial_raw" if neutral else VENDORS[vendor]["dissector"]
    if port.upper() != "NONE":
        sp = open_port(port)
        for _direction, frame in frames:
            sp.write(frame)
            sp.flush()
            records.append((time.time() - start, frame, tag))
            time.sleep(delay)
        sp.close()
    else:
        for _direction, frame in frames:
            records.append((time.time() - start, frame, tag))
            time.sleep(delay)
    if pcap:
        c103.write_pcap(pcap, records)
        print(f"pcap: {pcap} ({len(records)} frames)")
    _ = duration
    return 0


def run_protection(vendor: str, port: str, addr: int, duration: float) -> int:
    frames = [f for d, f in build_conversation(vendor, addr) if d == "slave"]
    sp = open_port(port)
    start = time.time()
    pending = list(frames)
    try:
        while (time.time() - start) < duration:
            _ = recv_frame(sp)
            if pending:
                sp.write(pending.pop(0))
                sp.flush()
    finally:
        sp.close()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="IEC 60870-5-103 serial simulator")
    ap.add_argument("--vendor", choices=sorted(VENDORS), default="sifang")
    ap.add_argument("--mode", choices=["both", "wire", "protection"], default="wire")
    ap.add_argument("--port", default="COM6", help="master port (or wire output)")
    ap.add_argument("--peer", default="COM7", help="protection side port")
    ap.add_argument("--addr", type=lambda v: int(v, 0), default=DEFAULT_ADDR)
    ap.add_argument("--pcap", type=Path, default=None)
    ap.add_argument("--duration", type=float, default=30.0)
    ap.add_argument("--delay", type=float, default=0.03)
    args = ap.parse_args()

    if args.mode == "both":
        return run_pair(args.vendor, args.port, args.peer, args.addr, args.pcap, args.duration)
    if args.mode == "protection":
        return run_protection(args.vendor, args.peer, args.addr, args.duration)
    return run_wire(args.vendor, args.port, args.addr, args.pcap, args.duration, args.delay)


if __name__ == "__main__":
    raise SystemExit(main())
