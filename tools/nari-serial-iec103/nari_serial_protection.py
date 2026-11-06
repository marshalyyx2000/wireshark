# -*- coding: utf-8 -*-
"""NARI serial IEC103 simulated protection (FT1.2 slave)."""
from __future__ import annotations

import argparse
import struct
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from nari_serial_ft12 import (
    ADDR_DEFAULT,
    Ft12Parser,
    SerialRawPcapWriter,
    asdu_hdr,
    cp32,
    cp56,
    frame_fixed,
    frame_var,
    open_serial,
)


class ProtectionSlave:
    """Minimal NARI serial 103 IED: link, GI, SOE, meas, disturbance list/values."""

    def __init__(self, port: str, addr: int = ADDR_DEFAULT, baud: int = 9600, pcap=None):
        self.addr = addr
        self.ser = open_serial(port, baud)
        self.parser = Ft12Parser()
        self.pcap = pcap
        self._queue: list[bytes] = []
        self._acd = False
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.fan = 0x43
        print(f"[protection] {self.ser.name} addr={addr}", flush=True)

    def _tx(self, frame: bytes) -> None:
        self.ser.write(frame)
        self.ser.flush()
        if self.pcap:
            self.pcap.write_frame(frame)
        print(f"[protection TX] {frame.hex(' ')}", flush=True)

    def _enqueue(self, asdu: bytes, acd_more: bool = False) -> None:
        with self._lock:
            self._queue.append(asdu)
            self._acd = True if acd_more or self._queue else False

    def _pop_class1(self):
        with self._lock:
            if not self._queue:
                self._acd = False
                return None
            asdu = self._queue.pop(0)
            self._acd = bool(self._queue)
            return asdu

    def prepare_demo_events(self) -> None:
        """Prime class-1 queue with SOE + GI payload + disturbance sample."""
        a = self.addr
        # ASDU1 SOE: switch closed INF=149
        self._enqueue(asdu_hdr(1, 1, a, fun=1, inf=149) + b"\x01" + cp56(), acd_more=True)
        # ASDU5 identification
        self._enqueue(
            asdu_hdr(5, 5, a, fun=255, inf=0)
            + bytes((3,))
            + b"NARI103\x00"
            + bytes((0x10, 0x01))
            + struct.pack("<H", 0x1234),
            acd_more=True,
        )

    def _handle_fixed(self, fr: bytes) -> None:
        ctrl = fr[1]
        fc = ctrl & 0x0F
        prm = (ctrl & 0x40) != 0
        if not prm:
            return
        acd = 0x20 if self._acd else 0
        if fc in (0, 7):  # reset CU / FCB
            self._tx(frame_fixed(0x00 | acd, self.addr))
        elif fc == 9:  # link status
            self._tx(frame_fixed(0x0B | acd, self.addr))
        elif fc == 10:  # class 1
            asdu = self._pop_class1()
            if asdu is None:
                self._tx(frame_fixed(0x09 | acd, self.addr))
            else:
                more = 0x20 if self._acd else 0
                self._tx(frame_var(0x08 | more, asdu, self.addr))
        elif fc == 11:  # class 2
            self._tx(frame_fixed(0x09 | acd, self.addr))

    def _handle_var(self, fr: bytes) -> None:
        # CODE at offset 4, ASDU starts at 6, length L at 1
        L = fr[1]
        asdu = fr[6 : 6 + (L - 2)]
        if len(asdu) < 6:
            self._tx(frame_fixed(0x00, self.addr))
            return
        typ, cot = asdu[0], asdu[2]
        a = self.addr
        if typ == 6:  # time sync
            self._tx(frame_fixed(0x00, self.addr))
        elif typ == 8 and cot == 9:  # GI start
            self._tx(frame_fixed(0x20, self.addr))  # ACK+ACD
            # GI responses: meas ASDU9 + status ASDU43 + GI end ASDU8 COT10
            meas = struct.pack("<hhhh", 1000, 1100, 1200, 5000)
            self._enqueue(asdu_hdr(9, 9, a, fun=1, inf=92, vsq=4) + meas, True)
            spi = bytes((1, 0, 0, 1))  # 4 points
            self._enqueue(asdu_hdr(43, 9, a, fun=1, inf=149, vsq=4) + spi + b"\x01", True)
            self._enqueue(asdu_hdr(8, 10, a) + b"\x01", False)
        elif typ == 24:  # disturbance command
            too = asdu[6] if len(asdu) > 6 else 0
            self._tx(frame_fixed(0x20, self.addr))
            if too in (0x18, 24, 4, 1):  # request list / select
                row = struct.pack("<H", self.fan) + bytes((0x07,)) + cp56()
                self._enqueue(asdu_hdr(23, 31, a, fun=254, vsq=1) + row, True)
            if too in (2, 0x02):  # request data
                body26 = (
                    bytes((0, 0, 1))
                    + struct.pack("<H", self.fan)
                    + struct.pack("<H", 1)
                    + bytes((1, 0, 8))
                    + struct.pack("<H", 1000)
                    + struct.pack("<I", 0)
                )
                self._enqueue(asdu_hdr(26, 31, a, fun=254) + body26, True)
                body27 = (
                    bytes((0, 0, 1))
                    + struct.pack("<H", self.fan)
                    + bytes((1,))
                    + struct.pack("<fff", 100.0, 5.0, 1.0)
                )
                self._enqueue(asdu_hdr(27, 31, a, fun=254) + body27, True)
                sdv = struct.pack("<hhhh", 1000, 2000, -1500, 500)
                body30 = (
                    bytes((0, 0, 1))
                    + struct.pack("<H", self.fan)
                    + bytes((1,))
                    + struct.pack("<HH", 4, 0)
                    + sdv
                )
                self._enqueue(asdu_hdr(30, 31, a, fun=254) + body30, False)
        elif typ == 10 or typ == 21:
            self._tx(frame_fixed(0x00, self.addr))
            # echo a simple ASDU10 description
            gid = "Ia".encode("ascii") + b"\x00\x00"
            gdd = bytes((1, 4, 1)) + gid  # OS8ASCII
            gen = bytes((0x01, 0x01, 0x01, 0x01, 0x0A)) + gdd
            self._enqueue(asdu_hdr(10, 1, a, fun=254, inf=0) + gen, False)
        else:
            self._tx(frame_fixed(0x00, self.addr))

    def handle_frame(self, fr: bytes) -> None:
        if self.pcap:
            self.pcap.write_frame(fr)
        print(f"[protection RX] {fr.hex(' ')}", flush=True)
        if fr[0] == 0x10:
            self._handle_fixed(fr)
        elif fr[0] == 0x68:
            self._handle_var(fr)

    def run(self, duration: float = 30.0) -> None:
        self.prepare_demo_events()
        t_end = time.time() + duration
        while time.time() < t_end and not self._stop.is_set():
            chunk = self.ser.read(256)
            if chunk:
                for fr in self.parser.feed(chunk):
                    self.handle_frame(fr)
            else:
                time.sleep(0.01)
        self.ser.close()
        print("[protection] stopped", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="NARI serial 103 protection simulator")
    ap.add_argument("--port", default="COM11")
    ap.add_argument("--addr", type=lambda x: int(x, 0), default=ADDR_DEFAULT)
    ap.add_argument("--baud", type=int, default=9600)
    ap.add_argument("--duration", type=float, default=30.0)
    ap.add_argument("--pcap", type=Path, default=None)
    ap.add_argument("--pcap-proto", default="serial_raw")
    args = ap.parse_args()
    pcap = SerialRawPcapWriter(args.pcap, args.pcap_proto) if args.pcap else None
    try:
        ProtectionSlave(args.port, args.addr, args.baud, pcap).run(args.duration)
    finally:
        if pcap:
            pcap.close()
            print(f"[protection] wrote {pcap.count} frames -> {pcap.path}", flush=True)


if __name__ == "__main__":
    main()