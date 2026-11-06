# -*- coding: utf-8 -*-
"""NARI serial IEC103 simulated master/client (FT1.2)."""
from __future__ import annotations

import argparse
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from nari_serial_ft12 import (
    ADDR_DEFAULT,
    Ft12Parser,
    SerialRawPcapWriter,
    asdu_hdr,
    cp56,
    frame_fixed,
    frame_var,
    open_serial,
)


class MasterClient:
    def __init__(self, port: str, addr: int = ADDR_DEFAULT, baud: int = 9600, pcap=None):
        self.addr = addr
        self.ser = open_serial(port, baud)
        self.parser = Ft12Parser()
        self.pcap = pcap
        self.fcb = 0x20
        print(f"[client] {self.ser.name} addr={addr}", flush=True)

    def _m_ctrl(self, fc: int, fcv: int = 0, toggle: bool = False) -> int:
        c = 0x40 | (fc & 0x0F)
        if fcv:
            c |= 0x10 | self.fcb
            if toggle:
                self.fcb ^= 0x20
        return c

    def _tx(self, frame: bytes) -> None:
        self.ser.write(frame)
        self.ser.flush()
        if self.pcap:
            self.pcap.write_frame(frame)
        print(f"[client TX] {frame.hex(' ')}", flush=True)

    def _recv(self, wait: float = 0.8):
        frames = []
        t_end = time.time() + wait
        while time.time() < t_end:
            chunk = self.ser.read(256)
            if chunk:
                for fr in self.parser.feed(chunk):
                    if self.pcap:
                        self.pcap.write_frame(fr)
                    print(f"[client RX] {fr.hex(' ')}", flush=True)
                    frames.append(fr)
                    # keep reading briefly for multi-frame bursts
                    t_end = max(t_end, time.time() + 0.15)
            else:
                time.sleep(0.02)
        return frames

    def session(self) -> None:
        a = self.addr
        # Reset FCB / link
        self._tx(frame_fixed(self._m_ctrl(7), a)); self._recv(0.5)
        self._tx(frame_fixed(self._m_ctrl(9), a)); self._recv(0.5)

        # Class1: pick primed SOE / ID
        for _ in range(4):
            self._tx(frame_fixed(self._m_ctrl(10, fcv=1, toggle=True), a))
            rs = self._recv(0.6)
            if not rs:
                break
            # stop if last response has ACD=0 and is fixed no-data
            last = rs[-1]
            if last[0] == 0x10 and (last[1] & 0x20) == 0:
                break

        # Time sync
        self._tx(frame_var(self._m_ctrl(3, fcv=1, toggle=True), asdu_hdr(6, 8, a) + cp56(), a))
        self._recv(0.5)

        # General interrogation
        self._tx(frame_var(self._m_ctrl(3, fcv=1, toggle=True), asdu_hdr(8, 9, a) + b"\x01", a))
        self._recv(0.5)
        for _ in range(8):
            self._tx(frame_fixed(self._m_ctrl(10, fcv=1, toggle=True), a))
            rs = self._recv(0.7)
            if not rs:
                break
            # GI end when ASDU8 COT=10 seen
            done = False
            for fr in rs:
                if fr[0] == 0x68 and len(fr) >= 12 and fr[6] == 8 and fr[8] == 10:
                    done = True
            if done:
                break

        # Class2 poll (doc 8.1)
        self._tx(frame_fixed(self._m_ctrl(11, fcv=1, toggle=True), a)); self._recv(0.4)

        # Disturbance list request ASDU24 TOO=0x18
        body = asdu_hdr(24, 31, a, fun=254) + bytes((0x18, 0x01)) + struct.pack("<H", 0) + b"\x00"
        self._tx(frame_var(self._m_ctrl(3, fcv=1, toggle=True), body, a)); self._recv(0.5)
        for _ in range(3):
            self._tx(frame_fixed(self._m_ctrl(10, fcv=1, toggle=True), a)); self._recv(0.6)

        # Request disturbance data TOO=2
        body2 = asdu_hdr(24, 31, a, fun=254) + bytes((0x02, 0x01)) + struct.pack("<H", 0x43) + b"\x00"
        self._tx(frame_var(self._m_ctrl(3, fcv=1, toggle=True), body2, a)); self._recv(0.5)
        for _ in range(6):
            self._tx(frame_fixed(self._m_ctrl(10, fcv=1, toggle=True), a))
            rs = self._recv(0.7)
            if not rs:
                break

        # Generic read ASDU21
        cmd = asdu_hdr(21, 42, a, fun=254) + bytes((0x01, 0x01, 0x01, 0x01, 0x0A))
        self._tx(frame_var(self._m_ctrl(3, fcv=1, toggle=True), cmd, a)); self._recv(0.5)
        self._tx(frame_fixed(self._m_ctrl(10, fcv=1, toggle=True), a)); self._recv(0.6)

        self.ser.close()
        print("[client] session done", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="NARI serial 103 master/client simulator")
    ap.add_argument("--port", default="COM10")
    ap.add_argument("--addr", type=lambda x: int(x, 0), default=ADDR_DEFAULT)
    ap.add_argument("--baud", type=int, default=9600)
    ap.add_argument("--pcap", type=Path, default=None)
    ap.add_argument("--pcap-proto", default="serial_raw")
    args = ap.parse_args()
    pcap = SerialRawPcapWriter(args.pcap, args.pcap_proto) if args.pcap else None
    try:
        MasterClient(args.port, args.addr, args.baud, pcap).session()
    finally:
        if pcap:
            pcap.close()
            print(f"[client] wrote {pcap.count} frames -> {pcap.path}", flush=True)


if __name__ == "__main__":
    main()