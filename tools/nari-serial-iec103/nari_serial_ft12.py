# -*- coding: utf-8 -*-
"""Shared FT1.2 helpers and serial_raw / exported-PDU pcap writer."""
from __future__ import annotations

import struct
import time
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, List, Optional

ADDR_DEFAULT = 0x0F
PCAP_MAGIC = 0xA1B2C3D4
PCAP_LINKTYPE = 252
EXP_PDU_TAG_DISSECTOR_NAME = 12
SNAPLEN = 256 * 1024


def cs8(data: bytes) -> int:
    return sum(data) & 0xFF


def frame_fixed(ctrl: int, addr: int = ADDR_DEFAULT) -> bytes:
    body = bytes((ctrl & 0xFF, addr & 0xFF))
    return bytes((0x10,)) + body + bytes((cs8(body), 0x16))


def frame_var(ctrl: int, asdu: bytes, addr: int = ADDR_DEFAULT) -> bytes:
    mid = bytes((ctrl & 0xFF, addr & 0xFF)) + asdu
    L = len(mid)
    return bytes((0x68, L, L, 0x68)) + mid + bytes((cs8(mid), 0x16))


def asdu_hdr(typ, cot, addr=ADDR_DEFAULT, fun=1, inf=0, vsq=0x81) -> bytes:
    return bytes((typ & 0xFF, vsq & 0xFF, cot & 0xFF, addr & 0xFF, fun & 0xFF, inf & 0xFF))


def cp56(dt: Optional[datetime] = None) -> bytes:
    if dt is None:
        dt = datetime.now()
    ms = dt.microsecond // 1000 + dt.second * 1000
    dow = dt.isoweekday() % 7
    day_dow = (dt.day & 0x1F) | ((dow & 7) << 5)
    return struct.pack("<HBBBBB", ms, dt.minute & 0x3F, dt.hour & 0x1F, day_dow, dt.month & 0x0F, dt.year % 100)


def cp32(dt: Optional[datetime] = None) -> bytes:
    if dt is None:
        dt = datetime.now()
    ms = dt.microsecond // 1000 + dt.second * 1000
    return struct.pack("<HBB", ms, dt.minute & 0x3F, dt.hour & 0x1F)


def open_serial(port: str, baud: int = 9600):
    import serial
    return serial.Serial(
        port,
        baudrate=baud,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_EVEN,
        stopbits=serial.STOPBITS_ONE,
        timeout=0.2,
        write_timeout=2.0,
    )


class Ft12Parser:
    def __init__(self) -> None:
        self.buf = bytearray()

    def feed(self, data: bytes) -> List[bytes]:
        self.buf += data
        out: List[bytes] = []
        while True:
            n = self._need()
            if n == 0:
                break
            if n < 0:
                del self.buf[0]
                continue
            if len(self.buf) < n:
                break
            out.append(bytes(self.buf[:n]))
            del self.buf[:n]
        return out

    def _need(self) -> int:
        if not self.buf:
            return 0
        b0 = self.buf[0]
        if b0 == 0xE5:
            return 1
        if b0 == 0x10:
            if len(self.buf) < 5:
                return 0
            return 5 if self.buf[4] == 0x16 else -1
        if b0 == 0x68:
            if len(self.buf) < 4:
                return 0
            if self.buf[1] != self.buf[2] or self.buf[3] != 0x68:
                return -1
            need = self.buf[1] + 6
            if len(self.buf) < need:
                return 0
            return need if self.buf[need - 1] == 0x16 else -1
        return -1


class SerialRawPcapWriter:
    def __init__(self, path: Path, protocol: str = "serial_raw") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.protocol = protocol
        self._fp: BinaryIO = self.path.open("wb")
        self.count = 0
        self._fp.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, SNAPLEN, PCAP_LINKTYPE))

    def write_frame(self, frame: bytes) -> None:
        name = self.protocol.encode("ascii") + b"\x00"
        name_len = (len(name) + 3) & ~3
        namebuf = name + b"\x00" * (name_len - len(name))
        total = 4 + name_len + 4 + len(frame)
        now = int(time.time())
        rec = struct.pack("<IIII", now, 0, total, total)
        tlv = struct.pack(">HH", EXP_PDU_TAG_DISSECTOR_NAME, name_len)
        self._fp.write(rec + tlv + namebuf + b"\x00\x00\x00\x00" + frame)
        self._fp.flush()
        self.count += 1

    def close(self) -> None:
        self._fp.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()