#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
YS800-W register map for address 5000+ (YSV2.9 section 9.5).

Each acquisition point occupies 18 bytes (9 Modbus registers):
  [4B voltage float LE][comm][pos][00][00][4B zero][4B full][44 59]
"""

from __future__ import annotations

import math
import struct
import time
from typing import List


MAGIC = b"\x44\x59"
BASE_REGISTER = 5000
REGISTER_END = 5506  # exclusive upper bound used by the captured poll cycle


def pack_unit(
    voltage: float,
    comm: int = 0x00,
    position: int = 0x00,
    zero: float = 0.757155,
    full: float = 1.0,
) -> bytes:
    """position: 0x00=投入, 0x01=退出; comm: 0x00=正常, 0xFF=中断."""
    block = bytearray(18)
    struct.pack_into("<f", block, 0, voltage)
    block[4] = comm & 0xFF
    block[5] = position & 0xFF
    struct.pack_into("<f", block, 8, zero)
    struct.pack_into("<f", block, 12, full)
    block[16:18] = MAGIC
    return bytes(block)


class YushunDevice:
    """In-memory Modbus holding register image for wired / voltage-sensor points."""

    def __init__(self, unit_count: int = 56) -> None:
        self.unit_count = unit_count
        self._units: List[bytes] = []
        self._seed_demo_units()
        self._flat = self._build_flat_image()

    def _seed_demo_units(self) -> None:
        # Values loosely inspired by the user's capture (-110 V class potentials).
        templates = [
            (-110.015, 0x00, 0x00, 0.757155, 1.0),
            (-58.509, 0x00, 0x01, 0.0, 1.0),
            (-109.865, 0x00, 0x00, 0.746065, 1.0),
            (-31.996, 0x00, 0x01, 0.0, 1.0),
            (-7.506, 0x00, 0x01, 0.0, 1.0),
            (-6.166, 0x00, 0x01, 0.0, 1.0),
            (-5.081, 0x00, 0x01, 0.0, 1.0),
            (-1.420, 0x00, 0x01, 0.0, 1.0),
            (-27.586, 0x00, 0x00, 0.218612, 1.0),
            (-41.061, 0x00, 0x00, 0.868652, 1.0),
            (-36.220, 0x00, 0x00, 0.809998, 1.0),
            (-32.031, 0x00, 0x00, 0.968475, 1.0),
            (-28.500, 0x00, 0x00, 0.0, 1.0),
            (-17.250, 0x00, 0x01, 0.0, 1.0),
            (-14.133, 0x00, 0x01, 0.0, 1.0),
            (-19.555, 0x00, 0x01, 0.0, 1.0),
            (-30.141, 0x00, 0x01, 0.0, 1.0),
        ]
        for index in range(self.unit_count):
            voltage, comm, pos, zero, full = templates[index % len(templates)]
            wobble = math.sin((index + 1) * 0.7) * 0.35
            self._units.append(pack_unit(voltage + wobble, comm, pos, zero, full))

    def _build_flat_image(self) -> bytearray:
        raw = bytearray()
        for unit in self._units:
            raw.extend(unit)
        # Pad to cover the last poll ending at register 5505.
        need_bytes = (REGISTER_END - BASE_REGISTER) * 2
        if len(raw) < need_bytes:
            raw.extend(b"\x00" * (need_bytes - len(raw)))
        return raw

    def tick(self) -> None:
        """Slowly drift voltages so repeated polls are not byte-identical."""
        now = time.time()
        for index, unit in enumerate(self._units):
            voltage, comm, pos, zero, full = struct.unpack("<fBBxxff", unit[:16])
            drift = math.sin(now * 0.2 + index) * 0.05
            self._units[index] = pack_unit(voltage + drift, comm, pos, zero, full)
        self._flat = self._build_flat_image()

    def read_registers(self, start: int, quantity: int) -> bytes:
        if quantity <= 0 or quantity > 125:
            raise ValueError("invalid register quantity")
        byte_start = (start - BASE_REGISTER) * 2
        byte_end = byte_start + quantity * 2
        if byte_start < 0 or byte_end > len(self._flat):
            raise IndexError(f"register range {start}-{start + quantity - 1} out of map")
        return bytes(self._flat[byte_start:byte_end])
