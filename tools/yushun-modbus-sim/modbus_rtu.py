#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Modbus RTU frame helpers (CRC16, encode/decode)."""

from __future__ import annotations

import struct
from typing import Optional, Tuple


def crc16_modbus(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def append_crc(payload: bytes) -> bytes:
    crc = crc16_modbus(payload)
    return payload + struct.pack("<H", crc)


def verify_crc(frame: bytes) -> bool:
    if len(frame) < 4:
        return False
    payload, crc_bytes = frame[:-2], frame[-2:]
    expected = struct.unpack("<H", crc_bytes)[0]
    return crc16_modbus(payload) == expected


def hex_line(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def build_read_holding_registers(slave: int, start: int, quantity: int) -> bytes:
    pdu = struct.pack(">B B H H", slave, 0x03, start, quantity)
    return append_crc(pdu)


def build_read_response(slave: int, register_bytes: bytes) -> bytes:
    if len(register_bytes) % 2:
        raise ValueError("register data must have even length")
    if len(register_bytes) > 250:
        raise ValueError("Modbus RTU read response exceeds 125 registers")
    pdu = struct.pack(">B B B", slave, 0x03, len(register_bytes)) + register_bytes
    return append_crc(pdu)


def parse_request(frame: bytes) -> Optional[Tuple[int, int, int, int]]:
    """
    Parse a Modbus RTU read-holding-registers request.
    Returns (slave, function, start_register, quantity) or None.
    """
    if not verify_crc(frame) or len(frame) < 8:
        return None
    slave, function, start, quantity = struct.unpack(">B B H H", frame[:6])
    if function != 0x03:
        return None
    return slave, function, start, quantity
