# -*- coding: utf-8 -*-
"""厂家 Modbus 模拟器：保护侧（从站应答）+ 主站（请求）+ 中性 pcap。

帧格式（PROTOCOL/ModBus、GE_Modbus）：
    RTU: 单元号 | 功能码 | 数据 | CRC16(小端)
    TCP: MBAP(事务号2|协议0|长度2|单元号) | 功能码 | 数据

用法
    python modbus_sim.py --all
    python modbus_sim.py --vendor modbus_protection
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path
from typing import Dict, List, Tuple

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[2]
sys.path.insert(0, str(SRC_ROOT / "tools" / "iec103-sim"))

import iec103_net_sim as nsim  # noqa: E402

OUT = HERE / "out"
UNIT = 0x11

FN_READ_HOLDING = 0x03
FN_READ_INPUT = 0x04
FN_WRITE_MULTI = 0x10

# 协议短名 -> (显示名, 承载)
VENDORS: Dict[str, Tuple[str, str]] = {
    "modbus_protection": ("保护装置 Modbus(RTU)", "serial"),
    "ge_modbus_rtu": ("GE Modbus(RTU)", "serial"),
    "ge_mlink_modbus": ("GE MLINK 调制解调器 Modbus", "serial"),
    "ge_modem_modbus_tcp": ("GE 调制解调器 Modbus/TCP", "tcp"),
}


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF


def rtu(unit: int, body: bytes) -> bytes:
    frame = bytes((unit,)) + body
    return frame + struct.pack("<H", crc16(frame))


def mbap(txn: int, unit: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", txn, 0, len(pdu) + 1, unit) + pdu


def master_frames() -> List[bytes]:
    """主站请求：读保持寄存器、读输入寄存器、写多寄存器。"""
    return [
        rtu(UNIT, bytes((FN_READ_HOLDING,)) + struct.pack(">HH", 0x0000, 8)),
        rtu(UNIT, bytes((FN_READ_INPUT,)) + struct.pack(">HH", 0x0100, 16)),
        rtu(UNIT, bytes((FN_WRITE_MULTI,)) + struct.pack(">HHB", 0x0200, 2, 4)
            + struct.pack(">HH", 100, 200)),
    ]


def slave_frames() -> List[bytes]:
    """从站应答：寄存器数据 + 异常应答。"""
    regs = struct.pack(">8H", 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007)
    inputs = struct.pack(">16H", *range(2000, 2016))
    return [
        rtu(UNIT, bytes((FN_READ_HOLDING, len(regs))) + regs),
        rtu(UNIT, bytes((FN_READ_INPUT, len(inputs))) + inputs),
        rtu(UNIT, bytes((FN_WRITE_MULTI,)) + struct.pack(">HH", 0x0200, 2)),
        # 异常应答：非法数据地址
        rtu(UNIT, bytes((FN_READ_HOLDING | 0x80, 0x02))),
    ]


def build(short: str) -> Path:
    display, kind = VENDORS[short]
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"{short}.pcap"
    ts = 1_700_000_000.0

    if kind == "serial":
        sys.path.insert(0, str(SRC_ROOT / "tools" / "iec103-sim"))
        import iec103_core as c103
        records = []
        for f in master_frames() + slave_frames():
            records.append((ts, f, "serial_raw"))
            ts += 0.05
        c103.write_pcap(path, records)
        return path

    frames = []
    txn = 1
    off_m = off_s = 0
    for f in master_frames():
        payload = mbap(txn, UNIT, f[1:])
        frames.append((ts, nsim.ipv4_tcp("192.168.110.10", "192.168.110.20",
                                         52000, 502, 1000 + off_m, 5000 + off_s, 0x18,
                                         payload, dst_mac="00:11:22:33:44:66")))
        off_m += len(payload)
        txn += 1
        ts += 0.05
    for f in slave_frames():
        payload = mbap(txn, UNIT, f[1:])
        frames.append((ts, nsim.ipv4_tcp("192.168.110.20", "192.168.110.10",
                                         502, 52000, 5000 + off_s, 1000 + off_m, 0x18,
                                         payload, dst_mac="00:11:22:33:44:55")))
        off_s += len(payload)
        txn += 1
        ts += 0.05
    nsim.write_net_pcap(path, [(t, f, "") for t, f in frames])
    return path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vendor", default=None)
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()

    names = [args.vendor] if args.vendor else sorted(VENDORS)
    for short in names:
        if short not in VENDORS:
            print(f"unknown vendor {short}")
            continue
        p = build(short)
        print(f"{p.name}  ({p.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
