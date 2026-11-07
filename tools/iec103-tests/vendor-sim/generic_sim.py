# -*- coding: utf-8 -*-
"""声明式帧厂家的模拟器：按 generic-spec.json 生成保护侧 + 主站报文。

用法
    python generic_sim.py --all
    python generic_sim.py --vendor sh2000
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path
from typing import Dict, List, Tuple

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[2]
sys.path.insert(0, str(SRC_ROOT / "tools" / "iec103-sim"))

import iec103_core as c103  # noqa: E402
import iec103_net_sim as nsim  # noqa: E402

SPEC = SRC_ROOT / "tools" / "protocol-audit" / "generic-spec.json"
OUT = HERE / "out"


def load_spec() -> List[Dict]:
    return json.loads(SPEC.read_text(encoding="utf-8"))["vendors"]


def crc16_modbus(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF


def finish(v: Dict, frame: bytes) -> bytes:
    """按 spec 的 crc 设定补校验尾（以及 CRC 之后的固定尾字节）。"""
    kind = v["crc"]
    off = v.get("crc_off", 0)
    extra = v.get("crc_tail_extra", 0)
    tail_byte = v.get("crc_tail_byte", 0)

    span = frame[off:]
    tail = b""
    if kind == "sum8":
        tail = struct.pack("<H", sum(span) & 0xFFFF)
    elif kind == "sum8_low":
        tail = bytes((sum(span) & 0xFF,))
    elif kind == "modbus16":
        tail = struct.pack("<H", crc16_modbus(span))

    if extra > 0:
        tail += bytes((tail_byte,)) * extra
    return frame + tail


def header_len(v: Dict) -> int:
    """帧头长度：spec 里各字段位置的最大上界（与 make_frame 保持一致）。"""
    return max(
        v["addr_off"] + v["addr_size"] if v["addr_off"] >= 0 else 0,
        v["cmd_off"] + 1 if v["cmd_off"] >= 0 else 0,
        v["len_off"] + v["len_size"] if v["len_off"] >= 0 else 0,
        len(bytes.fromhex(v["sig"])) if v["sig"] else 0)


def make_frame(v: Dict, body: bytes, addr: int, cmd: int) -> bytes:
    sig = bytes.fromhex(v["sig"]) if v["sig"] else b""
    head = bytearray()

    # 按 spec 的字段位置拼装头部；未指定的位置用 0 填充。
    hdr_len = header_len(v)
    head = bytearray(hdr_len)
    head[:len(sig)] = sig

    if v["addr_off"] >= 0:
        head[v["addr_off"]:v["addr_off"] + v["addr_size"]] = addr.to_bytes(
            v["addr_size"], "little")
    if v["cmd_off"] >= 0:
        head[v["cmd_off"]] = cmd & 0xFF

    payload = bytes(head) + body
    if v["len_off"] >= 0:
        total = len(payload) + v["crc_tail"]
        field = total - v["len_bias"]
        endian = "big" if v["len_be"] else "little"
        payload = (payload[:v["len_off"]]
                   + (field & ((1 << (v["len_size"] * 8)) - 1)).to_bytes(v["len_size"], endian)
                   + payload[v["len_off"] + v["len_size"]:])
    frame = finish(v, payload)
    return frame


# 每家两条命令：一条主站请求，一条装置应答
MASTER_CMD = 0x01
SLAVE_CMD = 0x02


def build_records(v: Dict) -> List[Tuple[float, bytes, str]]:
    addr = 0x05
    ts = 1_700_000_000.0
    out: List[Tuple[float, bytes, str]] = []
    serial = v["carrier"] == "serial"
    tag = "serial_raw" if serial else ""

    master_bodies = [b"\x00\x01\x00\x02", b"\x10\x20\x30", b""]
    slave_bodies = [b"\xaa\x55\x01\x02\x03\x04", b"\x11\x22\x33\x44", b""]

    # 长度不可自描述的厂家需要保证帧长不短于 min_len
    def pad(b: bytes) -> bytes:
        need = v["min_len"] - len(b)
        return b + b"\x00" * need if need > 0 else b

    if v.get("ascii_line"):
        # 文本行规约：命令字 + 参数，以 CR 结束
        master_bodies = [b"METER,1,2\r", b"READ,VOLT\r", b"STATUS\r"]
        slave_bodies = [b"METER,1,220.5,50.0\r", b"READ,VOLT,220.5\r", b"STATUS,OK\r"]

    # 定长帧必须精确对齐到 fixed_len：按 spec 的头部长度算出主体长度
    fixed = v.get("fixed_len", 0)
    if fixed > 0:
        hdr_len = header_len(v)
        body_len = fixed - v["crc_tail"] - v.get("crc_tail_extra", 0) - hdr_len
        if body_len >= 0:
            master_bodies = [(b + b"\x00" * body_len)[:body_len] for b in master_bodies]
            slave_bodies = [(b + b"\x00" * body_len)[:body_len] for b in slave_bodies]

    # 无长度字段且非定长的厂家，用 min_len 保证帧不被当成过短
    if v.get("fixed_len", 0) <= 0 and v["len_off"] < 0:
        master_bodies = [pad(b) for b in master_bodies]
        slave_bodies = [pad(b) for b in slave_bodies]

    for body in master_bodies:
        out.append((ts, make_frame(v, body, addr, MASTER_CMD), tag))
        ts += 0.05
    for body in slave_bodies:
        out.append((ts, make_frame(v, body, addr, SLAVE_CMD), tag))
        ts += 0.05
    return out


def write_pcap(v: Dict) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    short = v["short"]
    path = OUT / f"{short}.pcap"
    records = build_records(v)

    if v["carrier"] == "serial":
        c103.write_pcap(path, records)
        return path

    frames = []
    ts = 1_700_000_000.0
    off_m = off_s = 0
    half = len(records) // 2
    for i, (_t, payload, _tag) in enumerate(records):
        if v["carrier"] == "udp":
            frames.append((ts, nsim.ipv4_udp("192.168.130.10", "192.168.130.20",
                                             53000, 7001, payload,
                                             dst_mac="00:11:22:33:44:66")))
        elif i < half:
            frames.append((ts, nsim.ipv4_tcp("192.168.130.10", "192.168.130.20",
                                             53000, 7001, 1000 + off_m, 5000 + off_s,
                                             0x18, payload,
                                             dst_mac="00:11:22:33:44:66")))
            off_m += len(payload)
        else:
            frames.append((ts, nsim.ipv4_tcp("192.168.130.20", "192.168.130.10",
                                             7001, 53000, 5000 + off_s, 1000 + off_m,
                                             0x18, payload,
                                             dst_mac="00:11:22:33:44:55")))
            off_s += len(payload)
        ts += 0.05
    nsim.write_net_pcap(path, [(t, f, "") for t, f in frames])
    return path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vendor", default=None)
    ap.add_argument("--all", action="store_true")
    args = ap.parse_args()

    vendors = load_spec()
    if args.vendor:
        vendors = [v for v in vendors if v["short"] == args.vendor]
        if not vendors:
            raise SystemExit(f"unknown vendor {args.vendor}")

    for v in vendors:
        p = write_pcap(v)
        print(f"{p.name}  ({p.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
