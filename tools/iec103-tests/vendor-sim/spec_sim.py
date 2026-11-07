# -*- coding: utf-8 -*-
"""Spec 驱动的厂家模拟器：同一份 vendor-spec.json 生成保护侧 + 主站报文。

- serial_ft12 : FT1.2 帧写入中性 Exported PDU（serial_raw）
- tcp_ft12    : FT1.2 帧承载于 TCP（长度字段可为 16 位小端）
- tcp_apci    : 私有 APCI + ASDU，TCP 流
- udp_apci    : 私有 APCI + ASDU，一报一数据报
- tcp_asdu    : 裸 ASDU 流
- udp_asdu    : 一报一数据报，裸 ASDU

被 run_vendor_sim2.py（写 pcap）和 live 模式（真实 TCP 连接）共用。
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path
from typing import Dict, List, Tuple

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[2]
sys.path.insert(0, str(SRC_ROOT / "tools" / "iec103-sim"))

import iec103_core as c103  # noqa: E402

SPEC_PATH = SRC_ROOT / "tools" / "protocol-audit" / "vendor-spec.json"

ADDR = 0x03


def load_spec() -> Dict:
    return json.loads(SPEC_PATH.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# ASDU sets
# --------------------------------------------------------------------------

def protection_asdus(addr: int = ADDR) -> List[bytes]:
    """保护装置（从站）上送的一轮完整报文，覆盖 ASDU1..31。"""
    return [
        c103.asdu_ident(addr, desc=b"VENDOR 103 SIM"),
        c103.asdu_gi_start(addr, scn=1),
        c103.asdu_protection_event(addr, c103.FUN_DISTANCE, 16, dpi=2),
        c103.asdu_protection_event(addr, c103.FUN_OVERCURRENT, 16, dpi=2),
        c103.asdu_time_tagged(addr, c103.FUN_DISTANCE, 18, dpi=1),
        c103.asdu_measured(addr, c103.FUN_OVERCURRENT, 0, [1.732, 2.045, 1.998]),
        c103.asdu_generic(addr, [
            c103.gdd_entry(1, 1, 0x01, 7, 4, struct.pack(">f", 10.0)),
            c103.gdd_entry(1, 2, 0x01, 7, 4, struct.pack(">f", 9.0)),
        ], cot=c103.COT_GI, fun=c103.FUN_GENERIC, inf=1),
        c103.asdu_gi_end(addr, scn=1),
        c103.asdu_time_sync(addr),
        c103.asdu_dist_header(addr, 1, [(7, 0x03, None)]),
        c103.asdu_dist_cmd(addr, 24),
        c103.asdu_dist_ack(addr, 64),
        c103.asdu_dist_ready(addr, 1, 7, 1, 1, 0),
        c103.asdu_chan_ready(addr, 1, 7, 1, 100.0, 1.0, 0.01),
        c103.asdu_flag_ready(addr, 1, 7, 2),
        c103.asdu_flag_data(addr, 1),
        c103.asdu_dist_data(addr, [500, 900, 1400, 2100]),
        c103.asdu_dist_end(addr, 32),
    ]


def master_asdus(addr: int = ADDR) -> List[bytes]:
    """主站下发的一轮命令。"""
    return [
        c103.asdu_time_sync(addr),
        c103.asdu_gi_start(addr, scn=1),
        c103.asdu_command(addr, dco=0x02, rii=3),
        c103.asdu_generic_cmd(addr, 2, [
            c103.gdd_entry(1, 1, 0x01, 0, 0, b""),
            c103.gdd_entry(1, 2, 0x01, 0, 0, b""),
        ]),
        c103.asdu_dist_cmd(addr, 24),
        c103.asdu_dist_ack(addr, 64),
    ]


def widen_cot(asdu: bytes) -> bytes:
    """把 1 字节 COT 的标准 ASDU 改写成 2 字节 COT（104 风格）。"""
    if len(asdu) < 6:
        return asdu
    return asdu[:3] + b"\x00" + asdu[3:]


def shape_asdu(asdu: bytes, vendor: Dict) -> bytes:
    return widen_cot(asdu) if vendor.get("cot_len", 1) == 2 else asdu


# --------------------------------------------------------------------------
# Private APCI wrappers
# --------------------------------------------------------------------------

def wrap_apci(asdu: bytes, apci: Dict, addr: int = ADDR) -> bytes:
    """按 reference 实现的布局给 ASDU 套上私有传输头。"""
    hdr_len = apci["hdr_len"]
    # 帧总长 = hdr_len + len(asdu)，长度字段 = 总长 - len_bias
    total = hdr_len + len(asdu)
    field = total - apci["len_bias"]

    body = bytearray(hdr_len)
    for off, val in apci["sig"]:
        body[off] = val

    # 长度字段
    size = apci["len_size"]
    endian = "big" if apci["len_be"] else "little"
    body[apci["len_off"]:apci["len_off"] + size] = (field & ((1 << (size * 8)) - 1)).to_bytes(
        size, endian)

    # 地址 / 报文类型 / 保留字节：按 28 字节头的固定位置填充，
    # 其它布局（6 字节 APDU 头）保持签名占位值。
    if hdr_len == 28:
        body[14] = addr & 0xFF          # 目标地址
        body[16] = 0x00                 # 报文类型 0 = 103 报文
        body[21:28] = b"\xFF" * 7       # 保留字节（参考实现为 7 个 FF）
    return bytes(body) + asdu


# --------------------------------------------------------------------------
# FT1.2 framing
# --------------------------------------------------------------------------

def frame_var16le(ctrl: int, addr: int, asdu: bytes) -> bytes:
    """FT1.2 可变帧，长度字段为 16 位小端（buf[1] | buf[2] << 8）。"""
    length = len(asdu)
    head = bytes((0x68, length & 0xFF, (length >> 8) & 0xFF, 0x68, ctrl & 0xFF, addr & 0xFF))
    body = asdu
    cs = (sum(body) + (ctrl & 0xFF) + (addr & 0xFF)) & 0xFF
    return head + body + bytes((cs, 0x16))


def frame_var_addr2(ctrl: int, addr: int, asdu: bytes) -> bytes:
    """FT1.2 可变帧，链路地址 2 字节（ABB_COM_101）。

    长度字段从控制域起算：ctrl(1) + 地址(2) + ASDU。
    """
    length = 3 + len(asdu)
    head = bytes((0x68, length, length, 0x68, ctrl & 0xFF,
                  addr & 0xFF, (addr >> 8) & 0xFF))
    cs = (sum(asdu) + (ctrl & 0xFF) + (addr & 0xFF) + ((addr >> 8) & 0xFF)) & 0xFF
    return head + asdu + bytes((cs, 0x16))


def frame_var_std(ctrl: int, addr: int, asdu: bytes) -> bytes:
    return c103.frame_var(ctrl, addr, asdu)


# --------------------------------------------------------------------------
# Frame streams
# --------------------------------------------------------------------------

def build_records(vendor: Dict) -> List[Tuple[float, bytes, str]]:
    """返回 (时间戳, 帧字节, Exported PDU 名)。网络帧 PDU 名为空。"""
    transport = vendor["transport"]
    apci = None
    spec = load_spec()
    if vendor.get("apci"):
        apci = spec["apci"][vendor["apci"]]

    addr = ADDR
    ts = 1_700_000_000.0
    out: List[Tuple[float, bytes, str]] = []

    if transport == "serial_ft12":
        fcb = 0
        addr2 = vendor.get("ft12_addr_len", 1) == 2
        for asdu in master_asdus(addr):
            body = shape_asdu(asdu, vendor)
            ctrl = 0x40 | ((fcb & 1) << 5) | 0x10 | c103.FC_SEND_CONFIRM
            frame = (frame_var_addr2(ctrl, addr, body) if addr2
                     else frame_var_std(ctrl, addr, body))
            out.append((ts, frame, "serial_raw"))
            ts += 0.02
        for asdu in protection_asdus(addr):
            body = shape_asdu(asdu, vendor)
            frame = (frame_var_addr2(0x08, addr, body) if addr2
                     else frame_var_std(0x08, addr, body))
            out.append((ts, frame, "serial_raw"))
            ts += 0.02
        return out

    if transport == "tcp_ft12":
        maker = frame_var16le if vendor.get("ft12_len16le") else frame_var_std
        for asdu in master_asdus(addr):
            out.append((ts, maker(0x5A, addr, shape_asdu(asdu, vendor)), ""))
            ts += 0.02
        for asdu in protection_asdus(addr):
            out.append((ts, maker(0x08, addr, shape_asdu(asdu, vendor)), ""))
            ts += 0.02
        return out

    if transport in ("udp_ft12",):
        for asdu in master_asdus(addr):
            out.append((ts, frame_var_std(0x5A, addr, shape_asdu(asdu, vendor)), ""))
            ts += 0.02
        for asdu in protection_asdus(addr):
            out.append((ts, frame_var_std(0x08, addr, shape_asdu(asdu, vendor)), ""))
            ts += 0.02
        return out

    def pack(asdu: bytes) -> bytes:
        body = shape_asdu(asdu, vendor)
        return wrap_apci(body, apci, addr) if apci else body

    if transport in ("tcp_apci", "tcp_asdu"):
        for asdu in master_asdus(addr):
            out.append((ts, pack(asdu), ""))
            ts += 0.02
        for asdu in protection_asdus(addr):
            out.append((ts, pack(asdu), ""))
            ts += 0.02
        return out

    if transport in ("udp_apci", "udp_asdu", "udp_ft12"):
        for asdu in master_asdus(addr):
            body = shape_asdu(asdu, vendor)
            out.append((ts, wrap_apci(body, apci, addr) if apci else body, ""))
            ts += 0.02
        for asdu in protection_asdus(addr):
            body = shape_asdu(asdu, vendor)
            out.append((ts, wrap_apci(body, apci, addr) if apci else body, ""))
            ts += 0.02
        return out

    raise SystemExit(f"unknown transport {transport}")


def is_udp(vendor: Dict) -> bool:
    return vendor["transport"].startswith("udp")


def expected_port(vendor: Dict) -> int:
    return vendor.get("port", 0) or 2404
