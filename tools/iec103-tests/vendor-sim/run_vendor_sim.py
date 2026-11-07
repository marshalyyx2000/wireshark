# -*- coding: utf-8 -*-
"""103 家族补充厂家的模拟保护 + 模拟主站 + 基准抓包。

复用 tools/iec103-sim 的编解码与以太网写盘，只补各厂家的帧封装差异：
  - 串口厂家：FT1.2 帧写入 serial_raw（中性）
  - 网络厂家：普通以太网 TCP 帧（中性）

用法
    python run_vendor_sim.py                # 生成全部基准 pcap
    python run_vendor_sim.py --vendor nz103ii_serial_iec103
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path
from typing import List, Tuple

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[2]
sys.path.insert(0, str(SRC_ROOT / "tools" / "iec103-sim"))

import iec103_core as c103  # noqa: E402
import iec103_net_sim as nsim  # noqa: E402

OUT = HERE / "out"

# 协议短名 -> (承载, 端口, 显示名)
VENDORS = {
    "nr103_serial_iec103": ("serial", 0, "南瑞串口103(NR103)"),
    "nr103_rcs9691_serial_iec103": ("serial", 0, "南瑞 RCS-9691 串口103"),
    "xj103_com_serial_iec103": ("serial", 0, "许继串口103(XJ_103_COM)"),
    "xj_com103_serial_iec103": ("serial", 0, "许继串口103(XJ_COM103)"),
    "nz103ii_serial_iec103": ("serial", 0, "南自串口103(II)"),
    "sf103_csc103a_serial_iec103": ("serial", 0, "四方 CSC-103A 串口103"),
    "xj_net103_wxh13": ("net", 2404, "许继网络103(WXH13)"),
    "sf_net103_tcp": ("net", 2404, "四方网络103(TCP)"),
    "keli_103_tcp": ("net", 2404, "开利网络103"),
}

ADDR = 0x03

# 这些厂商的 ASDU 头里 COT 占 2 字节（参考实现为 104 风格）
COT16_VENDORS = {
    "xj103_com_serial_iec103",
    "xj_com103_serial_iec103",
    "xj_net103_wxh13",
    "sf_net103_tcp",
}


def asdu_header16(typ: int, cot: int, addr: int, fun: int, inf: int,
                  vsq: int = 0x81) -> bytes:
    """2 字节 COT 的 ASDU 头：TYP|VSQ|COT(2)|ADDR|FUN|INF。"""
    return bytes((typ & 0xFF, vsq & 0xFF, cot & 0xFF, 0x00, addr & 0xFF,
                  fun & 0xFF, inf & 0xFF))


def widen_cot(asdu: bytes) -> bytes:
    """把 1 字节 COT 的标准 ASDU 改写成 2 字节 COT 形式。"""
    if len(asdu) < 6:
        return asdu
    typ, vsq, cot, addr, fun, inf = asdu[:6]
    return asdu_header16(typ, cot, addr, fun, inf, vsq) + asdu[6:]


def protection_asdus(addr: int = ADDR) -> List[bytes]:
    """保护侧（从站）主动上送的 ASDU 集合。"""
    return [
        c103.asdu_ident(addr, desc=b"VENDOR 103  SIM"),
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
    return [
        c103.asdu_time_sync(addr),
        c103.asdu_gi_start(addr, scn=1),
        c103.asdu_command(addr, dco=0x02, rii=3),
        c103.asdu_dist_cmd(addr, 24),
        c103.asdu_dist_ack(addr, 64),
    ]


def serial_records(proto: str) -> List[Tuple[float, bytes, str]]:
    """FT1.2 帧，Exported PDU 名称统一 serial_raw（中性）。"""
    out: List[Tuple[float, bytes, str]] = []
    ts = 1_700_000_000.0
    addr = ADDR
    fcb = 0
    wide = proto in COT16_VENDORS

    def m2s(asdu: bytes | None, fc: int) -> None:
        nonlocal fcb
        ctrl = 0x40 | ((fcb & 1) << 5) | (0x10 if asdu else 0x00) | (fc & 0x0F)
        out.append((ts, c103.frame_var(ctrl, addr, asdu) if asdu else
                    c103.frame_fixed(ctrl, addr), "serial_raw"))

    for asdu in master_asdus():
        m2s(widen_cot(asdu) if wide else asdu, c103.FC_SEND_CONFIRM)
    for asdu in protection_asdus():
        ctrl = 0x08
        body = widen_cot(asdu) if wide else asdu
        out.append((ts, c103.frame_var(ctrl, addr, body), "serial_raw"))
        ts += 0.02
    return [(t, f, p) for t, f, p in out]


def net_records(proto: str, port: int) -> List[Tuple[float, bytes]]:
    """普通以太网 TCP 帧（中性）。"""
    out: List[Tuple[float, bytes]] = []
    ts = 1_700_000_000.0
    isn_m, isn_s = 1000, 5000
    off_m = off_s = 0
    wide = proto in COT16_VENDORS

    for asdu in master_asdus():
        body = widen_cot(asdu) if wide else asdu
        out.append((ts, nsim.ipv4_tcp("192.168.60.10", "192.168.60.20", 55000, port,
                                      isn_m + off_m, isn_s + off_s, 0x18, body,
                                      dst_mac="00:11:22:33:44:66")))
        off_m += len(body)
        ts += 0.02
    for asdu in protection_asdus():
        body = widen_cot(asdu) if wide else asdu
        out.append((ts, nsim.ipv4_tcp("192.168.60.20", "192.168.60.10", port, 55000,
                                      isn_s + off_s, isn_m + off_m, 0x18, body,
                                      dst_mac="00:11:22:33:44:55")))
        off_s += len(body)
        ts += 0.02
    return out


def build(proto: str) -> Tuple[Path, int]:
    kind, port, _display = VENDORS[proto]
    OUT.mkdir(parents=True, exist_ok=True)
    pcap = OUT / f"{proto}.pcap"
    if kind == "serial":
        records = serial_records(proto)
        c103.write_pcap(pcap, records)
        return pcap, len(records)
    records = net_records(proto, port)
    nsim.write_net_pcap(pcap, [(t, f, "") for t, f in records])
    return pcap, len(records)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vendor", default=None)
    args = ap.parse_args()

    names = [args.vendor] if args.vendor else sorted(VENDORS)
    for name in names:
        if name not in VENDORS:
            print(f"unknown vendor {name}")
            continue
        pcap, count = build(name)
        print(f"{pcap.name}  ({count} frames, {pcap.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
