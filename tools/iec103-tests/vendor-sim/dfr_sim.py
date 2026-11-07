# -*- coding: utf-8 -*-
"""录波器 68 帧模拟器：按 dfr-spec.json 生成保护侧 + 主站报文。

帧结构（来自 PROTOCOL/<dir>/DFR.cpp）：
    68 | 地址 | 命令 | 应答 | 密码(2) | 总长(4,LE,含 10 字节头) | 主体

用法
    python dfr_sim.py --vendor nfdfr
    python dfr_sim.py --all
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[2]
sys.path.insert(0, str(SRC_ROOT / "tools" / "iec103-sim"))

import iec103_core as c103  # noqa: E402

SPEC = SRC_ROOT / "tools" / "protocol-audit" / "dfr-spec.json"
OUT = HERE / "out"

ADDR = 0x05
START = 0x68
HDR = 10

CMD_WORKSTATUS = 0x80
CMD_SEARCHFILE = 0x81
CMD_DOWNLOADFILE = 0x82
CMD_REQUESTDATA = 0x84
CMD_CONTROL = 0x85
CMD_RESETCOMM = 0x86
CMD_TIMESYNC = 0x87

ANSWER_OK = 0x00


def load_spec() -> List[Dict]:
    return json.loads(SPEC.read_text(encoding="utf-8"))["vendors"]


def frame(cmd: int, body: bytes, addr: int = ADDR, answer: int = ANSWER_OK,
          passwd: int = 0) -> bytes:
    """组装一条 68 帧；总长字段含 10 字节头。"""
    total = HDR + len(body)
    head = bytes((START, addr & 0xFF, cmd & 0xFF, answer & 0xFF,
                  passwd & 0xFF, (passwd >> 8) & 0xFF))
    return head + struct.pack("<I", total) + body


def bcd(value: int) -> int:
    return ((value // 10) << 4) | (value % 10)


def master_frames(addr: int = ADDR) -> List[bytes]:
    """主站下发：状态查询、检索、下载请求、对时、复位。"""
    now = datetime(2024, 6, 1, 12, 30, 15)
    return [
        # 查询工作状态
        frame(CMD_WORKSTATUS, b"", addr),
        # 检索指定时间段的录波文件目录
        frame(CMD_SEARCHFILE,
              struct.pack("<HHBBBBHHBBBB", 2024, 2024, 1, 1, 0, 0, 2024, 2024, 12, 31, 23, 59)
              + b"??F\x00\x00", addr),
        # 请求下载文件
        frame(CMD_DOWNLOADFILE, struct.pack("<I", 0), addr),
        # 请求实时数据
        frame(CMD_REQUESTDATA, b"", addr),
        # 启动录波
        frame(CMD_CONTROL, b"", addr),
        # 对时（BCD 年月日时分秒）
        frame(CMD_TIMESYNC,
              bytes((bcd(now.year % 100), bcd(now.year // 100), bcd(now.month),
                     bcd(now.day), bcd(now.hour), bcd(now.minute),
                     bcd(now.second), 0, 0)), addr),
        # 复位通信
        frame(CMD_RESETCOMM, b"", addr),
    ]


def slave_frames(addr: int = ADDR) -> List[bytes]:
    """装置应答：各命令的成功应答，含一个文件目录条目。"""
    name = b"REC20240601123015.CFG\x00\x00\x00\x00\x00\x00\x00\x00"
    name = name[:28].ljust(28, b"\x00")
    return [
        frame(CMD_WORKSTATUS, b"\x01\x00\x00\x00", addr),
        # 检索应答：文件长度(4) + 文件名(28) + 类型 + 故障标志
        frame(CMD_SEARCHFILE, struct.pack("<I", 65536) + name + b"\x01\x01", addr),
        frame(CMD_SEARCHFILE, struct.pack("<I", 131072) + name + b"\x02\x00", addr),
        # 下载应答：偏移 + 一块数据
        frame(CMD_DOWNLOADFILE, struct.pack("<I", 0) + bytes(range(64)), addr),
        frame(CMD_REQUESTDATA, b"\x00\x00\x01\x02\x03\x04", addr),
        frame(CMD_CONTROL, b"\x01", addr),
        frame(CMD_TIMESYNC, b"\x01", addr),
        frame(CMD_RESETCOMM, b"\x01", addr),
        # 失败应答，覆盖否定路径
        frame(CMD_WORKSTATUS, b"", addr, answer=0x01),
    ]


def build_records(vendor: Dict) -> List[Tuple[float, bytes, str]]:
    addr = ADDR
    ts = 1_700_000_000.0
    out: List[Tuple[float, bytes, str]] = []
    serial = vendor["transport"] != "tcp_udp"

    for f in master_frames(addr):
        out.append((ts, f, "serial_raw" if serial else ""))
        ts += 0.05
    for f in slave_frames(addr):
        out.append((ts, f, "serial_raw" if serial else ""))
        ts += 0.05
    return out


def write_pcap(vendor: Dict) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    short = vendor["short"]
    records = build_records(vendor)
    path = OUT / f"{short}.pcap"
    if vendor["transport"] == "tcp_udp":
        import iec103_net_sim as nsim
        # 前一半走 TCP，后一半走 UDP，覆盖两个承接入口
        frames = []
        half = len(records) // 2
        ts = 1_700_000_000.0
        isn_m, isn_s = 2000, 6000
        off_m = off_s = 0
        for i, (_t, payload, _tag) in enumerate(records):
            if i < half:
                frames.append((ts, nsim.ipv4_tcp("192.168.90.10", "192.168.90.20",
                                                 51000, 7000, isn_m + off_m,
                                                 isn_s + off_s, 0x18, payload,
                                                 dst_mac="00:11:22:33:44:66")))
                off_m += len(payload)
            else:
                frames.append((ts, nsim.ipv4_udp("192.168.90.20", "192.168.90.10",
                                                 7000, 51000, payload,
                                                 dst_mac="00:11:22:33:44:55")))
            ts += 0.05
        nsim.write_net_pcap(path, [(t, f, "") for t, f in frames])
    else:
        c103.write_pcap(path, records)
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

    for vendor in vendors:
        path = write_pcap(vendor)
        print(f"{path.name}  ({path.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
