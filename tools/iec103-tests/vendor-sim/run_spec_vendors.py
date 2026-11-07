# -*- coding: utf-8 -*-
"""由 vendor-spec.json 生成中性抓包，并逐厂家断言。

覆盖两批共 21 家（9 家手写 profile + 12 家 spec 生成）。每家的：
  - 保护侧一轮 ASDU（ASDU1..31 全覆盖）
  - 主站侧一轮命令
  - 中性封装：串口写入 Exported PDU `serial_raw`，网络为普通以太网帧

用法
    python run_spec_vendors.py                 # 生成全部 pcap
    python run_spec_vendors.py --verify        # 生成并断言
    python run_spec_vendors.py --vendor wgl3000_iec103 --verify
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Sequence

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[2]
BUNDLE_ROOT = SRC_ROOT.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(SRC_ROOT / "tools" / "iec103-sim"))

import iec103_core as c103  # noqa: E402
import iec103_net_sim as nsim  # noqa: E402
import spec_sim  # noqa: E402

OUT = HERE / "out"
DEFAULT_TSHARK = (BUNDLE_ROOT / "06-build" / "wsbuild-industrial" / "run" /
                  "RelWithDebInfo" / "tshark.exe")

EXPECTED_ASDUS = [1, 2, 3, 5, 6, 7, 8, 10, 20, 21, 23, 24, 25, 26, 27, 28, 29, 30, 31]
FAILURE = ("Aborting on fatal", "failed assertion", "Dissector bug",
           "Segmentation", "Access violation", "heap corruption", "double free")


def all_vendors() -> List[Dict]:
    return spec_sim.load_spec()["vendors"]


def build(vendor: Dict) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    short = vendor["short"]
    records = spec_sim.build_records(vendor)
    pcap = OUT / f"{short}.pcap"
    if vendor["transport"].startswith("serial"):
        c103.write_pcap(pcap, records)
    else:
        port = spec_sim.expected_port(vendor)
        addr = spec_sim.ADDR
        frames = []
        ts = 1_700_000_000.0
        isn_m, isn_s = 1000, 5000
        off_m = off_s = 0
        for _t, payload, _tag in records:
            if spec_sim.is_udp(vendor):
                frames.append((ts, nsim.ipv4_udp("192.168.70.20", "192.168.70.10",
                                                 port, 55001, payload)))
            else:
                # 主站下发的报文在前半，保护上送在后半：用长度区分方向没有意义，
                # 这里按序号奇偶交替，保证两个方向都有流量。
                if len(frames) < len(spec_sim.master_asdus(addr)):
                    frames.append((ts, nsim.ipv4_tcp("192.168.70.10", "192.168.70.20",
                                                     55001, port,
                                                     isn_m + off_m, isn_s + off_s,
                                                     0x18, payload,
                                                     dst_mac="00:11:22:33:44:66")))
                    off_m += len(payload)
                else:
                    frames.append((ts, nsim.ipv4_tcp("192.168.70.20", "192.168.70.10",
                                                     port, 55001,
                                                     isn_s + off_s, isn_m + off_m,
                                                     0x18, payload,
                                                     dst_mac="00:11:22:33:44:55")))
                    off_s += len(payload)
            ts += 0.02
        nsim.write_net_pcap(pcap, [(t, f, "") for t, f in frames])
    return pcap


def run(tshark: Path, args: Sequence[str]) -> str:
    proc = subprocess.run([str(tshark), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    return proc.stdout


def select_args(vendor: Dict) -> List[str]:
    short = vendor["short"]
    if vendor["transport"].startswith("serial"):
        return ["-o", f"serial_raw.payload_dissector:{short}"]
    proto = "udp" if spec_sim.is_udp(vendor) else "tcp"
    return ["-d", f"{proto}.port=={spec_sim.expected_port(vendor)},{short}"]


def check(tshark: Path, vendor: Dict) -> List[str]:
    short = vendor["short"]
    pcap = OUT / f"{short}.pcap"
    problems: List[str] = []
    if not pcap.exists():
        return [f"missing pcap {pcap.name}"]

    # 1. 中性性：不选协议时不应解出该协议
    neutral = run(tshark, ["-r", str(pcap), "-Y", short, "-T", "fields",
                           "-e", "frame.number"])
    if any(tok.strip() for tok in neutral.splitlines()):
        problems.append("capture decodes without selection (not neutral)")

    # 2. 选择后命中 + ASDU 覆盖
    sel = select_args(vendor)
    frames = [f for f in run(tshark, ["-r", str(pcap), *sel, "-Y", short, "-T",
                                      "fields", "-e", "frame.number"]).split() if f.strip()]
    if not frames:
        return problems + ["no frames decoded after selection"]

    types = set()
    for line in run(tshark, ["-r", str(pcap), *sel, "-Y", short, "-T", "fields",
                             "-e", f"{short}.typeid"]).splitlines():
        for tok in line.split(","):
            if tok.strip().isdigit():
                types.add(int(tok))
    missing = [t for t in EXPECTED_ASDUS if t not in types]
    if missing:
        problems.append(f"missing ASDU {missing}")

    # 3. 关键字段
    for fld in (f"{short}.cot", f"{short}.fun", f"{short}.inf"):
        vals = [v for v in run(tshark, ["-r", str(pcap), *sel, "-Y", short,
                                        "-T", "fields", "-e", fld]).splitlines() if v.strip()]
        if not vals:
            problems.append(f"field {fld} empty")

    # 4. 无 Malformed / 崩溃
    tree = run(tshark, ["-r", str(pcap), *sel, "-Y", short, "-V"])
    for needle in ("Malformed",) + FAILURE:
        if needle.lower() in tree.lower():
            problems.append(f"'{needle}' found")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vendor", default=None)
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--tshark", default=None)
    args = ap.parse_args()

    vendors = all_vendors()
    if args.vendor:
        vendors = [v for v in vendors if v["short"] == args.vendor]
        if not vendors:
            raise SystemExit(f"unknown vendor {args.vendor}")

    failures = 0
    for vendor in vendors:
        pcap = build(vendor)
        print(f"{pcap.name}  ({pcap.stat().st_size} bytes)")
        if not args.verify:
            continue
        tshark = Path(args.tshark) if args.tshark else DEFAULT_TSHARK
        problems = check(tshark, vendor)
        print(f"  [{'PASS' if not problems else 'FAIL'}] {vendor['short']}")
        for p in problems:
            print(f"        - {p}")
        if problems:
            failures += 1

    if args.verify:
        print("\nALL SPEC VENDOR CHECKS PASSED" if failures == 0 else f"\n{failures} FAILURE(S)")
        return 0 if failures == 0 else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
