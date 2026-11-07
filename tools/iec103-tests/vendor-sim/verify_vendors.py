# -*- coding: utf-8 -*-
"""验证 103 家族补充厂家解析器（依据 PROTOCOL 参考实现）。

断言（每家）：
  1. 中性性：不加 Decode As / 不设 payload dissector 时解析不出该协议
  2. 选择后过滤器命中，ASDU 类型覆盖
  3. 关键字段非空
  4. 无 Malformed

用法
    python verify_vendors.py [--tshark PATH]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import List, Sequence

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[2]
BUNDLE_ROOT = SRC_ROOT.parents[1]
OUT = HERE / "out"

DEFAULT_TSHARK = (BUNDLE_ROOT / "06-build" / "wsbuild-industrial" / "run" /
                  "RelWithDebInfo" / "tshark.exe")

# 协议短名 -> (承载, 端口)
CASES = {
    "nr103_serial_iec103": ("serial", 0),
    "nr103_rcs9691_serial_iec103": ("serial", 0),
    "xj103_com_serial_iec103": ("serial", 0),
    "xj_com103_serial_iec103": ("serial", 0),
    "nz103ii_serial_iec103": ("serial", 0),
    "sf103_csc103a_serial_iec103": ("serial", 0),
    "xj_net103_wxh13": ("net", 2404),
    "sf_net103_tcp": ("net", 2404),
    "keli_103_tcp": ("net", 2404),
}

EXPECTED_ASDUS = [5, 6, 7, 8, 10, 2, 3, 23, 24, 25, 26, 27, 28, 29, 30, 31]

FAILURE = ("Aborting on fatal", "failed assertion", "Dissector bug",
           "Segmentation", "Access violation", "heap corruption", "double free")


def run(tshark: Path, args: Sequence[str]) -> str:
    proc = subprocess.run([str(tshark), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    return proc.stdout


def select_args(kind: str, proto: str, port: int) -> List[str]:
    if kind == "serial":
        return ["-o", f"serial_raw.payload_dissector:{proto}"]
    return ["-d", f"tcp.port=={port},{proto}"]


def check(tshark: Path, proto: str, kind: str, port: int) -> List[str]:
    pcap = OUT / f"{proto}.pcap"
    if not pcap.exists():
        return [f"missing pcap {pcap.name}"]

    problems: List[str] = []

    # 1. 中性性
    neutral = run(tshark, ["-r", str(pcap), "-Y", proto, "-T", "fields",
                           "-e", "frame.number"])
    if any(tok.strip() for tok in neutral.splitlines()):
        problems.append("capture decodes without selection (not neutral)")

    # 2. 命中与 ASDU 覆盖
    sel = select_args(kind, proto, port)
    frames = [f for f in run(tshark, ["-r", str(pcap), *sel, "-Y", proto,
                                      "-T", "fields", "-e", "frame.number"]).split()
              if f.strip()]
    if not frames:
        return problems + ["no frames decoded after selection"]

    types = set()
    for line in run(tshark, ["-r", str(pcap), *sel, "-Y", proto, "-T", "fields",
                             "-e", f"{proto}.typeid"]).splitlines():
        for tok in line.split(","):
            if tok.strip().isdigit():
                types.add(int(tok))
    missing = [t for t in EXPECTED_ASDUS if t not in types]
    if missing:
        problems.append(f"missing ASDU {missing}")

    # 3. 关键字段
    for fld in (f"{proto}.cot", f"{proto}.fun", f"{proto}.inf"):
        vals = [v for v in run(tshark, ["-r", str(pcap), *sel, "-Y", proto,
                                        "-T", "fields", "-e", fld]).splitlines()
                if v.strip()]
        if not vals:
            problems.append(f"field {fld} empty")

    # 4. 无 Malformed
    tree = run(tshark, ["-r", str(pcap), *sel, "-Y", proto, "-V"])
    for needle in ("Malformed",) + FAILURE:
        if needle.lower() in tree.lower():
            problems.append(f"'{needle}' found")

    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tshark", default=None)
    args = ap.parse_args()

    tshark = Path(args.tshark) if args.tshark else DEFAULT_TSHARK
    if not tshark.exists():
        raise SystemExit("tshark not found")

    print(f"tshark: {tshark}\n")
    failures = 0
    for proto, (kind, port) in CASES.items():
        problems = check(tshark, proto, kind, port)
        status = "PASS" if not problems else "FAIL"
        if problems:
            failures += 1
        print(f"[{status}] {proto}")
        for p in problems:
            print(f"        - {p}")

    print(f"\n{'ALL VENDOR CHECKS PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
