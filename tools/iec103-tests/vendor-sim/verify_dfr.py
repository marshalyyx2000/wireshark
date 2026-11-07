# -*- coding: utf-8 -*-
"""录波器 68 帧家族断言：中性性、命中、字段非空、无 Malformed。

用法
    python verify_dfr.py [--tshark PATH]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Sequence

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[2]
BUNDLE_ROOT = SRC_ROOT.parents[1]
sys.path.insert(0, str(HERE))

import dfr_sim  # noqa: E402

SPEC = SRC_ROOT / "tools" / "protocol-audit" / "dfr-spec.json"
OUT = HERE / "out"
DEFAULT_TSHARK = (BUNDLE_ROOT / "06-build" / "wsbuild-industrial" / "run" /
                  "RelWithDebInfo" / "tshark.exe")

EXPECTED_CMDS = [0x80, 0x81, 0x82, 0x84, 0x85, 0x86, 0x87]
FAILURE = ("Aborting on fatal", "failed assertion", "Dissector bug",
           "Segmentation", "Access violation", "heap corruption", "double free")


def run(tshark: Path, args: Sequence[str]) -> str:
    proc = subprocess.run([str(tshark), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    return proc.stdout


def select_args(vendor: Dict) -> List[str]:
    short = vendor["short"]
    if vendor["transport"] == "tcp_udp":
        return ["-d", f"tcp.port==7000,{short}", "-d", f"udp.port==7000,{short}"]
    return ["-o", f"serial_raw.payload_dissector:{short}"]


def check(tshark: Path, vendor: Dict) -> List[str]:
    short = vendor["short"]
    pcap = OUT / f"{short}.pcap"
    problems: List[str] = []
    if not pcap.exists():
        problems.append(f"missing pcap {pcap.name}")
        return problems

    # 1. 中性性
    neutral = run(tshark, ["-r", str(pcap), "-Y", short, "-T", "fields",
                           "-e", "frame.number"])
    if any(t.strip() for t in neutral.splitlines()):
        problems.append("capture decodes without selection (not neutral)")

    # 2. 命中 + 命令码覆盖
    sel = select_args(vendor)
    frames = [f for f in run(tshark, ["-r", str(pcap), *sel, "-Y", short,
                                      "-T", "fields", "-e", "frame.number"]).split()
              if f.strip()]
    if not frames:
        return problems + ["no frames decoded after selection"]

    cmds = set()
    for line in run(tshark, ["-r", str(pcap), *sel, "-Y", short, "-T", "fields",
                             "-e", f"{short}.cmd"]).splitlines():
        for tok in line.split(","):
            tok = tok.strip()
            if tok.isdigit():
                cmds.add(int(tok))
            elif tok.lower().startswith("0x"):
                try:
                    cmds.add(int(tok, 16))
                except ValueError:
                    pass
    missing = [hex(c) for c in EXPECTED_CMDS if c not in cmds]
    if missing:
        problems.append(f"missing cmd {missing}")

    # 3. 关键字段
    for fld in (f"{short}.addr", f"{short}.answer", f"{short}.total_len"):
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
    ap.add_argument("--tshark", default=None)
    args = ap.parse_args()

    tshark = Path(args.tshark) if args.tshark else DEFAULT_TSHARK
    if not tshark.exists():
        raise SystemExit("tshark not found")

    vendors = json.loads(SPEC.read_text(encoding="utf-8"))["vendors"]
    failures = 0
    for vendor in vendors:
        failures += 0  # keep loop shape explicit
        dfr_sim.write_pcap(vendor)
        problems = check(tshark, vendor)
        print(f"[{'PASS' if not problems else 'FAIL'}] {vendor['short']}")
        for p in problems:
            print(f"        - {p}")
        if problems:
            failures += 1

    print(f"\n{'ALL DFR CHECKS PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
