# -*- coding: utf-8 -*-
"""声明式帧厂家断言：中性性、命中、地址/命令字段、校验通过、无 Malformed。

用法
    python verify_generic_vendors.py [--tshark PATH]
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

import generic_sim  # noqa: E402

SPEC = SRC_ROOT / "tools" / "protocol-audit" / "generic-spec.json"
OUT = HERE / "out"
DEFAULT_TSHARK = (BUNDLE_ROOT / "06-build" / "wsbuild-industrial" / "run" /
                  "RelWithDebInfo" / "tshark.exe")

FAILURE = ("Aborting on fatal", "failed assertion", "Dissector bug",
           "Segmentation", "Access violation", "heap corruption", "double free")


def run(tshark: Path, args: Sequence[str]) -> str:
    proc = subprocess.run([str(tshark), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    return proc.stdout


def select_args(v: Dict) -> List[str]:
    short = v["short"]
    if v["carrier"] == "serial":
        return ["-o", f"serial_raw.payload_dissector:{short}"]
    proto = v["carrier"]   # tcp / udp
    return ["-d", f"{proto}.port==7001,{short}"]


def check(tshark: Path, v: Dict) -> List[str]:
    short = v["short"]
    pcap = OUT / f"{short}.pcap"
    problems: List[str] = []
    if not pcap.exists():
        return [f"missing pcap {pcap.name}"]

    neutral = run(tshark, ["-r", str(pcap), "-Y", short, "-T", "fields",
                           "-e", "frame.number"])
    if any(t.strip() for t in neutral.splitlines()):
        problems.append("capture decodes without selection (not neutral)")

    sel = select_args(v)
    frames = [f for f in run(tshark, ["-r", str(pcap), *sel, "-Y", short, "-T",
                                      "fields", "-e", "frame.number"]).split() if f.strip()]
    if not frames:
        return problems + ["no frames decoded after selection"]

    if v["addr_off"] >= 0:
        vals = [x for x in run(tshark, ["-r", str(pcap), *sel, "-Y", short, "-T",
                                        "fields", "-e", f"{short}.addr"]).splitlines()
                if x.strip()]
        if not vals:
            problems.append(f"field {short}.addr empty")

    if v["cmd_off"] >= 0:
        vals = [x for x in run(tshark, ["-r", str(pcap), *sel, "-Y", short, "-T",
                                        "fields", "-e", f"{short}.cmd"]).splitlines()
                if x.strip()]
        if not vals:
            problems.append(f"field {short}.cmd empty")

    if v["crc"] != "none":
        bad = run(tshark, ["-r", str(pcap), *sel, "-Y", f"{short}.crc.ok == 0",
                           "-T", "fields", "-e", "frame.number"])
        if any(t.strip() for t in bad.splitlines()):
            problems.append("CRC check failed on some frames")

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
    for v in vendors:
        generic_sim.write_pcap(v)
        problems = check(tshark, v)
        print(f"[{'PASS' if not problems else 'FAIL'}] {v['short']}")
        for p in problems:
            print(f"        - {p}")
        if problems:
            failures += 1

    print(f"\n{'ALL GENERIC VENDOR CHECKS PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
