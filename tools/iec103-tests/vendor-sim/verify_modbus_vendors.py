# -*- coding: utf-8 -*-
"""厂家 Modbus 断言：中性性、命中、功能码覆盖、CRC 正确、无 Malformed。

用法
    python verify_modbus_vendors.py [--tshark PATH]
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
sys.path.insert(0, str(HERE))

import modbus_sim  # noqa: E402

OUT = HERE / "out"
DEFAULT_TSHARK = (BUNDLE_ROOT / "06-build" / "wsbuild-industrial" / "run" /
                  "RelWithDebInfo" / "tshark.exe")

EXPECTED_FNS = {0x03, 0x04, 0x10, 0x83}
FAILURE = ("Aborting on fatal", "failed assertion", "Dissector bug",
           "Segmentation", "Access violation", "heap corruption", "double free")


def run(tshark: Path, args: Sequence[str]) -> str:
    proc = subprocess.run([str(tshark), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    return proc.stdout


def select_args(short: str) -> List[str]:
    _display, kind = modbus_sim.VENDORS[short]
    if kind == "serial":
        return ["-o", f"serial_raw.payload_dissector:{short}"]
    return ["-d", f"tcp.port==502,{short}"]


def check(tshark: Path, short: str) -> List[str]:
    pcap = OUT / f"{short}.pcap"
    problems: List[str] = []
    if not pcap.exists():
        return [f"missing pcap {pcap.name}"]

    neutral = run(tshark, ["-r", str(pcap), "-Y", short, "-T", "fields",
                           "-e", "frame.number"])
    if any(t.strip() for t in neutral.splitlines()):
        problems.append("capture decodes without selection (not neutral)")

    sel = select_args(short)
    frames = [f for f in run(tshark, ["-r", str(pcap), *sel, "-Y", short, "-T",
                                      "fields", "-e", "frame.number"]).split() if f.strip()]
    if not frames:
        return problems + ["no frames decoded after selection"]

    fns = set()
    for line in run(tshark, ["-r", str(pcap), *sel, "-Y", short, "-T", "fields",
                             "-e", f"{short}.fn"]).splitlines():
        for tok in line.split(","):
            tok = tok.strip()
            if tok.lower().startswith("0x"):
                try:
                    fns.add(int(tok, 16))
                except ValueError:
                    pass
            elif tok.isdigit():
                fns.add(int(tok))
    missing = sorted(hex(f) for f in EXPECTED_FNS if f not in fns)
    if missing:
        problems.append(f"missing fn {missing}")

    for fld in (f"{short}.unit",):
        vals = [v for v in run(tshark, ["-r", str(pcap), *sel, "-Y", short,
                                        "-T", "fields", "-e", fld]).splitlines() if v.strip()]
        if not vals:
            problems.append(f"field {fld} empty")

    # RTU 承载要检查 CRC 字段与校验通过；TCP 承载没有 CRC 字段
    if modbus_sim.VENDORS[short][1] == "serial":
        vals = [v for v in run(tshark, ["-r", str(pcap), *sel, "-Y", short,
                                        "-T", "fields", "-e", f"{short}.crc"]).splitlines()
                if v.strip()]
        if not vals:
            problems.append(f"field {short}.crc empty")
        bad = run(tshark, ["-r", str(pcap), *sel, "-Y",
                           f"{short}.crc.ok == 0", "-T", "fields", "-e", "frame.number"])
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

    failures = 0
    for short in sorted(modbus_sim.VENDORS):
        modbus_sim.build(short)
        problems = check(tshark, short)
        print(f"[{'PASS' if not problems else 'FAIL'}] {short}")
        for p in problems:
            print(f"        - {p}")
        if problems:
            failures += 1

    print(f"\n{'ALL MODBUS VENDOR CHECKS PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
