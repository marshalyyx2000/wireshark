# -*- coding: utf-8 -*-
"""Verify the 103 dissectors against protocol-neutral reference pcaps.

The pcaps deliberately carry NO protocol hint (serial_raw for serial, plain
Ethernet/IP/UDP/TCP for network). Dissection only happens when a dissector is
selected, exactly like clicking 串口103 / 网络103 in the GUI. The script applies
the same selection via tshark options:

  serial : -o serial_raw.payload_dissector:<proto>
  network: -d tcp.port==<port>,<proto> / -d udp.port==<port>,<proto>

Checks per vendor/link:
  1. neutral capture really is neutral (no 103 protocol without selection)
  2. after selection the filter matches and expected ASDU types appear
  3. key fields are populated (COT / FUN / INF, DPI, CP56Time2a)
  4. point-table names show up in the verbose tree
  5. no "malformed" escapes

Usage
    python tools/iec103-tests/verify.py [--tshark PATH] [--pcap-dir DIR]
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUNDLE_ROOT = ROOT.parents[1]

DEFAULT_TSHARK_CANDIDATES = [
    BUNDLE_ROOT / "06-build" / "wsbuild-industrial" / "run" / "RelWithDebInfo" / "tshark.exe",
    Path(r"C:\Program Files\Wireshark\tshark.exe"),
]


@dataclass
class Case:
    name: str
    pcap: str
    proto: str
    select_args: Sequence[str]          # tshark options that select the dissector
    expected_asdus: Sequence[int]
    expect_point_names: Sequence[str] = ()
    expect_fields: Sequence[str] = ()


SERIAL_ASDUS = (1, 2, 3, 5, 6, 7, 8, 10, 23, 24, 25, 26, 27, 28, 29, 30, 31)
NET_ASDUS = (5, 1, 2, 3, 10, 23, 24, 25, 26, 27, 28, 29, 30, 31)


def _serial(proto: str) -> List[str]:
    return ["-o", f"serial_raw.payload_dissector:{proto}"]


def _net(proto: str, ports: Sequence[int], udp: bool) -> List[str]:
    args: List[str] = []
    table = "udp.port" if udp else "tcp.port"
    for port in ports:
        args += ["-d", f"{table}=={port},{proto}"]
    return args


CASES = [
    Case("四方串口103", "sifang_serial.pcap", "sifang_serial_iec103",
         _serial("sifang_serial_iec103"), SERIAL_ASDUS,
         ("距离I段动作", "过流I段动作", "定值组"),
         ("sifang_serial_iec103.ctrl.func", "sifang_serial_iec103.cp56time",
          "sifang_serial_iec103.dpi")),
    Case("深圳南瑞串口103", "sznari_serial.pcap", "sznari_serial_iec103",
         _serial("sznari_serial_iec103"), SERIAL_ASDUS,
         ("距离I段动作", "过流I段动作"),
         ("sznari_serial_iec103.ctrl.func", "sznari_serial_iec103.cp56time")),
    Case("四方网络103", "sifang_net.pcap", "sifang_net_iec103",
         _net("sifang_net_iec103", (1888, 1889), True), NET_ASDUS,
         ("距离I段动作", "过流I段动作"),
         ("sifang_net_iec103.cot", "sifang_net_iec103.fun")),
    Case("南瑞网络103", "nrelectric_net.pcap", "nrelectric_net_iec103",
         _net("nrelectric_net_iec103", (1048,), False), SERIAL_ASDUS,
         ("距离I段动作", "线路差动动作", "差动速断动作"),
         ("nrelectric_net_iec103.cot", "nrelectric_net_iec103.fun")),
]

EXISTING_CASES = [
    ("南自网络103(回归)", "nari_net_iec103"),
    ("许继串口103(回归)", "xuji_serial_iec103"),
    ("深圳南瑞网络103(回归)", "sznari_net_iec103"),
]


def find_tshark(explicit: Optional[str]) -> Path:
    if explicit:
        return Path(explicit)
    for cand in DEFAULT_TSHARK_CANDIDATES:
        if cand.exists():
            return cand
    raise SystemExit("tshark not found; pass --tshark")


def run(tshark: Path, args: Sequence[str]) -> str:
    proc = subprocess.run([str(tshark), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    return proc.stdout + proc.stderr


def run_stdout(tshark: Path, args: Sequence[str]) -> str:
    """stdout only: tshark writes dissector-registration notices to stderr."""
    proc = subprocess.run([str(tshark), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    return proc.stdout


def check_case(tshark: Path, case: Case, pcap_dir: Path) -> List[str]:
    problems: List[str] = []
    pcap = pcap_dir / case.pcap
    if not pcap.exists():
        return [f"missing pcap {pcap}"]

    # 1. The capture must be neutral: without selection the vendor protocol
    #    must not appear at all.
    neutral = run_stdout(tshark, ["-r", str(pcap), "-Y", case.proto, "-T", "fields",
                                  "-e", "frame.number"])
    if any(tok.strip() for tok in neutral.splitlines()):
        problems.append("capture is NOT neutral (protocol preset in file)")

    # 2. After selecting the dissector the protocol must match frames.
    frames = [f for f in run_stdout(tshark, ["-r", str(pcap), *case.select_args, "-Y",
                                             case.proto, "-T", "fields",
                                             "-e", "frame.number"]).split()
              if f.strip()]
    if not frames:
        return problems + [f"no frames matched after selecting '{case.proto}'"]

    # 3. ASDU coverage
    typeids = set()
    for line in run_stdout(tshark, ["-r", str(pcap), *case.select_args, "-Y", case.proto,
                                    "-T", "fields",
                                    "-e", f"{case.proto}.typeid"]).splitlines():
        for tok in line.split(","):
            if tok.strip().isdigit():
                typeids.add(int(tok))
    for typ in case.expected_asdus:
        if typ not in typeids:
            problems.append(f"ASDU{typ} missing")

    # 4. Key fields populated
    for fld in case.expect_fields:
        vals = [v for v in run_stdout(tshark, ["-r", str(pcap), *case.select_args, "-Y",
                                               case.proto, "-T", "fields",
                                               "-e", fld]).splitlines() if v.strip()]
        if not vals:
            problems.append(f"field {fld} empty")

    # 5. Point names from the vendor CSV
    tree = run_stdout(tshark, ["-r", str(pcap), *case.select_args, "-Y", case.proto, "-V"])
    for name in case.expect_point_names:
        if name not in tree:
            problems.append(f"point name '{name}' not shown")

    # 6. No malformed escapes
    if re.search(r"(?i)malformed", tree):
        problems.append("malformed packet found")

    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tshark", default=None)
    ap.add_argument("--pcap-dir", default=str(HERE / "out"))
    args = ap.parse_args()

    tshark = find_tshark(args.tshark)
    pcap_dir = Path(args.pcap_dir)
    print(f"tshark: {tshark}\n")

    failures = 0
    report: List[str] = []

    for case in CASES:
        problems = check_case(tshark, case, pcap_dir)
        status = "PASS" if not problems else "FAIL"
        if problems:
            failures += 1
        print(f"[{status}] {case.name}")
        for p in problems:
            print(f"       - {p}")
        report.append(f"| {case.name} | {status} | {'; '.join(problems) or '-'} |")

    print("\nRegression (protocol registration):")
    protocols = run(tshark, ["-G", "protocols"])
    for name, proto in EXISTING_CASES:
        ok = proto in protocols
        if not ok:
            failures += 1
        print(f"[{'PASS' if ok else 'FAIL'}] {name}")
        report.append(f"| {name} | {'PASS' if ok else 'FAIL'} | "
                      f"{'-' if ok else 'not registered'} |")

    print("\n=== REPORT.md rows ===")
    for row in report:
        print(row)

    print(f"\n{'ALL CHECKS PASSED' if failures == 0 else f'{failures} CASE(S) FAILED'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
