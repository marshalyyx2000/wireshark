# -*- coding: utf-8 -*-
"""Stress the try-decode paths that the GUI menus trigger.

Every case is exercised the way the GUI does it:
  serial : serial_raw payload is handed to a vendor dissector
  network: Decode As is applied on the documented ports

The script repeats each selection several times (menus can be clicked repeatedly),
switches between vendors on the same file (wrong choice then right choice), and
checks for crashes, assertion failures and leaks reported by tshark.

Usage
    python tools/iec103-tests/stress_trydecode.py [--tshark PATH] [--repeat N]
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Sequence, Tuple

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUNDLE_ROOT = ROOT.parents[1]
OUT = HERE / "out"

SERIAL_VENDORS = ["sifang_serial_iec103", "sznari_serial_iec103",
                  "nari_serial_iec103", "xuji_serial_iec103"]
SERIAL_PCAPS = ["sifang_serial.pcap", "sznari_serial.pcap"]

NET_CASES: List[Tuple[str, str, bool, Sequence[int]]] = [
    ("sifang_net.pcap", "sifang_net_iec103", True, (1888, 1889)),
    ("nrelectric_net.pcap", "nrelectric_net_iec103", False, (1048,)),
]

FAILURE_PATTERNS = re.compile(
    r"(Aborting on fatal|failed assertion|Dissector bug|"
    r"unhandled_catcher|Segmentation|Access violation|"
    r"double free|Invalid address|heap corruption)",
    re.IGNORECASE,
)


def find_tshark(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)
    for cand in (BUNDLE_ROOT / "06-build" / "wsbuild-industrial" / "run" /
                 "RelWithDebInfo" / "tshark.exe", Path(r"C:\Program Files\Wireshark\tshark.exe")):
        if cand.exists():
            return cand
    raise SystemExit("tshark not found; pass --tshark")


def run(tshark: Path, args: Sequence[str]) -> Tuple[int, str]:
    proc = subprocess.run([str(tshark), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    return proc.returncode, proc.stdout + proc.stderr


def check(label: str, tshark: Path, args: Sequence[str]) -> List[str]:
    rc, out = run(tshark, args)
    problems: List[str] = []
    if rc not in (0, 1, 2):          # 2 = tshark error code, not a crash
        problems.append(f"exit code {rc}")
    if FAILURE_PATTERNS.search(out):
        hit = FAILURE_PATTERNS.search(out)
        problems.append(f"failure text: {hit.group(0) if hit else '?'}")
    if "LeakSanitizer" in out or "definitely lost" in out:
        problems.append("memory leak report")
    status = "PASS" if not problems else "FAIL"
    print(f"[{status}] {label}")
    for p in problems:
        print(f"        - {p}")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tshark", default=None)
    ap.add_argument("--repeat", type=int, default=3)
    args = ap.parse_args()

    tshark = find_tshark(args.tshark)
    print(f"tshark: {tshark}\n")
    failures = 0

    # ---- serial: one payload dissector per run, repeated -------------------
    for pcap_name in SERIAL_PCAPS:
        pcap = OUT / pcap_name
        if not pcap.exists():
            print(f"[SKIP] {pcap_name} missing")
            continue
        for vendor in SERIAL_VENDORS:
            for i in range(args.repeat):
                failures += len(check(
                    f"{pcap_name} + {vendor} (pass {i + 1})", tshark,
                    ["-r", str(pcap),
                     "-o", f"serial_raw.payload_dissector:{vendor}",
                     "-Y", vendor, "-T", "fields", "-e", f"{vendor}.typeid"]))

    # ---- serial: wrong vendor first, then the right one -------------------
    for pcap_name, good in (("sifang_serial.pcap", "sifang_serial_iec103"),
                            ("sznari_serial.pcap", "sznari_serial_iec103")):
        pcap = OUT / pcap_name
        if not pcap.exists():
            continue
        wrong = next(v for v in SERIAL_VENDORS if v != good)
        failures += len(check(f"{pcap_name} wrong vendor {wrong} then {good}", tshark,
                              ["-r", str(pcap), "-2",
                               "-o", f"serial_raw.payload_dissector:{wrong}",
                               "-o", f"serial_raw.payload_dissector:{good}",
                               "-Y", good, "-T", "fields", "-e", f"{good}.typeid"]))

    # ---- network: Decode As on every documented port ---------------------
    for pcap_name, proto, udp, ports in NET_CASES:
        pcap = OUT / pcap_name
        if not pcap.exists():
            print(f"[SKIP] {pcap_name} missing")
            continue
        table = "udp.port" if udp else "tcp.port"
        select: List[str] = []
        for port in ports:
            select += ["-d", f"{table}=={port},{proto}"]
        for i in range(args.repeat):
            failures += len(check(f"{pcap_name} Decode-As {proto} (pass {i + 1})", tshark,
                                  ["-r", str(pcap), *select, "-Y", proto, "-T", "fields",
                                   "-e", f"{proto}.typeid"]))
        # two-pass dissection is what the GUI does when it re-dissects
        failures += len(check(f"{pcap_name} two-pass", tshark,
                              ["-r", str(pcap), *select, "-2", "-Y", proto, "-T", "fields",
                               "-e", f"{proto}.typeid"]))

    # ---- the exact GUI path: neutral first, then decode ------------------
    for pcap_name, proto in (("sznari_serial.pcap", "sznari_serial_iec103"),
                             ("sifang_serial.pcap", "sifang_serial_iec103")):
        pcap = OUT / pcap_name
        if not pcap.exists():
            continue
        failures += len(check(f"{pcap_name} neutral must not decode", tshark,
                              ["-r", str(pcap), "-Y", proto, "-T", "fields",
                               "-e", "frame.number"]))
        failures += len(check(f"{pcap_name} after menu selection", tshark,
                              ["-r", str(pcap), "-2",
                               "-o", f"serial_raw.payload_dissector:{proto}",
                               "-V"]))

    print(f"\n{'ALL STRESS CASES PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
