# -*- coding: utf-8 -*-
"""Live loopback test over a com0com virtual pair (real pyserial I/O).

The capture is deliberately protocol-neutral: every record is tagged
``serial_raw``. Dissection only happens when a dissector is selected, which the
script applies the same way the GUI does (serial_raw.payload_dissector).

Usage
    python tools/iec103-tests/run_serial_live.py --vendor sifang --master COM6 --peer COM7
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import List

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[1]              # 03-source/wireshark
BUNDLE_ROOT = SRC_ROOT.parents[1]       # Wireshark-Industrial-Bundle-0.10.3
sys.path.insert(0, str(SRC_ROOT / "tools" / "iec103-sim"))

import iec103_core as c103  # noqa: E402
import iec103_serial_sim as ssim  # noqa: E402

OUT = HERE / "out"
EXPECTED = {1, 2, 3, 5, 6, 7, 8, 10, 23, 24, 25, 26, 27, 28, 29, 30, 31}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vendor", choices=sorted(ssim.VENDORS), required=True)
    ap.add_argument("--master", default="COM6")
    ap.add_argument("--peer", default="COM7")
    ap.add_argument("--addr", type=lambda v: int(v, 0), default=0x03)
    ap.add_argument("--pcap", type=Path, default=None)
    ap.add_argument("--tshark", default=None)
    args = ap.parse_args()

    pcap = args.pcap or (OUT / f"{args.vendor}_serial_live.pcap")
    rc = ssim.run_pair(args.vendor, args.master, args.peer, args.addr, pcap, 60.0,
                       neutral=True)
    if rc != 0:
        return rc

    tshark = args.tshark or str(BUNDLE_ROOT / "06-build" / "wsbuild-industrial" /
                                "run" / "RelWithDebInfo" / "tshark.exe")
    proto = ssim.VENDORS[args.vendor]["dissector"]

    # Neutral check: the file must not decode as the vendor protocol on its own.
    neutral = subprocess.run([tshark, "-r", str(pcap), "-Y", proto, "-T", "fields",
                              "-e", "frame.number"], capture_output=True, text=True,
                             encoding="utf-8", errors="replace").stdout
    problems: List[str] = []
    if any(tok.strip() for tok in neutral.splitlines()):
        problems.append("capture is NOT neutral (protocol preset in file)")

    # Now select the dissector, as the 串口103 menu does.
    out = subprocess.run([tshark, "-r", str(pcap),
                          "-o", f"serial_raw.payload_dissector:{proto}",
                          "-Y", proto, "-T", "fields", "-e", f"{proto}.typeid"],
                         capture_output=True, text=True, encoding="utf-8",
                         errors="replace").stdout
    types = sorted({int(t) for line in out.splitlines() for t in line.split(",")
                    if t.strip().isdigit()})
    missing = EXPECTED - set(types)
    if missing:
        problems.append(f"missing ASDU {sorted(missing)}")

    print(f"live capture: {pcap}")
    print(f"decoded ASDU types after selection: {types}")
    if problems:
        for p in problems:
            print(f"FAIL: {p}")
        return 1
    print("SERIAL LIVE PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
