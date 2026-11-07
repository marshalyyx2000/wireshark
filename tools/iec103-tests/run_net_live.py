# -*- coding: utf-8 -*-
"""Live loopback test for the network 103 variants.

sifang:    UDP 1888/1889 on 127.0.0.1
nrelectric: TCP 1048 + UDP 1032 on 127.0.0.1

Traffic is captured with dumpcap on the loopback interface when available,
otherwise the simulator falls back to a synthetic pcap from the same bytes.

Usage
    python tools/iec103-tests/run_net_live.py --vendor sifang
    python tools/iec103-tests/run_net_live.py --vendor nrelectric
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import List

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[1]
BUNDLE_ROOT = SRC_ROOT.parents[1]
sys.path.insert(0, str(SRC_ROOT / "tools" / "iec103-sim"))

import iec103_net_sim as nsim  # noqa: E402

OUT = HERE / "out"
EXPECTED = {
    "sifang": {5, 1, 2, 3, 10, 23, 24, 25, 26, 27, 28, 29, 30, 31},
    "nrelectric": {5, 6, 7, 8, 1, 2, 3, 10, 23, 24, 25, 26, 27, 28, 29, 30, 31},
}
PROTO = {
    "sifang": "sifang_net_iec103",
    "nrelectric": "nrelectric_net_iec103",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vendor", choices=sorted(EXPECTED), required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--pcap", type=Path, default=None)
    ap.add_argument("--tshark", default=None)
    args = ap.parse_args()

    pcap = args.pcap or (OUT / f"{args.vendor}_net_live.pcap")
    if args.vendor == "sifang":
        nsim.run_sifang(args.host, pcap, 10.0, emit_only=True)
    else:
        nsim.run_nrelectric(args.host, pcap, 10.0, emit_only=True)

    tshark = args.tshark or str(BUNDLE_ROOT / "06-build" / "wsbuild-industrial" /
                                "run" / "RelWithDebInfo" / "tshark.exe")
    proto = PROTO[args.vendor]
    udp = args.vendor == "sifang"
    ports = (1888, 1889) if udp else (1048,)
    select: List[str] = []
    for port in ports:
        table = "udp.port" if udp else "tcp.port"
        select += ["-d", f"{table}=={port},{proto}"]

    # Neutral check: without Decode As the vendor protocol must not appear.
    neutral = subprocess.run([tshark, "-r", str(pcap), "-Y", proto, "-T", "fields",
                              "-e", "frame.number"], capture_output=True, text=True,
                             encoding="utf-8", errors="replace").stdout
    problems: List[str] = []
    if any(tok.strip() for tok in neutral.splitlines()):
        problems.append("capture is NOT neutral (protocol preset in file)")

    out = subprocess.run([tshark, "-r", str(pcap), *select, "-Y", proto, "-T", "fields",
                          "-e", f"{proto}.typeid"], capture_output=True, text=True,
                         encoding="utf-8", errors="replace").stdout
    types = sorted({int(t) for line in out.splitlines() for t in line.split(",")
                    if t.strip().isdigit()})
    print(f"live capture: {pcap}")
    print(f"decoded ASDU types after selection: {types}")
    missing = EXPECTED[args.vendor] - set(types)
    if missing:
        problems.append(f"missing ASDU {sorted(missing)}")
    if problems:
        for p in problems:
            print(f"FAIL: {p}")
        return 1
    print("NET LIVE PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
