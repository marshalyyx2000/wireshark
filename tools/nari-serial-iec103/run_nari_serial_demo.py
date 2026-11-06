# -*- coding: utf-8 -*-
"""Run NARI serial protection + client on com0com pair and capture serial_raw pcap."""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_PCAP = ROOT / "captures" / "nari_serial_iec103.pcap"
DEFAULT_PCAP_DIRECT = ROOT / "captures" / "nari_serial_iec103_direct.pcap"
TSHARK = Path(r"C:\Development\wsbuild-industrial\run\RelWithDebInfo\tshark.exe")
WIRESHARK = Path(r"C:\Development\wsbuild-industrial\run\RelWithDebInfo\Wireshark.exe")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--client-port", default="COM10")
    ap.add_argument("--protection-port", default="COM11")
    ap.add_argument("--addr", default="0x0F")
    ap.add_argument("--pcap", type=Path, default=DEFAULT_PCAP)
    ap.add_argument("--open-ui", action="store_true")
    args = ap.parse_args()

    args.pcap.parent.mkdir(parents=True, exist_ok=True)
    direct = DEFAULT_PCAP_DIRECT

    prot = subprocess.Popen(
        [
            sys.executable,
            str(HERE / "nari_serial_protection.py"),
            "--port",
            args.protection_port,
            "--addr",
            args.addr,
            "--duration",
            "45",
        ],
        cwd=str(HERE),
    )
    time.sleep(0.8)
    try:
        # Client logs both directions into serial_raw pcap (UI try-decode)
        rc = subprocess.call(
            [
                sys.executable,
                str(HERE / "nari_serial_client.py"),
                "--port",
                args.client_port,
                "--addr",
                args.addr,
                "--pcap",
                str(args.pcap),
                "--pcap-proto",
                "serial_raw",
            ],
            cwd=str(HERE),
        )
        # Second pass: same session replay not needed — rewrite verify by
        # re-tagging is skipped; instead run client again briefly with direct proto
        # using a short wire of already-captured frames is heavy. Convert via tshark N/A.
        # Produce direct-dissect pcap by re-running a one-shot capture copy helper:
        subprocess.call(
            [
                sys.executable,
                str(HERE / "retag_pcap_proto.py"),
                str(args.pcap),
                str(direct),
                "nari_serial_iec103",
            ],
            cwd=str(HERE),
        )
    finally:
        prot.terminate()
        try:
            prot.wait(timeout=3)
        except Exception:
            prot.kill()

    print(f"\nPCAP(serial_raw) = {args.pcap}")
    print(f"PCAP(direct)     = {direct}")
    if TSHARK.exists() and direct.exists():
        print("\n=== tshark decode (direct nari_serial_iec103) ===")
        subprocess.call(
            [
                str(TSHARK),
                "-r",
                str(direct),
                "-T",
                "fields",
                "-e",
                "frame.number",
                "-e",
                "frame.len",
                "-e",
                "_ws.col.Protocol",
                "-e",
                "_ws.col.Info",
            ]
        )
    if args.open_ui and WIRESHARK.exists():
        subprocess.Popen([str(WIRESHARK), str(args.pcap)])
        print("Opened Wireshark. Use: 串口103 -> 南瑞串口103规约解析")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())