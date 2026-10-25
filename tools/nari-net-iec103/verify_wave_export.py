#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Smoke-verify NARI 103 wave export inputs from a pcapng via tshark."""

from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path

PCAP = Path(__file__).resolve().parent / "out" / "nari_net_103_loopback.pcapng"
TSHARK = Path(r"C:\Development\wsbuild-industrial\run\RelWithDebInfo\tshark.exe")
FAN = 1


def tshark_payloads(pcap: Path) -> list[bytes]:
    if not TSHARK.exists():
        raise FileNotFoundError(f"tshark not found: {TSHARK}")
    cmd = [
        str(TSHARK),
        "-r",
        str(pcap),
        "-Y",
        "tcp.port == 1048 && tcp.payload",
        "-T",
        "fields",
        "-e",
        "tcp.payload",
    ]
    out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    payloads: list[bytes] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        payloads.append(bytes.fromhex(line.replace(":", "")))
    return payloads


def parse_asdus(payload: bytes):
    off = 0
    while off + 6 <= len(payload):
        typ = payload[off]
        vsq = payload[off + 1]
        body_off = off + 6
        off = body_off
        if typ == 23:
            n = vsq & 0x7f
            for _ in range(n):
                if off + 10 > len(payload):
                    break
                fan = struct.unpack_from("<H", payload, off)[0]
                cp56 = payload[off + 3 : off + 10]
                yield ("asdu23", fan, cp56)
                off += 10
        elif typ == 26 and off + 16 <= len(payload):
            fan = struct.unpack_from("<H", payload, off + 3)[0]
            noe = payload[off + 8]
            int_us = struct.unpack_from("<H", payload, off + 9)[0]
            yield ("asdu26", fan, noe, int_us)
            off += 16
        elif typ == 27 and off + 18 <= len(payload):
            fan = struct.unpack_from("<H", payload, off + 3)[0]
            acc = payload[off + 5]
            yield ("asdu27", fan, acc)
            off += 18
        elif typ == 29 and off + 3 <= len(payload):
            fan = struct.unpack_from("<H", payload, off)[0]
            not_count = payload[off + 2]
            off += 3 + not_count * 5
            yield ("asdu29", fan, not_count)
        elif typ == 30 and off + 10 <= len(payload):
            fan = struct.unpack_from("<H", payload, off + 3)[0]
            acc = payload[off + 5]
            ndv, nfe = struct.unpack_from("<HH", payload, off + 6)
            pos = off + 10
            sdv_count = 0
            for _ in range(ndv):
                if pos + 2 > len(payload):
                    break
                sdv_count += 1
                pos += 2
            yield ("asdu30", fan, acc, nfe, ndv, sdv_count)
            off = pos
        else:
            break


def main() -> int:
    if not PCAP.exists():
        print(f"Missing pcap: {PCAP}", file=sys.stderr)
        return 1

    events = []
    for payload in tshark_payloads(PCAP):
        events.extend(parse_asdus(payload))

    fan_events = [e for e in events if e[1] == FAN]
    asdu30 = [e for e in fan_events if e[0] == "asdu30"]
    asdu29 = [e for e in fan_events if e[0] == "asdu29"]
    asdu26 = [e for e in fan_events if e[0] == "asdu26"]
    asdu23 = [e for e in fan_events if e[0] == "asdu23"]

    print(f"FAN={FAN}: ASDU23={len(asdu23)} ASDU26={len(asdu26)} ASDU29={len(asdu29)} ASDU30={len(asdu30)}")
    if not asdu30:
        print("FAIL: no ASDU30 for FAN", file=sys.stderr)
        return 1
    accs = sorted({e[2] for e in asdu30})
    print(f"Analog ACC channels: {accs}")
    print(f"ASDU30 segments: {len(asdu30)}")
    if asdu29:
        print(f"ASDU29 tag counts: {[e[2] for e in asdu29]}")
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
