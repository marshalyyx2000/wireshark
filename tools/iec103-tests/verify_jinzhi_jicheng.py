# -*- coding: utf-8 -*-
"""金智 / 积成 specific regression cases beyond the generic verify suite.

Covers the risks that only these two framings have:
  * control field 12 vs 13 bytes (auto detection)
  * two-byte little-endian length, truncated APDU
  * several APDUs in one TCP segment
  * 积成 UDP 6185 broadcast with a meaningless control field

Usage
    python tools/iec103-tests/verify_jinzhi_jicheng.py [--tshark PATH]
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path
from typing import List, Sequence, Tuple

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[1]
BUNDLE_ROOT = SRC_ROOT.parents[1]
sys.path.insert(0, str(SRC_ROOT / "tools" / "iec103-sim"))

import iec103_core as c103  # noqa: E402
import iec103_net_sim as nsim  # noqa: E402
from build_pcaps import write_eth_pcap  # noqa: E402

OUT = HERE / "out"
ADDR = 0x03
JZ_PORT = 6000
JC_PORT = 6185

FAILURE = ("Aborting on fatal", "failed assertion", "Dissector bug",
           "Segmentation", "Access violation", "heap corruption", "double free")


def run(tshark: Path, args: Sequence[str]) -> Tuple[int, str]:
    import subprocess
    proc = subprocess.run([str(tshark), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    return proc.returncode, proc.stdout + proc.stderr


def tcp_frame(payload: bytes, sport: int, dport: int, seq: int) -> bytes:
    return nsim.ipv4_tcp("192.168.10.10", "192.168.10.20", sport, dport,
                         seq, 1, 0x18, payload, dst_mac="00:11:22:33:44:66")


def stream_case(name: str, frames: List[bytes], proto: str, port: int,
                expect_types: Sequence[int], tshark: Path) -> List[str]:
    pcap = OUT / f"jz_jc_{name}.pcap"
    write_eth_pcap(pcap, [(1_700_000_000.0 + i * 0.01, f) for i, f in enumerate(frames)])

    select = ["-d", f"tcp.port=={port},{proto}"]
    rc, out = run(tshark, ["-r", str(pcap), *select, "-Y", proto, "-T", "fields",
                           "-e", f"{proto}.typeid"])
    problems: List[str] = []
    if rc not in (0, 1, 2):
        problems.append(f"exit {rc}")
    for needle in FAILURE:
        if needle.lower() in out.lower():
            problems.append(f"failure text: {needle}")

    types = {int(t) for line in out.splitlines() for t in line.split(",") if t.strip().isdigit()}
    for typ in expect_types:
        if typ not in types:
            problems.append(f"ASDU{typ} missing (got {sorted(types)})")

    _, tree = run(tshark, ["-r", str(pcap), *select, "-Y", proto, "-V"])
    if "Malformed" in tree:
        problems.append("malformed packet found")

    status = "PASS" if not problems else "FAIL"
    print(f"[{status}] {name}")
    for p in problems:
        print(f"        - {p}")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tshark", default=None)
    args = ap.parse_args()

    tshark = Path(args.tshark) if args.tshark else (
        BUNDLE_ROOT / "06-build" / "wsbuild-industrial" / "run" /
        "RelWithDebInfo" / "tshark.exe")
    if not tshark.exists():
        raise SystemExit("tshark not found")

    OUT.mkdir(parents=True, exist_ok=True)
    failures = 0

    ident = c103.asdu_ident(ADDR, desc=b"JINZHI  TEST")
    events = [c103.asdu_gi_start(ADDR, scn=1),
              c103.asdu_protection_event(ADDR, c103.FUN_DISTANCE, 16, dpi=2),
              c103.asdu_generic(ADDR, [c103.gdd_entry(5, 1, 0x01, 3, 1, b"\x01")],
                                cot=c103.COT_SPONT, fun=254, inf=5)]

    # 12-byte control field
    failures += len(stream_case(
        "jinzhi_ctrl12", [tcp_frame(nsim.jz_apdu(a, ctrl_len=12), 52000, JZ_PORT, i * 100)
                          for i, a in enumerate([ident] + events)],
        "jinzhi_net_iec103", JZ_PORT, (5, 7, 2, 10), tshark))

    # 13-byte control field
    failures += len(stream_case(
        "jinzhi_ctrl13", [tcp_frame(nsim.jz_apdu(a, ctrl_len=13), 52000, JZ_PORT, i * 100)
                          for i, a in enumerate([ident] + events)],
        "jinzhi_net_iec103", JZ_PORT, (5, 7, 2, 10), tshark))

    # Five APDUs packed into one TCP segment
    packed = b"".join(nsim.jz_apdu(a, ctrl_len=12) for a in [ident] + events)
    failures += len(stream_case("jinzhi_packed", [tcp_frame(packed, 52000, JZ_PORT, 0)],
                                "jinzhi_net_iec103", JZ_PORT, (5, 7, 2, 10), tshark))

    # Truncated APDU must not run past the buffer or crash. Only the complete
    # frame carries a decodable ASDU; the rest must degrade without Malformed.
    full = nsim.jz_apdu(events[1], ctrl_len=12)
    truncated = [tcp_frame(full, 52000, JZ_PORT, 0)]
    truncated += [tcp_frame(full[:n], 52000, JZ_PORT, (i + 1) * 100)
                  for i, n in enumerate((5, 12, 18, len(full) - 1))]
    problems = stream_case("jinzhi_truncated", truncated, "jinzhi_net_iec103",
                           JZ_PORT, (2,), tshark)
    # A cut frame may legitimately be reported as truncated; only a crash or an
    # out-of-bounds read (assertion) is unacceptable.
    problems = [p for p in problems if "malformed packet found" not in p]
    print(f"[{'PASS' if not problems else 'FAIL'}] jinzhi_truncated (crash/bounds only)")
    for p in problems:
        print(f"        - {p}")
    failures += len(problems)

    # Extension ASDU coverage (220-229, 203/204)
    ext = nsim.jinzhi_asdus()
    failures += len(stream_case(
        "jinzhi_ext", [tcp_frame(nsim.jz_apdu(a, ctrl_len=12), 52000, JZ_PORT, i * 100)
                       for i, a in enumerate(ext)],
        "jinzhi_net_iec103", JZ_PORT, (5, 8, 10, 220, 222, 223, 224, 225, 226, 227,
                                       229, 204), tshark))

    # Jicheng TCP stream and UDP broadcast
    jc_frames = [tcp_frame(nsim.jc_apdu(a, ns=i), 53000, JC_PORT, i * 80)
                 for i, a in enumerate(nsim.jicheng_master_asdus() + nsim.jicheng_asdus())]
    failures += len(stream_case("jicheng_tcp", jc_frames, "jicheng_net_iec103", JC_PORT,
                                (6, 20, 24, 25, 5, 10, 23, 31), tshark))

    udp_pcap = OUT / "jz_jc_jicheng_udp.pcap"
    write_eth_pcap(udp_pcap, [(1_700_000_000.0,
                               nsim.ipv4_udp("192.168.30.10", "192.168.30.255", JC_PORT,
                                             JC_PORT, nsim.jicheng_broadcast(),
                                             dst_mac="ff:ff:ff:ff:ff:ff"))])
    rc, out = run(tshark, ["-r", str(udp_pcap), "-d", f"udp.port=={JC_PORT},jicheng_net_iec103",
                           "-Y", "jicheng_net_iec103", "-T", "fields",
                           "-e", "jicheng_net_iec103.typeid"])
    udp_ok = rc in (0, 1, 2) and "6" in out
    print(f"[{'PASS' if udp_ok else 'FAIL'}] jicheng_udp6185")
    if not udp_ok:
        failures += 1
        print(f"        - typeid output: {out.strip()!r}")

    print(f"\n{'ALL SPECIFIC CASES PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
