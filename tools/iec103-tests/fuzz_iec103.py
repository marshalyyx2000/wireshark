# -*- coding: utf-8 -*-
"""Fuzz the 103 dissectors with truncated and mutated payloads.

The point is to prove the length walks never read past the PDU and that a bad
payload cannot crash the process. Every mutated frame is fed through the same
dissector the GUI would use.

Usage
    python tools/iec103-tests/fuzz_iec103.py [--rounds N] [--tshark PATH]
"""
from __future__ import annotations

import argparse
import random
import struct
import subprocess
import sys
from pathlib import Path
from typing import List, Sequence, Tuple

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUNDLE_ROOT = ROOT.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "iec103-sim"))

import iec103_core as c103  # noqa: E402
import iec103_serial_sim as ssim  # noqa: E402

OUT = HERE / "out"
FUZZ = OUT / "fuzz"
FAILURE = ("Aborting on fatal", "failed assertion", "Dissector bug", "Segmentation",
           "Access violation", "heap corruption", "double free")


def write_exported(path: Path, frames: Sequence[bytes], proto: str) -> None:
    c103.write_pcap(path, [(1_700_000_000.0 + i * 0.01, f, proto)
                           for i, f in enumerate(frames)])


def serial_variants() -> List[bytes]:
    base = [f for _d, f in ssim.build_conversation("sznari", 0x03)]
    out: List[bytes] = []
    for frame in base:
        # truncations at every boundary
        for cut in range(1, len(frame)):
            out.append(frame[:cut])
        # header field corruption for variable frames
        if len(frame) > 8 and frame[0] == 0x68:
            for pos in (1, 2, 5, 6, 7, 8):
                if pos < len(frame):
                    bad = bytearray(frame)
                    bad[pos] = 0xFF
                    out.append(bytes(bad))
                if pos < len(frame):
                    bad = bytearray(frame)
                    bad[pos] = 0x00
                    out.append(bytes(bad))
    return out


def net_variants() -> List[bytes]:
    base = [a for a in __import__("iec103_net_sim").nrelectric_asdus()]
    out: List[bytes] = []
    for asdu in base:
        for cut in range(1, len(asdu)):
            out.append(asdu[:cut])
        for pos in range(min(8, len(asdu))):
            bad = bytearray(asdu)
            bad[pos] = 0xFF
            out.append(bytes(bad))
    return out


def jinzhi_variants() -> List[bytes]:
    """金智: 2-byte length, 12/13-byte control, extension ASDU bodies."""
    import iec103_net_sim as nsim

    out: List[bytes] = []
    for asdu in nsim.jinzhi_asdus() + nsim.jinzhi_master_asdus():
        full = nsim.jz_apdu(asdu, ctrl_len=12)
        out.extend(full[:n] for n in range(1, len(full)))
        bad = bytearray(full)
        bad[1] = 0xFF      # length low byte
        out.append(bytes(bad))
        bad = bytearray(full)
        bad[2] = 0x00      # length high byte (truncates body)
        out.append(bytes(bad))
        bad = bytearray(full)
        bad[3] = 0xFF      # control byte 0
        out.append(bytes(bad))
    return out


def jicheng_variants() -> List[bytes]:
    import iec103_net_sim as nsim

    out: List[bytes] = []
    for asdu in nsim.jicheng_asdus() + nsim.jicheng_master_asdus():
        full = nsim.jc_apdu(asdu)
        out.extend(full[:n] for n in range(1, len(full)))
        bad = bytearray(full)
        bad[1] = 0xFF
        out.append(bytes(bad))
    return out


def random_mutations(frames: Sequence[bytes], rounds: int, seed: int = 20261107) -> List[bytes]:
    rng = random.Random(seed)
    out: List[bytes] = []
    for _ in range(rounds):
        frame = bytearray(rng.choice(frames))
        for _ in range(rng.randint(1, 4)):
            if not frame:
                break
            frame[rng.randrange(len(frame))] = rng.randrange(256)
        out.append(bytes(frame))
    return out


def run_batch(tshark: Path, pcap: Path, proto: str, label: str) -> List[str]:
    if proto.endswith("_net_iec103"):
        select = ["-d", f"tcp.port==1048,{proto}", "-d", f"udp.port==1032,{proto}"]
    else:
        select = ["-o", f"serial_raw.payload_dissector:{proto}"]
    proc = subprocess.run([str(tshark), "-r", str(pcap), *select, "-V"],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace")
    problems: List[str] = []
    if proc.returncode not in (0, 1, 2):
        problems.append(f"exit {proc.returncode}")
    combined = proc.stdout + proc.stderr
    for needle in FAILURE:
        if needle.lower() in combined.lower():
            problems.append(f"failure text: {needle}")
    status = "PASS" if not problems else "FAIL"
    print(f"[{status}] {label} ({len(combined)} bytes of dissection output)")
    for p in problems:
        print(f"        - {p}")
    return problems


def zh_variants() -> List[bytes]:
    """ZH 录波器: 两种帧格式、LEN 边界、结构体截断。"""
    sys.path.insert(0, str(ROOT / "tools" / "zh-recorder-sim"))
    import zh_core as zh

    files = zh.ZhFiles.demo()
    out: List[bytes] = []
    for type2 in (False, True):
        seq = zh.build_session(files, pkt_size=256, type2=type2)
        for _direction, payload in seq:
            # 每个报文逐字节截断
            out.extend(payload[:n] for n in range(1, len(payload)))
            # LEN 字段腐蚀
            if len(payload) >= 8:
                bad = bytearray(payload)
                bad[4 if not type2 else 12] = 0xFF
                out.append(bytes(bad))
            if len(payload) >= 8:
                bad = bytearray(payload)
                bad[0 if not type2 else 8] = 0xFF
                out.append(bytes(bad))
    return out


def run_batch_net(tshark: Path, pcap: Path, proto: str, port: int, label: str) -> List[str]:
    """Fuzz a network dissector selected through Decode As."""
    select = ["-d", f"tcp.port=={port},{proto}", "-d", f"udp.port=={port},{proto}"]
    proc = subprocess.run([str(tshark), "-r", str(pcap), *select, "-V"],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace")
    problems: List[str] = []
    if proc.returncode not in (0, 1, 2):
        problems.append(f"exit {proc.returncode}")
    combined = proc.stdout + proc.stderr
    for needle in FAILURE:
        if needle.lower() in combined.lower():
            problems.append(f"failure text: {needle}")
    status = "PASS" if not problems else "FAIL"
    print(f"[{status}] {label}")
    for p in problems:
        print(f"        - {p}")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tshark", default=None)
    ap.add_argument("--rounds", type=int, default=400)
    args = ap.parse_args()

    tshark = Path(args.tshark) if args.tshark else (
        BUNDLE_ROOT / "06-build" / "wsbuild-industrial" / "run" /
        "RelWithDebInfo" / "tshark.exe")
    if not tshark.exists():
        raise SystemExit("tshark not found")

    FUZZ.mkdir(parents=True, exist_ok=True)
    failures = 0

    ser = serial_variants()
    ser_pcap = FUZZ / "sznari_serial_truncated.pcap"
    write_exported(ser_pcap, ser, "serial_raw")
    failures += len(run_batch(tshark, ser_pcap, "sznari_serial_iec103",
                              f"sznari serial truncated/corrupt ({len(ser)} frames)"))

    net = net_variants()
    net_pcap = FUZZ / "nrelectric_net_truncated.pcap"
    write_exported(net_pcap, net, "nrelectric_net_iec103")
    failures += len(run_batch(tshark, net_pcap, "nrelectric_net_iec103",
                              f"nrelectric net truncated/corrupt ({len(net)} frames)"))

    rnd = random_mutations(ser + net, args.rounds)
    rnd_pcap = FUZZ / "random_mutations.pcap"
    write_exported(rnd_pcap, rnd, "serial_raw")
    failures += len(run_batch(tshark, rnd_pcap, "sznari_serial_iec103",
                              f"random mutations ({len(rnd)} frames)"))

    # 金智 / 积成: build neutral Ethernet pcaps and select with Decode As.
    import iec103_net_sim as nsim

    for label, variants, proto, port, builder in (
        ("jinzhi", jinzhi_variants(), "jinzhi_net_iec103", 6000, nsim.run_jinzhi),
        ("jicheng", jicheng_variants(), "jicheng_net_iec103", 6185, nsim.run_jicheng),
        ("zh_recorder", zh_variants(), "zh_recorder", 30282, None),
    ):
        frames = []
        for i, payload in enumerate(variants):
            frames.append((1_700_000_000.0 + i * 0.001,
                           nsim.ipv4_tcp("192.168.10.10", "192.168.10.20", 50000, port,
                                         i * 500, 1, 0x18, payload,
                                         dst_mac="00:11:22:33:44:66")))
        pcap = FUZZ / f"{label}_truncated.pcap"
        nsim.write_net_pcap(pcap, [(ts, f, "") for ts, f in frames])
        failures += len(run_batch_net(tshark, pcap, proto, port,
                                      f"{label} truncated/corrupt ({len(frames)} frames)"))

    print(f"\n{'FUZZ PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
