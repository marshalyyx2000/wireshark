# -*- coding: utf-8 -*-
"""确认所有 iec103_vendor_register() 的 profile 都已注册成功。

背景：packet-iec103-vendor-common.c 里有固定大小的 profile 表，超出容量时
注册会被丢弃，表现为"协议存在但永远解析不出内容"。本脚本用一个刻意构造的
样本逐个协议验证：能解析出 typeid 才算真正注册。

用法
    python verify_profiles.py [--tshark PATH]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import List, Sequence

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[1]
BUNDLE_ROOT = SRC_ROOT.parents[1]
DISSECTORS = SRC_ROOT / "epan" / "dissectors"
OUT = HERE / "out"

sys.path.insert(0, str(SRC_ROOT / "tools" / "iec103-sim"))
import iec103_core as c103  # noqa: E402

ADDR = 0x03

# 这两家有独立 APCI（2 字节长度 / 12-13 字节控制域 / 4 字节控制域），
# 裸 ASDU 样本无法触发，由 verify_jinzhi_jicheng.py 单独覆盖。
OWN_APCI = {"jinzhi_net_iec103", "jicheng_net_iec103"}


def spec_vendors() -> set:
    """Short names generated from vendor-spec.json.

    Those carry FT1.2-over-TCP or a private APCI wrapper, so a bare ASDU sample
    cannot trigger them here; tools/iec103-tests/vendor-sim/run_spec_vendors.py
    builds the correct frame for each one instead.
    """
    import json
    spec = Path(__file__).resolve().parents[1] / "protocol-audit" / "vendor-spec.json"
    if not spec.exists():
        return set()
    data = json.loads(spec.read_text(encoding="utf-8"))
    return {v["short"] for v in data["vendors"]}


SPEC_SHORTS = spec_vendors()


def discover_protocols() -> List[str]:
    """Find every protocol短名 that passes a profile to the shared engine."""
    names = set()
    for p in DISSECTORS.glob("packet-*.c"):
        text = p.read_text(encoding="utf-8", errors="ignore")
        if "iec103_vendor_register(" not in text:
            continue
        for m in __import__("re").finditer(r'register_dissector\("(\w+)"', text):
            name = m.group(1)
            # Skip alias handles (e.g. *_udp) that share another profile.
            if name.endswith("_udp") or name.endswith("_tcp"):
                if name[:-4] in text and f'"{name[:-4]}"' in text:
                    continue
            names.add(name)
    # The shared engine's own serial FT1.2 dissectors register by name too.
    return sorted(names)


def bindings(proto: str) -> tuple[bool, bool]:
    """Return (binds_tcp, binds_udp) for a protocol's Decode-As registration."""
    src = next((p for p in DISSECTORS.glob("packet-*.c")
                if f'"{proto}"' in p.read_text(encoding="utf-8", errors="ignore")), None)
    if src is None:
        return (False, False)
    text = src.read_text(encoding="utf-8", errors="ignore")
    return ('dissector_add_for_decode_as("tcp.port"' in text,
            'dissector_add_for_decode_as("udp.port"' in text)


def is_network_source(proto: str) -> bool:
    tcp, udp = bindings(proto)
    return tcp or udp


def build_pcap(path: Path, proto: str, cot16: bool) -> None:
    asdu = c103.asdu_ident(ADDR, desc=b"PROFILE  CHECK")
    if cot16:
        asdu = asdu[:2] + bytes((asdu[2], 0x00)) + asdu[3:]

    tcp, udp = bindings(proto)
    if tcp or udp:
        sys.path.insert(0, str(SRC_ROOT / "tools" / "iec103-sim"))
        import iec103_net_sim as nsim
        if tcp:
            frame = nsim.ipv4_tcp("192.168.70.10", "192.168.70.20", 56000, 2404,
                                  1000, 5000, 0x18, asdu,
                                  dst_mac="00:11:22:33:44:66")
        else:
            frame = nsim.ipv4_udp("192.168.70.10", "192.168.70.20", 56000, 1888,
                                  asdu, dst_mac="00:11:22:33:44:66")
        nsim.write_net_pcap(path, [(1_700_000_000.0, frame, "")])
        return

    frame = c103.frame_var(0x08, ADDR, asdu)
    c103.write_pcap(path, [(1_700_000_000.0, frame, "serial_raw")])


def select_args(proto: str) -> List[str]:
    tcp, udp = bindings(proto)
    if tcp:
        return ["-d", "tcp.port==2404," + proto]
    if udp:
        return ["-d", "udp.port==1888," + proto]
    return ["-o", f"serial_raw.payload_dissector:{proto}"]


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
    protocols = discover_protocols()
    print(f"profiles using the shared engine: {len(protocols)}\n")

    failures = 0
    for proto in protocols:
        if proto in OWN_APCI:
            print(f"[SKIP] {proto} (own APCI, covered by verify_jinzhi_jicheng.py)")
            continue
        if proto in SPEC_SHORTS:
            print(f"[SKIP] {proto} (FT1.2/APCI carrier, covered by vendor-sim/run_spec_vendors.py)")
            continue
        # 2-byte COT vendors are detected from their source.
        src = next((p for p in DISSECTORS.glob("packet-*.c")
                    if proto in p.read_text(encoding="utf-8", errors="ignore")), None)
        cot16 = src is not None and ".cot_len = 2" not in src.read_text(
            encoding="utf-8", errors="ignore") and "\t2\n};" in src.read_text(
            encoding="utf-8", errors="ignore")

        pcap = OUT / f"profile_{proto}.pcap"
        build_pcap(pcap, proto, cot16)
        proc = subprocess.run(
            [str(tshark), "-r", str(pcap), *select_args(proto), "-Y", proto,
             "-T", "fields", "-e", f"{proto}.typeid"],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        ok = bool(proc.stdout.strip())
        print(f"[{'PASS' if ok else 'FAIL'}] {proto}")
        if not ok:
            failures += 1

    print(f"\n{'ALL PROFILES REGISTERED' if failures == 0 else f'{failures} NOT REGISTERED'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
