# -*- coding: utf-8 -*-
"""ZH 录波器仿真一键演示：起录波器 + 主站，并生成中性抓包。

用法
    python run_zh_demo.py                 # 本机联调 + 生成 pcap
    python run_zh_demo.py --type2         # 使用类型二（带 STX/CHS/ETX）帧
    python run_zh_demo.py --pcap-only     # 不联网，仅生成 pcap
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import zh_core as zh  # noqa: E402

OUT = HERE / "out"
TSHARK = Path(r"C:\Development\Wireshark-Industrial-Bundle-0.10.3\06-build"
              r"\wsbuild-industrial\run\RelWithDebInfo\tshark.exe")


def build_pcap(path: Path, type2: bool, pkt_size: int = 1024) -> int:
    files = zh.ZhFiles.demo()
    seq = zh.build_session(files, pkt_size=pkt_size, type2=type2)
    zh.write_eth_pcap(path, zh.tcp_records(seq))
    print(f"pcap: {path} ({len(seq)} frames, type2={type2}, pkt_size={pkt_size})")
    return len(seq)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--type2", action="store_true")
    ap.add_argument("--pkt-size", type=int, default=1024)
    ap.add_argument("--pcap-only", action="store_true")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=zh.DEFAULT_PORT)
    args = ap.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    tag = "type2" if args.type2 else "type1"
    pcap = OUT / f"zh_recorder_{tag}.pcap"
    build_pcap(pcap, args.type2, args.pkt_size)

    if args.pcap_only:
        return 0

    rec = subprocess.Popen([
        sys.executable, str(HERE / "zh_recorder.py"),
        "--host", args.host, "--port", str(args.port),
        "--pkt-size", str(args.pkt_size),
    ] + (["--type2"] if args.type2 else []))
    time.sleep(1.0)
    try:
        rc = subprocess.call([
            sys.executable, str(HERE / "zh_master.py"),
            "--host", args.host, "--port", str(args.port),
        ] + (["--type2"] if args.type2 else []))
    finally:
        rec.terminate()
        try:
            rec.wait(timeout=5)
        except subprocess.TimeoutExpired:
            rec.kill()

    if rc != 0:
        print(f"master exited with {rc}")
        return rc

    if TSHARK.exists():
        proc = subprocess.run(
            [str(TSHARK), "-r", str(pcap), "-d",
             f"tcp.port=={args.port},zh_recorder", "-Y", "zh_recorder",
             "-T", "fields", "-e", "frame.number"],
            capture_output=True, text=True, encoding="utf-8", errors="replace")
        frames = [f for f in proc.stdout.split() if f.strip()]
        print(f"tshark decoded {len(frames)} zh_recorder frame(s)")
        if not frames:
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
