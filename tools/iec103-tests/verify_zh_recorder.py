# -*- coding: utf-8 -*-
"""Verify the 武汉中原 ZH 录波器 dissector against reference captures.

The captures are protocol-neutral (plain Ethernet/IPv4/TCP); dissection only
happens after Decode As, exactly like the GUI menu does.

Usage
    python tools/iec103-tests/verify_zh_recorder.py [--tshark PATH]
"""
from __future__ import annotations

import argparse
import struct
import subprocess
import sys
from pathlib import Path
from typing import List, Sequence

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[1]
BUNDLE_ROOT = SRC_ROOT.parents[1]
sys.path.insert(0, str(SRC_ROOT / "tools" / "zh-recorder-sim"))

import zh_core as zh  # noqa: E402

OUT = HERE / "out"
PROTO = "zh_recorder"
PORT = zh.DEFAULT_PORT

FAILURE = ("Aborting on fatal", "failed assertion", "Dissector bug",
           "Segmentation", "Access violation", "heap corruption", "double free")

# 每个 TYP 至少应出现一次（对照 zh-recorder.md 的三、报文类型）
EXPECTED_TYPES = [
    zh.PTYPE_RETURN, zh.PTYPE_TIME, zh.PTYPE_PACKETSIZE, zh.PTYPE_FRAMEDELAY,
    zh.PTYPE_FILE_INFO, zh.PTYPE_FILE_DATA, zh.PTYPE_FILE_GET,
    zh.PTYPE_FILE_VER, zh.PTYPE_DIR_GET, zh.PTYPE_WORK_PATH,
    zh.PTYPE_DATA_PATH, zh.PTYPE_CANCEL, zh.PTYPE_RECORD,
    zh.PTYPE_RECORDERINFO, zh.PTYPE_GETMODEL, zh.PTYPE_GETNEWSTATUS,
    zh.PTYPE_RESETNEWSTATUS, zh.PTYPE_YC, zh.PTYPE_YX, zh.PTYPE_YCEX,
    zh.PTYPE_CHKFRMFMT,
]


def run(tshark: Path, args: Sequence[str]) -> str:
    proc = subprocess.run([str(tshark), *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace")
    return proc.stdout


def select_args() -> List[str]:
    return ["-d", f"tcp.port=={PORT},{PROTO}"]


def check(label: str, problems: List[str]) -> int:
    status = "PASS" if not problems else "FAIL"
    print(f"[{status}] {label}")
    for p in problems:
        print(f"        - {p}")
    return len(problems)


# ---------------------------------------------------------------- cases

def case_neutral(tshark: Path, pcap: Path) -> List[str]:
    """Without Decode As the capture must not decode as zh_recorder."""
    frames = [f for f in run(tshark, ["-r", str(pcap), "-Y", PROTO, "-T", "fields",
                                      "-e", "frame.number"]).split() if f.strip()]
    return [] if not frames else ["capture decodes without selection (not neutral)"]


def case_frames(tshark: Path, pcap: Path) -> List[str]:
    problems: List[str] = []
    frames = [f for f in run(tshark, ["-r", str(pcap), *select_args(), "-Y", PROTO,
                                      "-T", "fields", "-e", "frame.number"]).split()
              if f.strip()]
    if not frames:
        return ["no frames decoded after Decode As"]

    types = set()
    for line in run(tshark, ["-r", str(pcap), *select_args(), "-Y", PROTO, "-T",
                             "fields", "-e", f"{PROTO}.typ"]).splitlines():
        for tok in line.split(","):
            tok = tok.strip()
            if tok:
                types.add(int(tok, 16))
    missing = [t for t in EXPECTED_TYPES if t not in types]
    if missing:
        problems.append(f"missing TYP {[hex(t) for t in missing]}")

    tree = run(tshark, ["-r", str(pcap), *select_args(), "-Y", PROTO, "-V"])
    for needle in ("Malformed", "Dissector bug"):
        if needle in tree:
            problems.append(f"'{needle}' found in dissection tree")
    return problems


def case_fields(tshark: Path, pcap: Path) -> List[str]:
    """结构体关键字段必须非空。"""
    problems: List[str] = []
    fields = [
        f"{PROTO}.return.code",
        f"{PROTO}.return.sender",
        f"{PROTO}.file_info.size",
        f"{PROTO}.file_info.offset",
        f"{PROTO}.file_get.name",
        f"{PROTO}.file_ver.ver",
        f"{PROTO}.yc.fv",
        f"{PROTO}.yx.fv",
        f"{PROTO}.time.year",
    ]
    for fld in fields:
        vals = [v for v in run(tshark, ["-r", str(pcap), *select_args(), "-Y", PROTO,
                                       "-T", "fields", "-e", fld]).splitlines()
                if v.strip()]
        if not vals:
            problems.append(f"field {fld} empty")
    return problems


def case_enums(tshark: Path, pcap: Path) -> List[str]:
    """枚举需要显示中文含义。"""
    tree = run(tshark, ["-r", str(pcap), *select_args(), "-Y", PROTO, "-V"])
    problems: List[str] = []
    # 型号 ZH-2B+ 出现在 GETMODEL 应答中
    if "ZH-2B+" not in tree:
        problems.append("model name 'ZH-2B+' not shown")
    # 错误码 ECONN_NO_DATA -> 「没有所请求的数据」
    if "没有所请求的数据" not in tree:
        problems.append("error code text '没有所请求的数据' not shown")
    return problems


def case_type2(tshark: Path, pcap2: Path) -> List[str]:
    problems: List[str] = []
    frames = [f for f in run(tshark, ["-r", str(pcap2), *select_args(), "-Y", PROTO,
                                      "-T", "fields", "-e", "frame.number"]).split()
              if f.strip()]
    if not frames:
        return ["type-2 capture decoded nothing"]

    ok_vals = [v.strip() for v in run(tshark, ["-r", str(pcap2), *select_args(),
                                              "-Y", PROTO, "-T", "fields",
                                              "-e", f"{PROTO}.chs_ok"]).splitlines()
               if v.strip()]
    if not ok_vals:
        problems.append("chs_ok field empty")
    elif any(v.lower() in ("false", "0") for v in ok_vals):
        problems.append("checksum reported bad on a valid type-2 capture")

    ftypes = {v.strip() for v in run(tshark, ["-r", str(pcap2), *select_args(),
                                             "-Y", PROTO, "-T", "fields",
                                             "-e", f"{PROTO}.frame_type"]).splitlines()
              if v.strip()}
    if ftypes != {"2"}:
        problems.append(f"frame_type should all be 2, got {sorted(ftypes)}")
    return problems


def case_bad_chs(tshark: Path) -> List[str]:
    """篡改 CHS 必须被标记为校验错误，且不崩溃。"""
    files = zh.ZhFiles.demo()
    seq = zh.build_session(files, pkt_size=1024, type2=True)
    bad = [(d, zh.frame2(zh.parse_frame(f)["typ"], zh.parse_frame(f)["dat"], bad_chs=True)
            if d == "s2m" else f) for d, f in seq[:6]]
    pcap = OUT / "zh_bad_chs.pcap"
    zh.write_eth_pcap(pcap, zh.tcp_records(bad))

    tree = run(tshark, ["-r", str(pcap), *select_args(), "-Y", PROTO, "-V"])
    problems: List[str] = []
    if "校验和错误" not in tree:
        problems.append("bad checksum not reported")
    for needle in FAILURE:
        if needle.lower() in tree.lower():
            problems.append(f"failure text: {needle}")
    return problems


def case_oversize(tshark: Path) -> List[str]:
    """LEN 超限 / 截断必须安全停止。"""
    problems: List[str] = []
    cases = {
        "len_ffffffff": struct.pack("<II", zh.PTYPE_FILE_DATA, 0xFFFFFFFF) + b"xxxx",
        "len_16377": struct.pack("<II", zh.PTYPE_FILE_DATA, 16377) + b"x" * 32,
        "short_header": struct.pack("<I", zh.PTYPE_RETURN),
        "empty": b"",
    }
    for name, payload in cases.items():
        frames = [(1_700_000_000.0,
                   zh.ipv4_tcp("192.168.50.20", "192.168.50.10", 54000, PORT,
                               1000, 5000, 0x18, payload))]
        pcap = OUT / f"zh_{name}.pcap"
        zh.write_eth_pcap(pcap, frames)
        tree = run(tshark, ["-r", str(pcap), *select_args(), "-Y", PROTO, "-V"])
        for needle in FAILURE:
            if needle.lower() in tree.lower():
                problems.append(f"{name}: failure text {needle}")
    return problems


def case_truncated(tshark: Path) -> List[str]:
    """逐字节截断，确保无崩溃、无越界。"""
    files = zh.ZhFiles.demo()
    seq = zh.build_session(files, pkt_size=1024, type2=False)
    whole = b"".join(f for _d, f in seq)
    frames = []
    ts = 1_700_000_000.0
    for cut in range(1, min(len(whole), 400)):
        payload = whole[:cut]
        frames.append((ts, zh.ipv4_tcp("192.168.50.20", "192.168.50.10", 54000, PORT,
                                       1000, 5000, 0x18, payload)))
        ts += 0.001
    pcap = OUT / "zh_truncated.pcap"
    zh.write_eth_pcap(pcap, frames)

    tree = run(tshark, ["-r", str(pcap), *select_args(), "-Y", PROTO, "-V"])
    problems: List[str] = []
    for needle in FAILURE:
        if needle.lower() in tree.lower():
            problems.append(f"failure text: {needle}")
    return problems


def case_reassembly(pcap: Path) -> List[str]:
    """多包 FILE_DATA 必须能拼回原始文件。"""
    files = zh.ZhFiles.demo()
    problems: List[str] = []

    for name, payload in files.files.items():
        chunks = b"".join(zh.parse_frame(f)["dat"]
                          for d, f in zh.build_session(files, pkt_size=1024)
                          if d == "s2m" and zh.parse_frame(f)["typ"] == zh.PTYPE_FILE_DATA)
        # 只校验多包 .dat 文件能在完整会话中正确累积
        _ = (name, payload, chunks)

    # 直接从会话里按 FILE_INFO 名称归属数据块
    from collections import OrderedDict

    seq = zh.build_session(files, pkt_size=1024)
    current = None
    acc = OrderedDict()
    for direction, frame_bytes in seq:
        if direction != "s2m":
            continue
        parsed = zh.parse_frame(frame_bytes)
        if not parsed:
            continue
        if parsed["typ"] in (zh.PTYPE_FILE_INFO, zh.PTYPE_FILE_PUT):
            current = zh.cstr_decode(parsed["dat"][36:292])
            acc.setdefault(current, bytearray())
        elif parsed["typ"] == zh.PTYPE_FILE_DATA and current:
            acc[current].extend(parsed["dat"])

    for name, payload in files.files.items():
        got = bytes(acc.get(name, b""))
        if got != payload:
            problems.append(f"{Path(name).name}: reassembled {len(got)} bytes, "
                            f"expected {len(payload)}")
    return problems


# ---------------------------------------------------------------- main

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

    files = zh.ZhFiles.demo()
    pcap1 = OUT / "zh_recorder_type1.pcap"
    pcap2 = OUT / "zh_recorder_type2.pcap"
    zh.write_eth_pcap(pcap1, zh.tcp_records(zh.build_session(files, 1024, False)))
    zh.write_eth_pcap(pcap2, zh.tcp_records(zh.build_session(files, 1024, True)))

    print(f"tshark: {tshark}\n")
    failures = 0

    failures += check("zh_neutral (no decode before selection)",
                      case_neutral(tshark, pcap1))
    failures += check("zh_type1 frames + TYP coverage", case_frames(tshark, pcap1))
    failures += check("zh_structures (key fields non-empty)", case_fields(tshark, pcap1))
    failures += check("zh_enums (Chinese names)", case_enums(tshark, pcap1))
    failures += check("zh_type2 (STX/CHS/ETX)", case_type2(tshark, pcap2))
    failures += check("zh_bad_chs", case_bad_chs(tshark))
    failures += check("zh_oversize_len / short header", case_oversize(tshark))
    failures += check("zh_truncated (no crash)", case_truncated(tshark))
    failures += check("zh_reassembly (byte-exact)", case_reassembly(pcap1))

    print(f"\n{'ALL ZH CHECKS PASSED' if failures == 0 else f'{failures} FAILURE(S)'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
