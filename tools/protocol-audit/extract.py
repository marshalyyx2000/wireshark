# -*- coding: utf-8 -*-
"""从 PROTOCOL 参考实现抽取权威协议事实。

对每个厂商目录扫描 .cpp/.h，提取：
  - 帧格式特征（FT1.2 / 103-ASDU / TYP+LEN / 固定头）
  - 出现的 ASDU/TYP 常量
  - 传送原因（COT）常量
  - 帧长公式与校验算法特征
  - 端口号（htons/ntohs、listen/connect 字面量）
  - 传输方式（SOCK_STREAM / SOCK_DGRAM / 串口）

输出 audit/<vendor>.json 与 audit/SUMMARY.md。

用法
    python extract.py            # 全部厂商
    python extract.py --vendor SF103
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[1]
PROTOCOL_DIR = SRC_ROOT / "tools" / "现场运行的各种规约程序" / "PROTOCOL"
OUT_DIR = HERE / "audit"

SOURCE_EXT = {".cpp", ".h"}

# ASDU 类型：case 123: 只在 103 语境下算数，这里先全量收集再靠上下文过滤
RE_CASE_NUM = re.compile(r"case\s+(\d{1,3})\s*:")
RE_CASE_HEX = re.compile(r"case\s+0[xX]([0-9A-Fa-f]{1,4})\s*:")
RE_ASDU_COMMENT = re.compile(r"ASDU\s*(\d{1,3})")
RE_TYPEID_COMMENT = re.compile(r"TYP\s*=?\s*<?(\d{1,3})>?")
RE_PORT = re.compile(r"(?:htons|ntohs)\s*\(\s*(0[xX][0-9A-Fa-f]+|\d{2,5})\s*\)")
RE_PORT_DECL = re.compile(r"(?:port|Port|PORT)\s*[=:]\s*(0[xX][0-9A-Fa-f]+|\d{4,5})")
RE_LISTEN = re.compile(r"(?:bind|listen|connect)\s*\(\s*[^)]*\b(\d{4,5})\b")
RE_LEN_BYTE = re.compile(r"\[\s*1\s*\]\s*\)\s*[;,]?\s*//?\s*len", re.I)
RE_U16_LEN = re.compile(r"get_?u16|WORD\s+len|LEN", re.I)

RE_CHECKSUM_ADD = re.compile(r"checksum\s*=\s*\(BYTE\)\s*\(\s*checksum\s*\+", re.I)
RE_CHECKSUM_XOR = re.compile(r"checksum\s*(\^=|\^)", re.I)
RE_CRC16 = re.compile(r"crc16|CRC_16|Crc16", re.I)
RE_SUM8 = re.compile(r"sum\s*&\s*0[xX]?FF|&\s*0[xX]?FF.*sum", re.I)


def read_text(path: Path) -> str:
    """参考实现是 GBK 编码的 VC6 工程。"""
    for enc in ("gbk", "utf-8", "latin-1"):
        try:
            return path.read_text(encoding=enc, errors="ignore")
        except OSError:
            return ""
    return ""


def gather(vendor_dir: Path) -> dict:
    files = []
    text_parts = []
    for root, _dirs, names in os.walk(vendor_dir):
        for name in names:
            p = Path(root) / name
            if p.suffix.lower() in SOURCE_EXT:
                files.append(p.relative_to(vendor_dir).as_posix())
                text_parts.append(read_text(p))
    text = "\n".join(text_parts)
    low = text.lower()

    # --- 帧格式特征 ---
    has_68 = "0x68" in low or "0X68" in text
    has_10_16 = "0x10" in low and "0x16" in low
    has_asdu = "asdu" in low
    has_typ_len = re.search(r"\bTYP\b", text) is not None and re.search(r"\bLEN\b", text) is not None

    if has_asdu and has_68:
        framing = "iec103"
    elif has_typ_len:
        framing = "typ_len_dat"
    elif has_10_16:
        framing = "ft12"
    elif "ascii" in low:
        framing = "ascii"
    else:
        framing = "unknown"

    # --- ASDU / TYP 常量 ---
    asdu_from_comment = sorted({int(x) for x in RE_ASDU_COMMENT.findall(text) if int(x) <= 255})
    typ_from_comment = sorted({int(x) for x in RE_TYPEID_COMMENT.findall(text) if int(x) <= 255})
    case_nums = sorted({int(x) for x in RE_CASE_NUM.findall(text) if 0 < int(x) <= 255})
    case_hex = sorted({int(x, 16) for x in RE_CASE_HEX.findall(text) if 0 < int(x, 16) <= 0xFFFF})

    # --- 端口 ---
    ports = set()
    for m in RE_PORT.findall(text):
        v = int(m, 0)
        if 1 <= v <= 65535:
            ports.add(v)
    for m in RE_PORT_DECL.findall(text):
        v = int(m, 0)
        if 1 <= v <= 65535:
            ports.add(v)
    for m in RE_LISTEN.findall(text):
        v = int(m)
        if 1 <= v <= 65535:
            ports.add(v)

    # --- 传输方式 ---
    tcp = "SOCK_STREAM" in text or "CSocket" in text or "WSAStartup" in text
    udp = "SOCK_DGRAM" in text
    serial = ("CreateFile" in text and "COM" in text) or "SetCommState" in text

    # --- 校验 ---
    checksum = []
    if RE_CHECKSUM_ADD.search(text):
        checksum.append("sum8_add")
    if RE_CHECKSUM_XOR.search(text):
        checksum.append("xor8")
    if RE_CRC16.search(text):
        checksum.append("crc16")
    if RE_SUM8.search(text):
        checksum.append("sum8")

    return {
        "vendor": vendor_dir.name,
        "files": len(files),
        "bytes": len(text),
        "framing": framing,
        "asdu_comments": asdu_from_comment,
        "typ_comments": typ_from_comment,
        "case_ints": case_nums[:64],
        "case_hex": [f"0x{v:04X}" for v in case_hex[:64]],
        "ports": sorted(ports),
        "tcp": tcp,
        "udp": udp,
        "serial": serial,
        "checksum": checksum,
        "has_sttp_dll": "SttpEngineC.dll" in text,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vendor", default=None)
    args = ap.parse_args()

    if not PROTOCOL_DIR.is_dir():
        raise SystemExit(f"protocol source not found: {PROTOCOL_DIR}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    vendors = ([args.vendor] if args.vendor
               else sorted(p.name for p in PROTOCOL_DIR.iterdir() if p.is_dir()))

    summary = []
    for name in vendors:
        vdir = PROTOCOL_DIR / name
        if not vdir.is_dir():
            print(f"skip missing {name}")
            continue
        info = gather(vdir)
        (OUT_DIR / f"{name}.json").write_text(
            json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
        summary.append(info)

    lines = ["# PROTOCOL 参考实现索引", "",
             "由 `extract.py` 从 87 个厂商 C++ 源码机器提取，不含人工推断。", "",
             "| 厂商 | 帧格式 | TCP | UDP | 串口 | 端口 | ASDU 注释 | case 常量 | 校验 | 字节数 |",
             "|------|--------|-----|-----|------|------|-----------|-----------|------|--------|"]
    for s in summary:
        lines.append(
            f"| {s['vendor']} | {s['framing']} | {int(s['tcp'])} | {int(s['udp'])} | "
            f"{int(s['serial'])} | {','.join(map(str, s['ports'])) or '-'} | "
            f"{','.join(map(str, s['asdu_comments'][:8])) or '-'} | "
            f"{len(s['case_ints'])} 个 | {','.join(s['checksum']) or '-'} | {s['bytes']} |")
    (OUT_DIR / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    by_framing = {}
    for s in summary:
        by_framing.setdefault(s["framing"], 0)
        by_framing[s["framing"]] += 1
    print(f"vendors: {len(summary)}")
    for k, v in sorted(by_framing.items(), key=lambda x: -x[1]):
        print(f"  {k}: {v}")
    print(f"output: {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
