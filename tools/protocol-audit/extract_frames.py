# -*- coding: utf-8 -*-
"""抽取每个网络 103 厂商的帧头常量，用于与现有解析器逐项比对。

关注点：
  - ASDU_START_POSTION / m_StartPos / ASDU 起始偏移
  - 帧长字段位置与字节数
  - 校验和覆盖范围与算法
  - 是否有固定同步头（0x68 / 其它魔数）

用法
    python extract_frames.py            # 全部
    python extract_frames.py --vendor SF_NET103
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[1]
PROTOCOL_DIR = SRC_ROOT / "tools" / "现场运行的各种规约程序" / "PROTOCOL"
OUT_DIR = HERE / "audit"

RE_DEFINE_START = re.compile(
    r"#define\s+(\w*(?:ASDU|START|HEAD|HDR|POS)\w*)\s+(\d+)", re.I)
RE_DEFINE_MAGIC = re.compile(r"#define\s+(\w+)\s+(0[xX][0-9A-Fa-f]{2,8})")
RE_LEN_READ = re.compile(r"(?:pbuf|buf|m_pRead->buf)\s*\[\s*(\d+)\s*\]")
RE_CHKSUM_RANGE = re.compile(
    r"CheckSum\s*\(\s*&?\(?\s*(?:m_pRead->buf|pbuf|buf)\s*\[\s*(\d+)\s*\]\s*\)?\s*,\s*([^)]+)\)")
RE_FRAME_LEN_CALC = re.compile(r"dwLen\s*=\s*([^;]{1,80});")
RE_SOCKET_KIND = re.compile(r"(SOCK_STREAM|SOCK_DGRAM)")


def read_text(path: Path) -> str:
    for enc in ("gbk", "utf-8", "latin-1"):
        try:
            return path.read_text(encoding=enc, errors="ignore")
        except OSError:
            return ""
    return ""


def gather(vdir: Path) -> dict:
    text = ""
    for root, _dirs, names in os.walk(vdir):
        for name in names:
            p = Path(root) / name
            if p.suffix.lower() in (".cpp", ".h"):
                text += read_text(p) + "\n"

    defines = {m.group(1): int(m.group(2)) for m in RE_DEFINE_START.finditer(text)}
    magics = {m.group(1): m.group(2) for m in RE_DEFINE_MAGIC.finditer(text)}

    starts = sorted({v for k, v in defines.items()
                     if re.search(r"ASDU.*(START|POS)|(START|POS).*ASDU", k, re.I)})
    # m_StartPos=NN 这种直接赋值
    for m in re.finditer(r"m_StartPos\s*=\s*(\d+)\s*;", text):
        starts.append(int(m.group(1)))

    len_offsets = sorted({int(m.group(1)) for m in RE_LEN_READ.finditer(text)})
    chk = [(int(m.group(1)), " ".join(m.group(2).split()))
           for m in RE_CHKSUM_RANGE.finditer(text)][:4]
    len_calc = [" ".join(m.group(1).split()) for m in RE_FRAME_LEN_CALC.finditer(text)][:4]
    sockets = sorted({m.group(1) for m in RE_SOCKET_KIND.finditer(text)})

    return {
        "vendor": vdir.name,
        "asdu_start_candidates": sorted(set(starts)),
        "defines": defines,
        "magics": magics,
        "len_field_offsets": len_offsets[:10],
        "checksum_ranges": chk,
        "frame_len_expr": len_calc,
        "sockets": sockets,
        "bytes": len(text),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vendor", default=None)
    args = ap.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    vendors = ([args.vendor] if args.vendor
               else sorted(p.name for p in PROTOCOL_DIR.iterdir() if p.is_dir()))

    results = []
    for name in vendors:
        vdir = PROTOCOL_DIR / name
        if not vdir.is_dir():
            continue
        info = gather(vdir)
        if not info["sockets"] and not info["asdu_start_candidates"]:
            continue
        results.append(info)
        (OUT_DIR / f"{name}.frames.json").write_text(
            json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = ["# 网络 103 帧结构抽取", "",
             "| 厂商 | socket | ASDU 起始 | 长度字段偏移 | 校验范围 | 魔数 |",
             "|------|--------|-----------|--------------|----------|------|"]
    for r in results:
        lines.append(
            f"| {r['vendor']} | {','.join(r['sockets']) or '-'} | "
            f"{','.join(map(str, r['asdu_start_candidates'])) or '-'} | "
            f"{','.join(map(str, r['len_field_offsets'])) or '-'} | "
            f"{'; '.join(f'[{o}]={n}' for o, n in r['checksum_ranges']) or '-'} | "
            f"{','.join(f'{k}={v}' for k, v in list(r['magics'].items())[:3]) or '-'} |")
    (OUT_DIR / "FRAMES.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"vendors with network/103 info: {len(results)}")
    print(f"output: {OUT_DIR / 'FRAMES.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
