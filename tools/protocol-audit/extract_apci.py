# -*- coding: utf-8 -*-
"""抽取每个厂商的私有 APCI 头部布局（逐字节），用于与解析器比对。

识别手法：在 `*Packet*.cpp` / `Net*.cpp` 里查找连续 `buf[i++] = 0xNN` 或
`buf[i++] = <expr>` 的序列，并保留注释，形成可读的字节表。

用法
    python extract_apci.py
    python extract_apci.py --vendor NZ_NET103
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

RE_ASSIGN = re.compile(
    r"(?:buf|pbuf|m_pSendBuff->buf|m_pRead->buf)\s*\[\s*i\+\+\s*\]\s*=\s*"
    r"([^;]{1,90});\s*(?://\s*([^\n]{0,60}))?")


def read_text(path: Path) -> str:
    for enc in ("gbk", "utf-8", "latin-1"):
        try:
            return path.read_text(encoding=enc, errors="ignore")
        except OSError:
            return ""
    return ""


def best_run(text: str) -> list:
    """找出最长的一段连续赋值，作为头部构造。"""
    runs, cur = [], []
    last_end = None
    for m in RE_ASSIGN.finditer(text):
        if last_end is not None and m.start() - last_end > 220:
            if len(cur) >= 4:
                runs.append(cur)
            cur = []
        expr = " ".join(m.group(1).split())
        comment = (m.group(2) or "").strip()
        cur.append({"expr": expr, "comment": comment})
        last_end = m.end()
    if len(cur) >= 4:
        runs.append(cur)
    runs.sort(key=len, reverse=True)
    return runs[0] if runs else []


def gather(vdir: Path) -> dict | None:
    best = []
    best_file = None
    for root, _dirs, names in os.walk(vdir):
        for name in names:
            p = Path(root) / name
            if p.suffix.lower() != ".cpp":
                continue
            run = best_run(read_text(p))
            if len(run) > len(best):
                best = run
                best_file = p.name
    if len(best) < 4:
        return None
    return {
        "vendor": vdir.name,
        "file": best_file,
        "header_bytes": len(best),
        "layout": [f"{i:02d}: {b['expr']}" + (f"   // {b['comment']}" if b["comment"] else "")
                   for i, b in enumerate(best)],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--vendor", default=None)
    args = ap.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    vendors = ([args.vendor] if args.vendor
               else sorted(p.name for p in PROTOCOL_DIR.iterdir() if p.is_dir()))

    found = []
    for name in vendors:
        vdir = PROTOCOL_DIR / name
        if not vdir.is_dir():
            continue
        info = gather(vdir)
        if info:
            found.append(info)
            (OUT_DIR / f"{name}.apci.json").write_text(
                json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")

    lines = ["# 私有 APCI 头部抽取", "",
             "每个厂商连续 `buf[i++]` 赋值序列，长度即推断出的头部字节数。", ""]
    for f in found:
        lines.append(f"## {f['vendor']}  ({f['header_bytes']} 字节, 来自 {f['file']})")
        lines.append("```")
        lines.extend(f["layout"])
        lines.append("```")
    (OUT_DIR / "APCI.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"vendors with header layout: {len(found)}")
    for f in sorted(found, key=lambda x: -x["header_bytes"])[:12]:
        print(f"  {f['vendor']:24s} {f['header_bytes']:2d} bytes  ({f['file']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
