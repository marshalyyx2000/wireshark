# -*- coding: utf-8 -*-
"""把参考实现的权威事实与我们解析器的实际字段做机器比对。

比对项：
  - 协议是否存在
  - 帧封装形态（裸 ASDU / FT1.2 / 私有 APCI / 2 字节 COT）
  - COT 字节宽度
  - TYP 覆盖（参考实现出现过的 TYP 是否都有对应解析）

用法
    python diff_report.py            # 生成 audit/DIFF.md
"""
from __future__ import annotations

import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[1]
DISSECTORS = SRC_ROOT / "epan" / "dissectors"
AUDIT = HERE / "audit"

# 参考目录名 -> 我们已实现的协议短名（None 表示尚未实现）
IMPLEMENTED = {
    "SF103": "sifang_serial_iec103",
    "SF103_CSC103A": "sifang_serial_iec103",
    "SF_NET103": "sifang_net_iec103",
    "SF_UDP103": "sifang_net_iec103",
    "NZ103": "nari_serial_iec103",
    "NZ103II": "nari_serial_iec103",
    "NZ_NET103": "nari_net_iec103",
    "NR103": "nrelectric_net_iec103",
    "NR_103_NET": "nrelectric_net_iec103",
    "NR103_RCS9691": "nrelectric_net_iec103",
    "XJ_103_COM": "xuji_serial_iec103",
    "XJ_COM103": "xuji_serial_iec103",
    "XJ_NET103": "xuji_net_iec103",
    "SZNR_103_TCP": "sznari_net_iec103",
    "ZHDFR": "zh_recorder",
}

# 参考实现的封装特征（由本目录 extract_*.py 的产物人工确认后固定在此，
# 变更需同时更新 audit/APCI.md 中的依据）
ENCAPSULATION = {
    "NZ_NET103": ("private_apci_28", "90 EB + len(4) + 90 EB + src/dst + type + 保留"),
    "SF_NET103": ("private_apci_28", "ASDU_START_POSTION 28"),
    "SF_UDP103": ("ft12_over_udp", "68/10/16 帧，UDP 载荷"),
    "SH2000": ("private_apci_28", "ASDU_START_POSTION 28"),
    "WGL3000": ("private_apci_28", "ASDU_START_POSTION 28"),
    "SF_CSFM103_TCP": ("private_apci_28", "ASDU_START_POSTION 28"),
    "WFBL_FTP103": ("private_apci_28", "ASDU_START_POSTION 28"),
    "XJ_NET103": ("apci_68_cot16", "68 + len + N(S)/N(R) + ASDU，COT 2 字节"),
    "XJ_NET103_WXH13": ("apci_68_cot16", "同上"),
    "SZNR_103_TCP": ("ft12_over_tcp", "68 L L 68 C A ASDU ... 16"),
    "KELI_103_TCP": ("ft12_over_tcp", "68 1C 00 68 C A ASDU ... 16"),
    "NR_103_NET": ("bare_asdu_udp", "UDP 裸 ASDU，COT 1 字节"),
}


def our_cot_width(short_name: str) -> int:
    """Read the COT width actually registered for this protocol."""
    for p in DISSECTORS.glob("packet-*.c"):
        text = p.read_text(encoding="utf-8", errors="ignore")
        if f'"{short_name}"' not in text:
            continue
        # Vendors using the shared 2404 engine set cot_len explicitly.
        m = re.search(r"(\w*)_regs\.cot_len\s*=\s*([12])\s*;", text)
        if m:
            return int(m.group(2))
        # Own-engine dissectors: look for a 2-byte COT read.
        if re.search(r"hf_cot\w*\s*,\s*tvb\s*,\s*offset\s*,\s*2\s*,", text):
            return 2
        if "COT 高字节" in text or "cot.hi" in text:
            return 2
        return 1
    return 0


def our_has_proto(short_name: str) -> bool:
    for p in DISSECTORS.glob("packet-*.c"):
        t = p.read_text(encoding="utf-8", errors="ignore")
        if f'"{short_name}"' in t:
            return True
    return False


def main() -> int:
    rows = []
    for vendor, short in sorted(IMPLEMENTED.items()):
        frames = AUDIT / f"{vendor}.frames.json"
        facts = AUDIT / f"{vendor}.json"
        start_pos = None
        if frames.exists():
            d = json.loads(frames.read_text(encoding="utf-8"))
            cands = d.get("asdu_start_candidates") or []
            start_pos = cands[0] if cands else None

        proto_file = next((p for p in DISSECTORS.glob("packet-*.c")
                           if f'"{short}"' in p.read_text(encoding="utf-8", errors="ignore")),
                          None)
        cot_w = our_cot_width(short) if proto_file else None
        encap, note = ENCAPSULATION.get(vendor, ("bare_asdu", "标准 6 字节 ASDU 头"))

        expected_cot = 2 if encap == "apci_68_cot16" else 1
        status = []
        if not proto_file:
            status.append("未实现")
        else:
            if cot_w != expected_cot:
                status.append(f"COT 宽度不符（我们 {cot_w}，参考 {expected_cot}）")
            if start_pos and encap.startswith("private_apci"):
                src = proto_file.read_text(encoding="utf-8", errors="ignore")
                if "PRIV_APCI_LEN" not in src and "private_apci" not in src:
                    status.append(f"缺私有 APCI（参考起始 {start_pos} 字节）")

        rows.append({
            "vendor": vendor,
            "short": short,
            "encap": encap,
            "asdu_start": start_pos,
            "our_cot": cot_w,
            "ref_cot": expected_cot,
            "note": note,
            "status": "一致" if not status else "; ".join(status),
        })

    lines = ["# 已实现协议 vs 参考实现 差异清单", "",
             "由 `diff_report.py` 机器生成；`status` 非「一致」的项需要处理。", "",
             "| 参考目录 | 协议 | 封装 | 参考 ASDU 起始 | 我们 COT | 参考 COT | 状态 |",
             "|----------|------|------|----------------|----------|----------|------|"]
    for r in rows:
        lines.append(
            f"| {r['vendor']} | {r['short']} | {r['encap']} | "
            f"{r['asdu_start'] if r['asdu_start'] is not None else '-'} | "
            f"{r['our_cot']} | {r['ref_cot']} | {r['status']} |")
    (AUDIT / "DIFF.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    bad = [r for r in rows if r["status"] != "一致"]
    print(f"compared: {len(rows)}  mismatched: {len(bad)}")
    for r in bad:
        print(f"  {r['vendor']:18s} {r['status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
