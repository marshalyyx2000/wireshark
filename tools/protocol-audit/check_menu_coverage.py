# -*- coding: utf-8 -*-
"""核对每个已实现协议是否在 GUI 菜单/对话框中可达。"""
import io
import json
import re
from pathlib import Path

ROOT = Path(r"C:\Development\Wireshark-Industrial-Bundle-0.10.3\03-source\wireshark")
DISS = ROOT / "epan" / "dissectors"
UI = ROOT / "ui" / "qt"

specs = ["vendor-spec.json", "dfr-spec.json", "generic-spec.json"]
implemented = {}
for spec in specs:
    data = json.loads((ROOT / "tools" / "protocol-audit" / spec).read_text(encoding="utf-8"))
    for v in data["vendors"]:
        implemented[v["short"]] = spec

# 手写解析器（不在 spec 里）：只统计本项目的协议，排除 Wireshark 自带的
OWN_PREFIXES = ("iec103", "recorder", "modbus_protection", "ge_modbus", "ge_mlink",
                "ge_modem", "dfr", "zh_", "yushun")
OWN_SUFFIXES = ("_iec103", "_recorder", "_dfr")


def is_ours(name: str) -> bool:
    if name in implemented:
        return True
    if any(name.startswith(p) for p in OWN_PREFIXES):
        return True
    if any(name.endswith(s) for s in OWN_SUFFIXES):
        return True
    # generic-spec 里的短名已在 implemented；其余跳过
    return False


for p in DISS.glob("packet-*.c"):
    text = p.read_text(encoding="utf-8", errors="ignore")
    if "toolbar" in p.name or not any(k in text for k in
                                      ("iec103", "dfr_", "modbus_vendor", "vgf_")):
        continue
    for m in re.finditer(r'register_dissector\("([a-z0-9_]+)"', text):
        name = m.group(1)
        if is_ours(name):
            implemented.setdefault(name, "hand-written")

slots = (UI / "wireshark_main_window_slots.cpp").read_text(encoding="utf-8", errors="ignore")
dialog = (UI / "vendor_recipe_dialog.cpp").read_text(encoding="utf-8", errors="ignore")

print(f"{'protocol':32s} source           in_slots  in_dialog")
missing = []
# iec103_asdu6 是给串口 FT1.2 复用的内部 ASDU handle，不是用户可选协议。
INTERNAL = {"iec103_asdu6"}
for name in sorted(implemented):
    if name in INTERNAL:
        continue
    in_slots = f'"{name}"' in slots
    in_dialog = f'"{name}"' in dialog
    flag = "" if (in_slots or in_dialog) else "  <-- 无入口"
    if not (in_slots or in_dialog):
        missing.append(name)
    print(f"{name:32s} {implemented[name]:16s} {str(in_slots):8s}  {str(in_dialog):9s}{flag}")

print(f"\n共 {len(implemented) - len(INTERNAL)} 个可选协议，{len(missing)} 个无入口")
if missing:
    for m in missing:
        print("  ", m)
