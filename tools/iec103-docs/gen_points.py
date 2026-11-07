# -*- coding: utf-8 -*-
"""Generate IEC103 vendor point tables (CSV) from the DL/T 667 baseline.

Columns: vendor,fun,inf,name,asdu,datatype,unit,source,note
  source: std = DL/T 667 compatible range, public = stated in public vendor doc,
          inferred = vendor-specific mapping deduced from public captures/docs.
Run: python tools/iec103-docs/gen_points.py
"""
from __future__ import annotations

import csv
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUT = ROOT / "resources" / "share" / "wireshark" / "iec103" / "points"

HDR = ["vendor", "fun", "inf", "name", "asdu", "datatype", "unit", "source", "note"]

# DL/T 667 compatible-range baseline shared by all vendors.
GLOBAL_STD = [
    (255, 0, "通用分类功能类型", 10, "GIN", "", "std", "组标识符"),
    (255, 1, "时间同步", 6, "CP56", "", "std", ""),
    (255, 2, "总查询启动", 7, "NONE", "", "std", ""),
    (255, 3, "总查询终止", 8, "NONE", "", "std", ""),
    (255, 4, "装置复位/初始化", 5, "COL", "", "std", ""),
    (255, 5, "信号复归", 20, "RII", "", "std", ""),
    (255, 16, "一般命令(遥控)", 20, "DCO", "", "std", ""),
    (255, 19, "扰动数据传输命令", 24, "TOO", "", "std", ""),
    (255, 20, "扰动数据传输认可", 25, "TOO", "", "std", ""),
    (255, 23, "被记录的扰动表", 23, "SOF", "", "std", ""),
    (255, 24, "扰动数据传输准备就绪", 26, "TOV", "", "std", ""),
    (255, 25, "通道传输准备就绪", 27, "ACC", "", "std", ""),
    (255, 26, "带标志状态变位准备就绪", 28, "FAN", "", "std", ""),
    (255, 27, "传送带标志的状态变位", 29, "TAP", "", "std", ""),
    (255, 28, "传输扰动值", 30, "SDV", "", "std", ""),
    (255, 31, "传送结束", 31, "TOO", "", "std", ""),
]

PROTECTION_STD = [
    (128, 16, "距离I段动作", 2, "DPI", "", "std", "距离保护"),
    (128, 17, "距离II段动作", 2, "DPI", "", "std", "距离保护"),
    (128, 18, "距离III段动作", 2, "DPI", "", "std", "距离保护"),
    (128, 19, "距离加速动作", 2, "DPI", "", "std", "距离保护"),
    (128, 20, "距离保护启动", 2, "DPI", "", "std", "距离保护"),
    (128, 21, "距离保护返回", 2, "DPI", "", "std", "距离保护"),
    (160, 16, "过流I段动作", 2, "DPI", "", "std", "过流保护"),
    (160, 17, "过流II段动作", 2, "DPI", "", "std", "过流保护"),
    (160, 18, "过流III段动作", 2, "DPI", "", "std", "过流保护"),
    (160, 19, "过流加速动作", 2, "DPI", "", "std", "过流保护"),
    (160, 20, "过流保护启动", 2, "DPI", "", "std", "过流保护"),
    (160, 21, "过流保护返回", 2, "DPI", "", "std", "过流保护"),
    (160, 22, "零序过流动作", 2, "DPI", "", "std", "过流保护"),
    (160, 23, "负序过流动作", 2, "DPI", "", "std", "过流保护"),
    (176, 16, "差动速断动作", 2, "DPI", "", "std", "变压器差动"),
    (176, 17, "比率差动动作", 2, "DPI", "", "std", "变压器差动"),
    (176, 18, "差流越限告警", 1, "DPI", "", "std", "变压器差动"),
    (176, 19, "二次谐波闭锁", 1, "DPI", "", "std", "变压器差动"),
    (176, 20, "差动保护启动", 2, "DPI", "", "std", "变压器差动"),
    (192, 16, "线路差动动作", 2, "DPI", "", "std", "线路差动"),
    (192, 17, "线路差动启动", 2, "DPI", "", "std", "线路差动"),
    (192, 18, "线路差动告警", 1, "DPI", "", "std", "线路差动"),
]

COMMON_MEAS = [
    (254, 1, "定值组", 10, "GIN", "", "std", "通用分类"),
    (254, 2, "测量值组", 10, "GIN", "", "std", "通用分类"),
    (254, 3, "软压板/控制字组", 10, "GIN", "", "std", "通用分类"),
    (254, 4, "动作事件组", 10, "GIN", "", "std", "通用分类"),
    (254, 5, "告警组", 10, "GIN", "", "std", "通用分类"),
]

# Vendor-specific additions: (fun, inf, name, asdu, datatype, unit, source, note)
SIFANG = [
    (254, 10, "保护定值区号", 10, "UI", "", "inferred", "四方定值区"),
    (254, 11, "保护定值校验码", 10, "UI", "", "inferred", ""),
    (254, 12, "软压板投退状态", 10, "BS1", "", "inferred", "控制字"),
    (254, 13, "测量值Ia", 10, "R32", "A", "inferred", "一次值×RFA=二次值"),
    (254, 14, "测量值Ib", 10, "R32", "A", "inferred", ""),
    (254, 15, "测量值Ic", 10, "R32", "A", "inferred", ""),
    (254, 16, "短路位置", 10, "R32", "Ω", "public", "SCL"),
    (254, 17, "故障电流", 10, "R32", "A", "inferred", ""),
    (255, 32, "扰动数据传输结束", 31, "TOO", "", "public", "TOO 32-40"),
    (255, 64, "扰动数据传输认可(肯定)", 25, "TOO", "", "public", "TOO 64-69"),
    (255, 65, "扰动数据传输不认可(否定)", 25, "TOO", "", "public", ""),
]

SZNARI = [
    (254, 20, "定值区号", 10, "UI", "", "inferred", "深圳所定值"),
    (254, 21, "定值组标题", 10, "OS8", "", "inferred", ""),
    (254, 22, "测量值Ua", 10, "R32", "V", "inferred", ""),
    (254, 23, "测量值Ub", 10, "R32", "V", "inferred", ""),
    (254, 24, "测量值Uc", 10, "R32", "V", "inferred", ""),
    (254, 25, "测量值P", 10, "R32", "W", "inferred", ""),
    (254, 26, "测量值Q", 10, "R32", "var", "inferred", ""),
    (254, 27, "软压板组", 10, "BS1", "", "inferred", "控制字"),
    (255, 6, "初始化完成", 5, "COL", "", "public", "标识 ASDU5"),
    (255, 17, "召唤历史信息", 17, "NONE", "", "inferred", "南自系扩展"),
]

NRElectric = [
    (254, 30, "定值区号", 10, "UI", "", "inferred", "继保南瑞定值"),
    (254, 31, "定值项", 10, "R32", "", "inferred", ""),
    (254, 32, "测量值Ia", 10, "R32", "A", "inferred", ""),
    (254, 33, "测量值Ib", 10, "R32", "A", "inferred", ""),
    (254, 34, "测量值Ic", 10, "R32", "A", "inferred", ""),
    (254, 35, "开关位置", 10, "DPI", "", "inferred", ""),
    (254, 36, "系统状态字", 10, "BS1", "", "public", "系统状态字更新版"),
]

NARI = [
    (254, 40, "定值组", 10, "GIN", "", "inferred", "南自通用分类"),
    (254, 41, "测量值组", 10, "GIN", "", "inferred", ""),
    (254, 42, "软压板组", 10, "GIN", "", "inferred", ""),
    (254, 43, "扩展远动测量", 10, "R32", "", "public", "扩展远动测量组"),
    (255, 34, "召唤历史信息", 17, "NONE", "", "public", "ASDU17"),
]

# 金智 应用层规范 4.x 通用分类组（GIN 组号，条目 00 为组标题）
JINZHI = [
    (254, 1,  "装置描述组", 10, "GIN", "", "public", "4.1"),
    (254, 2,  "装置参数组", 10, "GIN", "", "public", "4.2"),
    (254, 3,  "定值区号组", 10, "GIN", "", "public", "4.3"),
    (254, 4,  "定值组", 10, "GIN", "", "public", "4.4"),
    (254, 5,  "动作元件", 10, "GIN", "", "public", "4.5 主动上送"),
    (254, 6,  "装置自检", 10, "GIN", "", "public", "4.6 主动上送"),
    (254, 7,  "运行告警", 10, "GIN", "", "public", "4.7 主动上送"),
    (254, 8,  "软压板", 10, "GIN", "", "public", "4.8 主动上送"),
    (254, 9,  "硬压板", 10, "GIN", "", "public", "4.9 主动上送"),
    (254, 10, "遥信", 10, "GIN", "", "public", "4.10 主动上送"),
    (254, 11, "保护测量", 10, "GIN", "", "public", "4.20 定时上送"),
    (254, 12, "遥测", 10, "GIN", "", "public", "4.11 定时上送"),
    (254, 13, "遥脉", 10, "GIN", "", "public", "4.12"),
    (254, 14, "遥控", 10, "GIN", "", "public", "4.13"),
    (254, 15, "遥调", 10, "GIN", "", "public", "4.14"),
    (254, 16, "档位", 10, "GIN", "", "public", "4.15 主动上送"),
    (254, 17, "故障信息", 10, "GIN", "", "public", "4.16 主动上送"),
    (254, 18, "扰动数据说明", 10, "GIN", "", "public", "4.17"),
    (254, 19, "操作信息", 10, "GIN", "", "public", "4.18 主动上送"),
    (254, 20, "制造商专用信息", 10, "GIN", "", "public", "4.19"),
    (254, 21, "接地选线数据", 10, "GIN", "", "public", "4.21"),
    (254, 22, "接地试跳", 10, "GIN", "", "public", "4.22"),
    (254, 23, "顺控操作信息", 10, "GIN", "", "public", "主动上送"),
    (254, 240, "读所有组标题", 10, "GIN", "", "public", "INF F0"),
    (254, 241, "读一个组全部条目", 10, "GIN", "", "public", "INF F1"),
    (254, 244, "遥控校验", 10, "GIN", "", "public", "ASDU228/229"),
]

# 积成 IES-N103 通用分类与召唤
JICHENG = [
    (254, 230, "召唤", 21, "GIN", "", "public", "INF E6"),
    (254, 240, "读所有组标题", 21, "GIN", "", "public", "读命令 COT=42"),
    (254, 241, "读一个组全部条目", 21, "GIN", "", "public", "读命令 COT=42"),
    (254, 242, "读单个条目", 21, "GIN", "", "public", "读命令 COT=42"),
    (254, 1, "装置描述组", 10, "GIN", "", "public", "通用分类"),
    (254, 2, "装置参数组", 10, "GIN", "", "public", "通用分类"),
    (254, 3, "定值区号", 10, "GIN", "", "public", "通用分类"),
    (254, 4, "定值组", 10, "GIN", "", "public", "通用分类"),
    (254, 9, "保护测量值", 10, "GIN", "", "public", "报文示例 组号09"),
    (254, 10, "遥测组", 10, "GIN", "", "public", "通用分类"),
    (254, 11, "遥信组", 10, "GIN", "", "public", "通用分类"),
]

VENDORS = {
    "sifang": SIFANG,
    "sznari": SZNARI,
    "nrelectric": NRElectric,
    "nari": NARI,
    "jinzhi": JINZHI,
    "jicheng": JICHENG,
}


def rows_for(vendor: str):
    seen = set()
    out = []
    # Vendor-specific rows come before the generic classification baseline so a
    # vendor's own FUN/INF meaning wins over the shared "定值组/测量值组" rows.
    for fun, inf, name, asdu, dt, unit, src, note in (
        GLOBAL_STD + PROTECTION_STD + VENDORS[vendor] + COMMON_MEAS
    ):
        key = (fun, inf)
        if key in seen:
            continue
        seen.add(key)
        out.append([vendor, fun, inf, name, asdu, dt, unit, src, note])
    return out


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    for vendor in VENDORS:
        path = OUT / f"{vendor}.csv"
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh, lineterminator="\n")
            w.writerow(HDR)
            w.writerows(rows_for(vendor))
        print(f"{path.relative_to(ROOT)}: {len(rows_for(vendor))} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
