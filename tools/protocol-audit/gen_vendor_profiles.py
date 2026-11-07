# -*- coding: utf-8 -*-
"""按模板生成 103 家族厂商 profile 源文件。

每个文件只有 ~50 行：填写厂商名、协议短名、点表 key、COT 扩展表，其余全部复用
packet-iec103-vendor-common.c 的引擎。生成前会检查目标文件不存在，避免覆盖手工改动。

用法
    python gen_vendor_profiles.py --dry-run
    python gen_vendor_profiles.py
"""
from __future__ import annotations

import argparse
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[1]
DISSECTORS = SRC_ROOT / "epan" / "dissectors"

TEMPLATE = '''/* {filename}
 *
 * {display} {transport_desc}
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/{vendor} .
 * Framing and ASDU layout reuse packet-iec103-vendor-common.c; this file only
 * supplies the vendor identity and its extra TYP/COT names.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-vendor-common.h"

void proto_register_{short}(void);
void proto_reg_handoff_{short}(void);

static int proto_{short};

static iec103_vendor_profile_t {short}_profile = {{
\t0,
\t"{col_protocol}",
\t{singleton},
\t"{display}",
\t{points},
\t{extra_typ},
\t{extra_cot},
\tNULL
}};

static int
dissect_{short}(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{{
\treturn {dispatch}(tvb, pinfo, tree, &{short}_profile);
}}

void
proto_register_{short}(void)
{{
\tproto_{short} = proto_register_protocol(
\t\t"{display}",
\t\t"{short_display}",
\t\t"{short}");

\t{short}_profile.proto = proto_{short};

\tregister_dissector("{short}", dissect_{short}, proto_{short});

\tiec103_vendor_register(&{short}_profile);
\tiec103_vendor_register_prefs(prefs_register_protocol(proto_{short}, NULL),
\t\t"{display}");
}}

void
proto_reg_handoff_{short}(void)
{{
\t{handoff}
\tiec103_points_init();
}}
'''

SERIAL_HANDOFF = "/* Registered by name only: the 串口103 menu forces this dissector\n\t * onto neutral serial_raw payloads via serial_raw.payload_dissector. */"
NET_HANDOFF = ('/* Neutral capture policy: no port binding. The 网络103 menu applies\n'
               '\t * Decode As for this vendor\'s documented port. */\n'
               '\t dissector_add_for_decode_as("tcp.port", {short}_handle);')


def handoff_block(short: str, transport: str) -> str:
    if transport == "serial":
        return SERIAL_HANDOFF
    return NET_HANDOFF.replace("{short}", short)


# vendor 目录名, 协议短名, 中文显示, 简称, transport, 点表, 说明
VENDORS = [
    ("NR103_RCS9691", "nr103_rcs9691_serial_iec103", "南瑞 RCS-9691 串口103",
     "南瑞RCS9691串口103", "serial", "IEC103_POINTS_NARI", "FT1.2 串口"),
    ("XJ_103_COM", "xj103_com_serial_iec103", "许继串口103(XJ_103_COM)",
     "许继串口103(XJ_103_COM)", "serial", "IEC103_POINTS_SIFANG", "FT1.2 串口"),
    ("XJ_COM103", "xj_com103_serial_iec103", "许继串口103(XJ_COM103)",
     "许继串口103(XJ_COM103)", "serial", "IEC103_POINTS_SIFANG", "FT1.2 串口"),
    ("XJ_NET103_WXH13", "xj_net103_wxh13", "许继网络103(WXH13)",
     "许继网络103(WXH13)", "net", "IEC103_POINTS_SIFANG", "68 帧 + 2 字节 COT"),
    ("NZ103II", "nz103ii_serial_iec103", "南自串口103(II)",
     "南自串口103(II)", "serial", "IEC103_POINTS_NARI", "FT1.2 串口"),
    ("SF103_CSC103A", "sf103_csc103a_serial_iec103", "四方 CSC-103A 串口103",
     "四方CSC103A串口103", "serial", "IEC103_POINTS_SIFANG", "FT1.2 串口"),
    ("SF_NET103", "sf_net103_tcp", "四方网络103(TCP)",
     "四方网络103(TCP)", "net", "IEC103_POINTS_SIFANG", "28 字节传输头"),
    ("KELI_103_TCP", "keli_103_tcp", "开利网络103",
     "开利网络103", "net", "IEC103_POINTS_SIFANG", "FT1.2 帧承载于 TCP"),
]


def build(vendor: str, short: str, display: str, short_display: str,
          transport: str, points: str, transport_desc: str) -> tuple[Path, str]:
    filename = f"packet-{short}.c"
    dispatch = ("iec103_vendor_dissect_ft12" if transport == "serial"
                else "iec103_vendor_dissect_asdu_stream")
    text = TEMPLATE.format(
        filename=filename,
        vendor=vendor,
        display=display,
        short=short,
        short_display=short_display,
        col_protocol=display,
        singleton="NULL" if transport != "serial" else '"单字符 E5"',
        points=points,
        extra_typ="NULL",
        extra_cot="NULL",
        dispatch=dispatch,
        transport_desc=transport_desc,
        handoff=handoff_block(short, transport),
    )
    return DISSECTORS / filename, text


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    created = 0
    for vendor, short, display, short_display, transport, points, desc in VENDORS:
        path, text = build(vendor, short, display, short_display, transport, points, desc)
        if path.exists():
            print(f"skip existing {path.name}")
            continue
        if args.dry_run:
            print(f"would create {path.name} ({len(text)} bytes)")
        else:
            path.write_text(text, encoding="utf-8")
            print(f"created {path.name}")
        created += 1
    print(f"total: {created}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
