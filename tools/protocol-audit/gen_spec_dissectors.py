# -*- coding: utf-8 -*-
"""从 vendor-spec.json 生成厂商解析器 C 源文件。

每个生成文件只含一份 iec103_vendor_profile_t 表项 + 承载入口，帧/ASDU 解析全部
复用 packet-iec103-vendor-common.c。

用法
    python gen_spec_dissectors.py --dry-run
    python gen_spec_dissectors.py
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[1]
DISSECTORS = SRC_ROOT / "epan" / "dissectors"
SPEC = HERE / "vendor-spec.json"

HEADER = """/* packet-{short}.c
 *
 * {display}
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/{vendor_dir} .
 * Framing and ASDU layout reuse packet-iec103-vendor-common.c; this file only
 * supplies the vendor identity, its carrier and its private APCI.
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
static dissector_handle_t {short}_handle;
"""

APCI_DESC = """
/* {label} */
static const iec103_apci_desc_t {short}_apci = {{
\t"{label}",
\t{hdr_len}, {len_off}, {len_size}, {len_bias}, {len_be},
\t{sig_count},
\t{{ {sig_offs} }},
\t{{ {sig_vals} }}
}};
"""

PROFILE = """
static iec103_vendor_profile_t {short}_profile = {{
\t0,                              /* proto, filled in at registration */
\t"{display}",                    /* COL_PROTOCOL */
\t{single_char},
\t"{display}",                    /* unknown-ASDU expert prefix */
\tIEC103_POINTS_{points},
\tNULL,                           /* extra_asdu_types */
\tNULL,                           /* extra_cot */
\tNULL,                           /* dissect_extra_asdu */
\t{cot_len},
\t{ft12_len16le},
\t{ft12_addr_len},
\t{apci_ref}
}};
"""

DISPATCH = {
    "serial_ft12": "iec103_vendor_dissect_ft12",
    "tcp_ft12": "iec103_vendor_dissect_ft12_stream",
    "udp_ft12": "iec103_vendor_dissect_ft12_datagram",
    "tcp_apci": "iec103_vendor_dissect_asdu_stream",
    "udp_apci": "iec103_vendor_dissect_asdu_datagram",
    "tcp_asdu": "iec103_vendor_dissect_asdu_stream",
    "udp_asdu": "iec103_vendor_dissect_asdu_datagram",
}

HANDOFF = {
    "serial_ft12": (
        '\t/* Registered by name only: the 串口103 menu forces this dissector onto\n'
        '\t * neutral serial_raw payloads via serial_raw.payload_dissector. */\n'),
    "tcp_ft12": (
        '\t/* Neutral capture policy: no port binding. The 网络103 menu applies\n'
        '\t * Decode As for this vendor\'s documented port. */\n'
        '\tdissector_add_for_decode_as("tcp.port", {short}_handle);\n'),
    "tcp_apci": (
        '\t/* Neutral capture policy: no port binding. The 网络103 menu applies\n'
        '\t * Decode As for this vendor\'s documented port. */\n'
        '\tdissector_add_for_decode_as("tcp.port", {short}_handle);\n'),
    "tcp_asdu": (
        '\t/* Neutral capture policy: no port binding. The 网络103 menu applies\n'
        '\t * Decode As for this vendor\'s documented port. */\n'
        '\tdissector_add_for_decode_as("tcp.port", {short}_handle);\n'),
    "udp_ft12": (
        '\t/* Neutral capture policy: no port binding. */\n'
        '\tdissector_add_for_decode_as("udp.port", {short}_handle);\n'),
    "udp_apci": (
        '\t/* Neutral capture policy: no port binding. */\n'
        '\tdissector_add_for_decode_as("udp.port", {short}_handle);\n'),
    "udp_asdu": (
        '\t/* Neutral capture policy: no port binding. */\n'
        '\tdissector_add_for_decode_as("udp.port", {short}_handle);\n'),
}

BODY = """
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

\t{short}_handle = register_dissector("{short}", dissect_{short}, proto_{short});

\tiec103_vendor_register(&{short}_profile);
\tiec103_vendor_register_prefs(prefs_register_protocol(proto_{short}, NULL),
\t\t"{display}");
}}

void
proto_reg_handoff_{short}(void)
{{
{handoff}\tiec103_points_init();
}}
"""


def load_spec() -> dict:
    return json.loads(SPEC.read_text(encoding="utf-8"))


def render(vendor: dict, apci_defs: dict) -> str:
    short = vendor["short"]
    out = [HEADER.format(short=short, display=vendor["display"],
                         vendor_dir=vendor["vendor_dir"])]

    apci_ref = "NULL"
    apci_name = vendor.get("apci")
    if apci_name:
        d = apci_defs[apci_name]
        sig = d["sig"]
        pad = len("<IEC103_APCI_MAX_SIG>")
        offs = ", ".join(str(p[0]) for p in sig)
        vals = ", ".join(f"0x{p[1]:02X}" for p in sig)
        out.append(APCI_DESC.format(
            short=short,
            label=d["label"],
            hdr_len=d["hdr_len"],
            len_off=d["len_off"],
            len_size=d["len_size"],
            len_bias=d["len_bias"],
            len_be="true" if d["len_be"] else "false",
            sig_count=len(sig),
            sig_offs=offs,
            sig_vals=vals,
        ))
        apci_ref = f"&{short}_apci"
        _ = pad

    out.append(PROFILE.format(
        short=short,
        display=vendor["display"],
        single_char=('"单字符 E5"' if vendor["transport"].startswith("serial")
                     else "NULL"),
        points=vendor["points"],
        cot_len=vendor.get("cot_len", 1),
        ft12_len16le=vendor.get("ft12_len16le", 0),
        ft12_addr_len=vendor.get("ft12_addr_len", 1),
        apci_ref=apci_ref,
    ))

    out.append(BODY.format(
        short=short,
        display=vendor["display"],
        short_display=vendor["short_display"],
        dispatch=DISPATCH[vendor["transport"]],
        handoff=HANDOFF[vendor["transport"]].format(short=short),
    ))
    return "".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    spec = load_spec()
    created = 0
    for vendor in spec["vendors"]:
        path = DISSECTORS / f"packet-{vendor['short']}.c"
        text = render(vendor, spec["apci"])
        if args.dry_run:
            print(f"would write {path.name} ({len(text)} bytes)")
            continue
        path.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {path.name}")
        created += 1
    print(f"total: {created}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
