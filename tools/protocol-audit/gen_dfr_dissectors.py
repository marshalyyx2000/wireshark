# -*- coding: utf-8 -*-
"""从 dfr-spec.json 生成录波器厂家解析器（复用 packet-iec103-dfr-common.c）。

用法
    python gen_dfr_dissectors.py --dry-run
    python gen_dfr_dissectors.py
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[1]
DISSECTORS = SRC_ROOT / "epan" / "dissectors"
SPEC = HERE / "dfr-spec.json"

TEMPLATE = """/* packet-{short}.c
 *
 * {display}
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/{vendor_dir} .
 * Frame layout and command table live in packet-iec103-dfr-common.c.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-dfr-common.h"

void proto_register_{short}(void);
void proto_reg_handoff_{short}(void);

static int proto_{short};
{handles}
static dfr_vendor_profile_t {short}_profile = {{
\t0,
\t"{col}",
\t"{unknown}",
\tNULL,
\tNULL,
\tfalse,
\tNULL
}};
{body}
void
proto_register_{short}(void)
{{
\tproto_{short} = proto_register_protocol(
\t\t"{display}",
\t\t"{short_display}",
\t\t"{short}");

\t{short}_profile.proto = proto_{short};
{register}

\tdfr_common_register(&{short}_profile);
\tprefs_register_protocol(proto_{short}, NULL);
}}

void
proto_reg_handoff_{short}(void)
{{
\t/* Neutral capture policy: no port binding, the 录波器规约 menu applies
\t * Decode As at runtime. */
{handoff}}}
"""

TCP_BODY = """
static int
dissect_{short}_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{{
\treturn dfr_dissect_stream(tvb, pinfo, tree, &{short}_profile);
}}

static int
dissect_{short}_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{{
\treturn dfr_dissect_datagram(tvb, pinfo, tree, &{short}_profile);
}}
"""

TCP_HANDLES = ("static dissector_handle_t {short}_tcp_handle;\n"
               "static dissector_handle_t {short}_udp_handle;\n")

TCP_REGISTER = ("\t{short}_tcp_handle = register_dissector(\"{short}\", dissect_{short}_tcp,\n"
                "\t\tproto_{short});\n"
                "\t{short}_udp_handle = register_dissector(\"{short}_udp\", dissect_{short}_udp,\n"
                "\t\tproto_{short});\n")

TCP_HANDOFF = ("\tdissector_add_for_decode_as(\"tcp.port\", {short}_tcp_handle);\n"
               "\tdissector_add_for_decode_as(\"udp.port\", {short}_udp_handle);\n")

SERIAL_BODY = """
static int
dissect_{short}(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{{
\treturn dfr_dissect_datagram(tvb, pinfo, tree, &{short}_profile);
}}
"""

SERIAL_HANDLES = "static dissector_handle_t {short}_handle;\n"
SERIAL_REGISTER = ("\t{short}_handle = register_dissector(\"{short}\", dissect_{short},\n"
                   "\t\tproto_{short});\n")
SERIAL_HANDOFF = ("\t/* Registered by name only: the 录波器规约 serial entry forces this\n"
                  "\t * dissector onto neutral serial_raw payloads. */\n")


def render(vendor: dict) -> str:
    short = vendor["short"]
    col = vendor["display"]
    unknown = vendor["short_display"]
    if vendor["transport"] == "tcp_udp":
        body, handles, register, handoff = (
            TCP_BODY, TCP_HANDLES, TCP_REGISTER, TCP_HANDOFF)
    else:
        body, handles, register, handoff = (
            SERIAL_BODY, SERIAL_HANDLES, SERIAL_REGISTER, SERIAL_HANDOFF)
    return TEMPLATE.format(
        short=short,
        display=col,
        short_display=vendor["short_display"],
        vendor_dir=vendor["vendor_dir"],
        col=col,
        unknown=unknown,
        body=body.format(short=short),
        handles=handles.format(short=short),
        register=register.format(short=short),
        handoff=handoff.format(short=short),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    spec = json.loads(SPEC.read_text(encoding="utf-8"))
    created = 0
    for vendor in spec["vendors"]:
        path = DISSECTORS / f"packet-{vendor['short']}.c"
        if path.exists() and vendor["short"] == "nfdfr":
            print(f"skip hand-written {path.name}")
            continue
        text = render(vendor)
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
