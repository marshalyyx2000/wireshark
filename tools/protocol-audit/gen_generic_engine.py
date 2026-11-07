# -*- coding: utf-8 -*-
"""从 generic-spec.json 生成声明式帧解析器（复用 packet-vendor-generic-frame.c）。

用法
    python gen_generic_engine.py --dry-run
    python gen_generic_engine.py
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC_ROOT = HERE.parents[1]
DISSECTORS = SRC_ROOT / "epan" / "dissectors"
SPEC = HERE / "generic-spec.json"

TEMPLATE = """/* packet-{short}.c
 *
 * {display}
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/{vendor_dir} .
 * {note}
 * Frame synchronisation, length and checksum come from
 * packet-vendor-generic-frame.c; the body is vendor-defined and stays as bytes
 * because the reference implementation carries no field semantics for it.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-vendor-generic-frame.h"

void proto_register_{short}(void);
void proto_reg_handoff_{short}(void);

static int proto_{short};
static dissector_handle_t {short}_handle;

static const uint8_t {short}_sig[{sig_alloc}] = {{ {sig_bytes} }};

static vgf_profile_t {short}_profile = {{
\t0,
\t"{display}",
\t"{note}",
\t{carrier},
\t{sig_count}, {{ {sig_pad} }},
\t	{len_off}, {len_size}, {len_be}, {len_bias}, {min_len}, {max_len}, {fixed_len},
\t{addr_off}, {addr_size}, {cmd_off},
\t	{crc}, {crc_tail}, {crc_off}, {ascii_line}, {crc_tail_extra}, {crc_tail_byte},
\tNULL
}};

static int
dissect_{short}(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{{
\treturn vgf_dissect(tvb, pinfo, tree, (void *)&{short}_profile);
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
\tvgf_register(&{short}_profile);
}}

void
proto_reg_handoff_{short}(void)
{{
\t/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
{handoff}}}
"""

CARRIER = {
    "serial": "VGF_CARRIER_SERIAL",
    "tcp": "VGF_CARRIER_TCP",
    "udp": "VGF_CARRIER_UDP",
}

CRC = {
    "none": "VGF_CRC_NONE",
    "sum8": "VGF_CRC_SUM8",
    "sum8_low": "VGF_CRC_SUM8_LOW",
    "modbus16": "VGF_CRC_MODBUS16",
}

HANDOFF = {
    "serial": ("\t/* Registered by name only: the menu forces this dissector onto neutral\n"
               "\t * serial_raw payloads. */\n"),
    "tcp": "\tdissector_add_for_decode_as(\"tcp.port\", {short}_handle);\n",
    "udp": "\tdissector_add_for_decode_as(\"udp.port\", {short}_handle);\n",
}


def render(v: dict) -> str:
    short = v["short"]
    sig = bytes.fromhex(v["sig"]) if v["sig"] else b""
    sig_bytes = ", ".join(f"0x{b:02X}" for b in sig) or "0x00"
    sig_pad = (sig_bytes + ", 0x00" * (6 - len(sig))) if sig else "0x00"
    return TEMPLATE.format(
        short=short,
        display=v["display"],
        short_display=v["short_display"],
        vendor_dir=v["vendor_dir"],
        note=v["note"],
        carrier=CARRIER[v["carrier"]],
        sig_alloc=max(1, len(sig)),
        sig_count=len(sig),
        sig_bytes=sig_bytes,
        sig_pad=sig_pad,
        len_off=v["len_off"],
        len_size=v["len_size"],
        len_be="true" if v["len_be"] else "false",
        len_bias=v["len_bias"],
        min_len=v["min_len"],
        max_len=v["max_len"],
        fixed_len=v.get("fixed_len", 0),
        addr_off=v["addr_off"],
        addr_size=v["addr_size"],
        cmd_off=v["cmd_off"],
        crc=CRC[v["crc"]],
        crc_tail=v["crc_tail"],
        crc_off=v.get("crc_off", 0),
        ascii_line="true" if v.get("ascii_line") else "false",
        crc_tail_extra=v.get("crc_tail_extra", 0),
        crc_tail_byte=v.get("crc_tail_byte", 0),
        handoff=HANDOFF[v["carrier"]].format(short=short),
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    spec = json.loads(SPEC.read_text(encoding="utf-8"))
    created = 0
    for v in spec["vendors"]:
        path = DISSECTORS / f"packet-{v['short']}.c"
        text = render(v)
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
