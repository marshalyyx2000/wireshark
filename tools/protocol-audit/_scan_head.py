# -*- coding: utf-8 -*-
"""Scan reference sources for frame-head / APCI construction sites."""
import io
import os
import sys

ROOT = r"C:\Development\Wireshark-Industrial-Bundle-0.10.3\03-source\wireshark\tools\现场运行的各种规约程序\PROTOCOL"
KEYS = ("Set_PacketHead", "Set_Head", "MakeHead", "PacketHead", "Set_PacketTail",
        "ASDU_START", "Body_Start", "SetHead", "SendHead", "m_iHead")


def rd(p):
    return io.open(p, encoding="gbk", errors="replace").read()


for vendor in sys.argv[1:]:
    print("=" * 78)
    print(vendor)
    vd = os.path.join(ROOT, vendor)
    if not os.path.isdir(vd):
        print("  missing")
        continue
    for dp, dn, fn in os.walk(vd):
        for f in sorted(fn):
            if not f.lower().endswith((".cpp", ".h")):
                continue
            t = rd(os.path.join(dp, f))
            hits = []
            for i, l in enumerate(t.splitlines(), 1):
                if any(k in l for k in KEYS):
                    hits.append(f"    {f}:{i}: {l.strip()[:120]}")
            if hits:
                print("\n".join(hits[:25]))
