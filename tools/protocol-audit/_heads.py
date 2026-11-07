# -*- coding: utf-8 -*-
"""Extract the literal frame-head bytes each vendor writes into its send buffer."""
import io
import os
import re
import sys

ROOT = r"C:\Development\Wireshark-Industrial-Bundle-0.10.3\03-source\wireshark\tools\现场运行的各种规约程序\PROTOCOL"

PAT = re.compile(
    r"buf\s*\[\s*i\s*\+\+\s*\]\s*=\s*(0x[0-9A-Fa-f]{1,2}|\d{1,3})\s*;?\s*(?://\s*(.*))?")
IDX = re.compile(r"buf\s*\[\s*(\d+)\s*\]\s*=\s*(0x[0-9A-Fa-f]{1,2}|\d{1,3})")


def rd(p):
    try:
        return io.open(p, encoding="gbk", errors="replace").read().splitlines()
    except OSError:
        return []


def main() -> int:
    for vendor in sys.argv[1:]:
        vd = os.path.join(ROOT, vendor)
        print("=" * 74)
        print(vendor)
        for dp, dn, fn in os.walk(vd):
            for f in sorted(fn):
                if not f.lower().endswith((".cpp", ".h")):
                    continue
                lines = rd(os.path.join(dp, f))
                run = []
                start = 0
                for i, line in enumerate(lines):
                    m = PAT.search(line)
                    mi = IDX.search(line)
                    if m:
                        val = m.group(1)
                        run.append(val)
                    elif mi:
                        if len(run) < 3:
                            start = i
                            run = []
                        run.append(mi.group(2))
                    else:
                        if len(run) >= 4:
                            print(f"  {f}:{start+1}  {' '.join(run[:16])}")
                        run = []
                if len(run) >= 4:
                    print(f"  {f}:{start+1}  {' '.join(run[:16])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
