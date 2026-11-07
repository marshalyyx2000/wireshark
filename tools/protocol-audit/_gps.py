# -*- coding: utf-8 -*-
"""Classify every vendor: GPS/clock-sync vs protocol dissector."""
import io
import os

ROOT = r"C:\Development\Wireshark-Industrial-Bundle-0.10.3\03-source\wireshark\tools\现场运行的各种规约程序\PROTOCOL"


def main() -> int:
    names = [d for d in sorted(os.listdir(ROOT)) if os.path.isdir(os.path.join(ROOT, d))]
    print("%-28s %-6s %-6s %-6s %s" % ("vendor", "gps", "setclk", "sttp", "notes"))
    for v in names:
        d = os.path.join(ROOT, v)
        gps = setlocal = sttp = False
        for dp, dn, fn in os.walk(d):
            for f in fn:
                if not f.lower().endswith((".cpp", ".h")):
                    continue
                try:
                    t = io.open(os.path.join(dp, f), encoding="gbk", errors="replace").read()
                except OSError:
                    continue
                if "mGpsTime" in t:
                    gps = True
                if "SetLocalTime" in t or "SetSystemTime" in t:
                    setlocal = True
                if "SttpEngineC" in t:
                    sttp = True
        note = ""
        if gps and setlocal:
            note = "纯对时（无 STTP）"
        elif not sttp:
            note = "无 STTP 引擎"
        print("%-28s %-6s %-6s %-6s %s" % (v, gps, setlocal, sttp, note))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
