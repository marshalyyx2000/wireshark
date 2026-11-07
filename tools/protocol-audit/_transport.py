# -*- coding: utf-8 -*-
"""Classify every PROTOCOL vendor: transport flavour and frame wrapper."""
import io
import os
import re

ROOT = r"C:\Development\Wireshark-Industrial-Bundle-0.10.3\03-source\wireshark\tools\现场运行的各种规约程序\PROTOCOL"


def rd(p):
    try:
        return io.open(p, encoding="gbk", errors="replace").read()
    except OSError:
        return ""


def main() -> int:
    vendors = sorted(d for d in os.listdir(ROOT) if os.path.isdir(os.path.join(ROOT, d)))
    print(f"{'vendor':24s} {'iface':7s} {'wrapper':10s} {'asdustart':9s} ports")
    for v in vendors:
        vd = os.path.join(ROOT, v)
        blob = ""
        for dp, dn, fn in os.walk(vd):
            for f in fn:
                if f.lower().endswith((".cpp", ".h")):
                    blob += rd(os.path.join(dp, f))
        iface = "-"
        m = re.search(r"Run\s*\(\s*(_COMM|_NET32|_NET)\s*\*", blob)
        if m:
            iface = {"_COMM": "COM", "_NET32": "NET32", "_NET": "NET"}[m.group(1)]
        elif "SOCK_STREAM" in blob or "SOCK_DGRAM" in blob:
            iface = "NET?"
        elif re.search(r"CreateFile\s*\(|GetComID|COMMTIMEOUTS", blob):
            iface = "COM?"
        wrapper = []
        if "0xEB" in blob and "0x90" in blob:
            wrapper.append("EB90")
        if re.search(r"buf\[i\+\+\]\s*=\s*0x68", blob):
            wrapper.append("68")
        if re.search(r"buf\[i\+\+\]\s*=\s*0x10", blob):
            wrapper.append("10")
        asdu = re.search(r"#define\s+ASDU_START_POSTION\s+(\d+)", blob)
        ports = sorted(set(re.findall(r"wPort\s*=\s*(\d+)", blob)))
        print(f"{v:24s} {iface:7s} {'+'.join(wrapper) or '-':10s} "
              f"{(asdu.group(1) if asdu else '-'):9s} {'/'.join(ports)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
