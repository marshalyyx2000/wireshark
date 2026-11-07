# -*- coding: utf-8 -*-
"""Dump the receive-buffer layout checks of the clock-sync (对时) protocols."""
import io
import os
import re
import sys

ROOT = r"C:\Development\Wireshark-Industrial-Bundle-0.10.3\03-source\wireshark\tools\现场运行的各种规约程序\PROTOCOL"

VENDORS = sys.argv[1:] or [
    "KH_20", "KH_2000", "KH_2000_", "KH_2022",
    "BSS_3", "BSS_3II", "BSS_3_YongHe", "ARBITER_1088AB",
    "SX_TD_04", "SX_TD_2000", "SDZR_CEP220B_COM", "SDZR_CEP223_COM",
    "HJTF_HJ201_COM", "SZ_4U_ASCII", "SZ_ZU_ASCII",
]

KEYS = ("recvbuff[", "chRecvBuff[", "uchRecvBuff[", "pbuff[", "readlen", "dwLength",
        "SetLocalTime", "memcpy(Temp", "iTemp=", "atoi")


def main() -> int:
    for v in VENDORS:
        d = os.path.join(ROOT, v)
        print("=" * 78)
        print(v)
        for f in sorted(os.listdir(d)):
            if not f.lower().endswith(".cpp"):
                continue
            t = io.open(os.path.join(d, f), encoding="gbk", errors="replace").read()
            lines = t.splitlines()
            for i, line in enumerate(lines, 1):
                s = line.strip()
                if any(k in s for k in KEYS) and "//" not in s[:2]:
                    print(f"  {f}:{i}: {s[:130]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
