# -*- coding: utf-8 -*-
"""为剩余厂家提取帧头签名与长度字段（宽松匹配）。"""
import io
import os
import re

ROOT = r"C:\Development\Wireshark-Industrial-Bundle-0.10.3\03-source\wireshark\tools\现场运行的各种规约程序\PROTOCOL"

VENDORS = ["ASCII", "DGT801", "DataSpy", "FH_3000_TCP", "FH_LR12_COM",
           "FH_LR2000_COM", "FH_LR2000_NET", "FtpClient", "GEC", "HZ1000",
           "HathAwayIDM", "HuaRuiT_FWK_COM", "LBD_LuBo_TCP", "LFP", "NR_LFP_COM",
           "NR_RCS_9785", "NetCSC2000", "NetCSC2000L", "SD_WGDLV_NET", "SH2000",
           "ShareDir", "SpaBus", "Toshiba_Com_RSM", "WDS", "WFBL_FTP103",
           "WHFount_FTR_TCP", "WXB", "WXB11", "YS8", "YSOsc"]

ASSIGN = re.compile(r"buf\w*\s*\[\s*i\s*\+\+\s*\]\s*=")
LIT = re.compile(r"=\s*(0x[0-9A-Fa-f]{1,2}|'[^']'|\d{1,3})\s*;")


def rd(p):
    try:
        return io.open(p, encoding="gbk", errors="replace").read()
    except OSError:
        return ""


def main() -> int:
    for v in VENDORS:
        d = os.path.join(ROOT, v)
        if not os.path.isdir(d):
            print(f"{v:22s} MISSING")
            continue
        best = []
        for f in sorted(os.listdir(d)):
            if not f.lower().endswith(".cpp"):
                continue
            lines = rd(os.path.join(d, f)).splitlines()
            run = []
            for line in lines:
                if ASSIGN.search(line):
                    m = LIT.search(line)
                    run.append(m.group(1) if m else "?")
                    if len(run) > len(best):
                        best = list(run)
                else:
                    run = []
        print(f"{v:22s} {' '.join(best[:11])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
