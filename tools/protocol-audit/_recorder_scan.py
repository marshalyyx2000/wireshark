# -*- coding: utf-8 -*-
"""Summarise framing style for the recorder family."""
import io
import os
import re

ROOT = r"C:\Development\Wireshark-Industrial-Bundle-0.10.3\03-source\wireshark\tools\现场运行的各种规约程序\PROTOCOL"

FAMILY = ["ZHDFR", "SDDFR", "NFDFR", "NFDFR200", "NF_RFW200_NET", "SD_WGDLV_NET",
          "FH_LR2000_NET", "FH_LR12_COM", "FH_LR2000_COM", "FH_3000_TCP",
          "HZ1000", "YS8", "YS88A", "YSOsc", "YS_89A_NET", "YS_89_NET",
          "WDS", "WFBL_FTP103", "WHFount_FTR_TCP", "DataSpy", "GE_MODEM",
          "GE_MLINK_MODEM_MODBUS_COM", "SpaBus", "LBD_LuBo_TCP", "SF_CSFM103_TCP"]


def rd(p):
    try:
        return io.open(p, encoding="gbk", errors="replace").read()
    except OSError:
        return ""


print(f"{'vendor':26s} {'68var':6s} {'68len16':8s} {'68addr':7s} {'eb90':5s} {'10fixed':8s} {'iface':8s} files")
for v in FAMILY:
    vd = os.path.join(ROOT, v)
    if not os.path.isdir(vd):
        print(f"{v:26s} MISSING")
        continue
    blob = ""
    files = []
    for dp, dn, fn in os.walk(vd):
        for f in sorted(fn):
            if f.lower().endswith((".cpp", ".h")):
                blob += rd(os.path.join(dp, f))
                files.append(f)
    # 68 | len8 | len8 | 68
    var8 = bool(re.search(r"buf\[i\+\+\]\s*=\s*0x68\s*;\s*[^\n]*\n\s*[^\n]*buf\[i\+\+\]\s*=\s*([^;]+);[^\n]*\n\s*[^\n]*buf\[i\+\+\]\s*=\s*([^;]+);[^\n]*\n\s*[^\n]*buf\[i\+\+\]\s*=\s*0x68", blob))
    len16 = bool(re.search(r"buf\[i\+\+\]\s*=\s*0x68[^\n]*\n[^\n]*buf\[i\+\+\]\s*=\s*[^;\n]+/\s*256[^\n]*\n[^\n]*buf\[i\+\+\]\s*=\s*[^;\n]+%256", blob)) or \
            bool(re.search(r"buf\[i\+\+\]\s*=\s*[^;\n]+%\s*256[^\n]*\n[^\n]*buf\[i\+\+\]\s*=\s*[^;\n]+/\s*256[^\n]*\n[^\n]*buf\[i\+\+\]\s*=\s*0x68", blob))
    addr68 = bool(re.search(r"buf\[i\+\+\]\s*=\s*0x68;[^\n]*\n[^\n]*buf\[i\+\+\]\s*=\s*m_iAddr", blob))
    eb90 = "0xEB" in blob and "0x90" in blob
    fixed10 = bool(re.search(r"buf\[i\+\+\]\s*=\s*0x10", blob))
    iface = "NET" if ("SOCK_STREAM" in blob or "SOCK_DGRAM" in blob) else ("COM" if "GetComID" in blob or "COMMTIMEOUTS" in blob else "-")
    print(f"{v:26s} {str(var8):6s} {str(len16):8s} {str(addr68):7s} {str(eb90):5s} {str(fixed10):8s} {iface:8s} {len(files)}")
