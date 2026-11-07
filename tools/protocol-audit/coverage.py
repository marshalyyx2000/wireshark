# -*- coding: utf-8 -*-
"""Audit coverage: which PROTOCOL vendors already have a dissector."""
import io
import json
import os
import re

ROOT = r"C:\Development\Wireshark-Industrial-Bundle-0.10.3\03-source\wireshark\tools\现场运行的各种规约程序\PROTOCOL"
DISS = r"C:\Development\Wireshark-Industrial-Bundle-0.10.3\03-source\wireshark\epan\dissectors"

# PROTOCOL 目录 -> 已实现的协议短名（来自解析器源文件的 vendor_dir 注释或显式映射）
EXPLICIT = {
    "ABB103": "abb103_serial_iec103",
    "ABB_COM_101": "abb_com101_serial_iec103",
    "ALSTOM_103_COM": "alstom103_serial_iec103",
    "BP103": "bp103_serial_iec103",
    "NR_103_NET": "nr103_net_iec103",
    "SIEMENS_103_COM": "siemens103_serial_iec103",
    "SJ103": "sj103_serial_iec103",
    "SZNR_103_TCP": "sznr103_tcp_iec103",
    "WGL3000": "wgl3000_iec103",
    "NR103": "nr103_serial_iec103",
    "NR103_RCS9691": "nr103_rcs9691_serial_iec103",
    "NR103_RCS9793": "nr103_rcs9793_iec103",
    "NZ103": "nz103_serial_iec103",
    "NZ103II": "nz103ii_serial_iec103",
    "NZ_NET103": "nz_net103_iec103",
    "KELI_103_TCP": "keli_103_tcp",
    "SF103": "sf103_serial_iec103",
    "SF103_CSC103A": "sf103_csc103a_serial_iec103",
    "SF_CSFM103_TCP": "sf_csfm103_tcp_iec103",
    "SF_NET103": "sf_net103_tcp",
    "SF_UDP103": "sf_udp103_iec103",
    "XJ_103_COM": "xj103_com_serial_iec103",
    "XJ_COM103": "xj_com103_serial_iec103",
    "XJ_NET103": "xj_net103_tcp_iec103",
    "XJ_NET103_WXH13": "xj_net103_wxh13",
    "NFDFR": "nfdfr",
    "NFDFR200": "nfdfr200",
    "NF_RFW200_NET": "nf_rfw200_net",
    "YS88A": "ys88a",
    "YS8": "ys8_serial",
    "YSOsc": "ysosc_serial",
    "YS_89_NET": "ys_89_net",
    "YS_89A_NET": "ys_89a_net",
    "SDDFR": "sddffr",
    "ZHDFR": "zh_recorder",
    "SH2000": "sh2000",
    "FH_3000_TCP": "fh3000_tcp",
    "FH_LR12_COM": "fh_lr12_com",
    "FH_LR2000_COM": "fh_lr2000_com",
    "FH_LR2000_NET": "fh_lr2000_net",
    "SD_WGDLV_NET": "sd_wgdlv_net",
    "WFBL_FTP103": "wfbl_ftp103",
    "WXB": "wxb_serial",
    "WXB11": "wxb11_serial",
    "GEC": "gec_serial_iec103",
    "DGT801": "dgt801_serial",
    "NR_LFP_COM": "nr_lfp_com",
    "HuaRuiT_FWK_COM": "huaruit_fwk_com",
    "Toshiba_Com_RSM": "toshbia_com_rsm",
    "ASCII": "ascii_meter_serial",
    "LBD_LuBo_TCP": "lbd_lubo_tcp",
    "NR_RCS_9785": "nrcs9785_net",
    "NetCSC2000": "netcsc2000_net",
    "NetCSC2000L": "netcsc2000l_net",
    "LFP": "lfp_serial",
    "WDS": "wds_serial",
    "SpaBus": "spabus_serial",
    "ModBus": "modbus_protection",
    "GE_Modbus": "ge_modbus_rtu",
    "GE_MLINK_MODEM_MODBUS_COM": "ge_mlink_modbus",
    "GE_MODEM": "ge_modem_modbus_tcp",
}

# 纯对时（GPS/时钟同步）类：按需求不做规约解析
CLOCK_ONLY = {
    "GPS_JC_DDX_COM", "GPS_MH202", "GPS_SF_CSN_1A_COM", "GPS_VatechHydro_TCR510SAT_COM",
    "ARBITER_1088AB", "BSS_3", "BSS_3II", "BSS_3_YongHe", "HJTF_HJ201_COM",
    "KH_12", "KH_20", "KH_2000", "KH_2000_", "KH_2022",
    "SDZR_CEP220B_COM", "SDZR_CEP223_COM", "SX_TD_04", "SX_TD_2000",
    "SZ_4U_ASCII", "SZ_ZU_ASCII",
}


def main() -> int:
    names = [d for d in sorted(os.listdir(ROOT)) if os.path.isdir(os.path.join(ROOT, d))]

    covered, clock, missing = [], [], []
    for v in names:
        if v in CLOCK_ONLY:
            clock.append(v)
        elif v in EXPLICIT:
            covered.append((v, EXPLICIT[v]))
        else:
            missing.append(v)

    print(f"PROTOCOL 厂家总数: {len(names)}")
    print(f"已实现规约解析:   {len(covered)}")
    print(f"对时类跳过:       {len(clock)}")
    print(f"待实现:           {len(missing)}\n")

    print("--- 对时类（不做规约解析）---")
    for v in clock:
        print(f"  {v}")
    print("\n--- 待实现 ---")
    for v in missing:
        print(f"  {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
