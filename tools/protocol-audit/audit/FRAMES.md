# 网络 103 帧结构抽取

| 厂商 | socket | ASDU 起始 | 长度字段偏移 | 校验范围 | 魔数 |
|------|--------|-----------|--------------|----------|------|
| FH_3000_TCP | SOCK_STREAM | - | 0,1,2,3,4,10,11,12 | [1]=2; [4]=len | - |
| HathAwayIDM | SOCK_STREAM | - | 2,3,5,6,7,14 | - | - |
| KELI_103_TCP | SOCK_STREAM | - | 0,1,2,3,4,8,9,12,14 | - | - |
| LBD_LuBo_TCP | SOCK_STREAM | - | 0,4 | - | - |
| NFDFR | SOCK_DGRAM | - | 0,1,3,10,11,12,13,14,21,114 | - | - |
| NFDFR200 | SOCK_DGRAM | - | 0,1,3,10,11,12,13,14,21,74 | - | - |
| NF_RFW200_NET | SOCK_DGRAM | - | 0,1,2,3,5,6,7,8,10,11 | - | - |
| NR103_RCS9793 | SOCK_STREAM | - | 10,12,13,14 | - | - |
| NR_103_NET | SOCK_DGRAM | - | 0,1,2,6,7,8,10,12,13,14 | - | - |
| NR_RCS_9785 | SOCK_DGRAM | - | - | - | - |
| NZ_NET103 | SOCK_DGRAM,SOCK_STREAM | 28 | 0,2,3,5,8,9,15,16,17,18 | - | - |
| SF_CSFM103_TCP | SOCK_STREAM | 28 | 0,1,2,3,4,10,11,12,13,14 | - | U_TEST_CON_MASK=0x80,U_TEST_ACT_MASK=0x40,U_STOP_CON_MASK=0x20 |
| SF_NET103 | SOCK_STREAM | 28 | 12,14,16,24 | - | - |
| SF_UDP103 | SOCK_DGRAM | 28 | 0,1,2,3,4,6,8,9,10,11 | [1]=2; [4]=len | - |
| SH2000 | SOCK_STREAM | 28 | 0,4,9,10,11,12 | - | - |
| SZNR_103_TCP | SOCK_STREAM | - | 0,1,2,3,4,5,6,8,10,11 | - | - |
| WFBL_FTP103 | SOCK_STREAM | 28 | 0 | - | - |
| WGL3000 | SOCK_STREAM | 28 | 0,4 | - | - |
| XJ_NET103 | SOCK_STREAM | - | 1,6,8,11,12,13,14,28,30,35 | - | U_TEST_CON_MASK=0x80,U_TEST_ACT_MASK=0x40,U_STOP_CON_MASK=0x20 |
| XJ_NET103_WXH13 | SOCK_STREAM | - | 1,6,8,11,12,13,14,28,30,35 | - | U_TEST_CON_MASK=0x80,U_TEST_ACT_MASK=0x40,U_STOP_CON_MASK=0x20 |
| YS88A | SOCK_DGRAM | - | 0,1,3,10,11,12,13,14,15,16 | - | - |
| YS_89_NET | SOCK_DGRAM | - | 0,1,3,10,11,12,13,14,15,16 | - | - |
