# 已实现协议 vs 参考实现 差异清单

由 `diff_report.py` 机器生成；`status` 非「一致」的项需要处理。

| 参考目录 | 协议 | 封装 | 参考 ASDU 起始 | 我们 COT | 参考 COT | 状态 |
|----------|------|------|----------------|----------|----------|------|
| NR103 | nrelectric_net_iec103 | bare_asdu | - | 1 | 1 | 一致 |
| NR103_RCS9691 | nrelectric_net_iec103 | bare_asdu | - | 1 | 1 | 一致 |
| NR_103_NET | nrelectric_net_iec103 | bare_asdu_udp | - | 1 | 1 | 一致 |
| NZ103 | nari_serial_iec103 | bare_asdu | - | 1 | 1 | 一致 |
| NZ103II | nari_serial_iec103 | bare_asdu | - | 1 | 1 | 一致 |
| NZ_NET103 | nari_net_iec103 | private_apci_28 | 28 | 1 | 1 | 一致 |
| SF103 | sifang_serial_iec103 | bare_asdu | - | 1 | 1 | 一致 |
| SF103_CSC103A | sifang_serial_iec103 | bare_asdu | - | 1 | 1 | 一致 |
| SF_NET103 | sifang_net_iec103 | private_apci_28 | 28 | 1 | 1 | 一致 |
| SF_UDP103 | sifang_net_iec103 | ft12_over_udp | 28 | 1 | 1 | 一致 |
| SZNR_103_TCP | sznari_net_iec103 | ft12_over_tcp | - | 1 | 1 | 一致 |
| XJ_103_COM | xuji_serial_iec103 | bare_asdu | - | 1 | 1 | 一致 |
| XJ_COM103 | xuji_serial_iec103 | bare_asdu | - | 1 | 1 | 一致 |
| XJ_NET103 | xuji_net_iec103 | apci_68_cot16 | - | 2 | 2 | 一致 |
| ZHDFR | zh_recorder | bare_asdu | - | 1 | 1 | 一致 |
