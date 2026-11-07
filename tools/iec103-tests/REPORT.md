# IEC 60870-5-103 验证报告

日期：2026-11-07
`tshark`：`06-build\wsbuild-industrial\run\RelWithDebInfo\tshark.exe`（开发树构建）

## 0. 中性抓包原则

现场抓包不知道是哪家 103、甚至不确定是不是 103，因此**所有抓包文件都不含协议提示**：

- 串口：Exported PDU 名称一律为 `serial_raw`
- 网络：普通 Ethernet/IPv4/UDP/TCP 帧；所有 103 网络解析器改为 Decode-As 注册，
  **不再按端口自动绑定**（此前 `nari_net`/`shandong`/`sznari`/`xuji`/`yunnan` 均会抢 1048/2404/2405）

解析时机：用户点击 `串口103` / `网络103` 菜单后，才设置 `serial_raw.payload_dissector`
或对端口应用 Decode As。`verify.py` 第 1 项断言即验证"未选择时不出现任何 103 协议"。

## 1. 基准 pcap 断言（`verify.py`）

| 用例 | 链路 | 中性 | 选择后解析 | 备注 |
|------|------|------|-----------|------|
| 四方串口103 | FT1.2 / serial_raw | PASS | PASS | ASDU 1,2,3,5,6,7,8,10,23–31 全覆盖 |
| 深圳南瑞串口103 | FT1.2 / serial_raw | PASS | PASS | 同上 |
| 四方网络103 | UDP 1888/1889 | PASS | PASS | 裸 ASDU，无 malformed |
| 南瑞网络103 | TCP 1048 + UDP 1032 | PASS | PASS | 含 41 字节主站广播 |
| **金智网络103** | **TCP 6000，2 字节长度 + 12/13 控制域** | **PASS** | **PASS** | **扩展 ASDU 203/204/220–229 全覆盖** |
| **积成网络103** | **TCP/UDP 6185，4 字节 APCI** | **PASS** | **PASS** | **扩展 COT 40–44** |
| 南自网络103（回归） | TCP 1048 | — | PASS | 协议已注册 |
| 许继串口103（回归） | FT1.2 | — | PASS | 协议已注册 |
| 深圳南瑞网络103（回归） | TCP 2404 APCI | — | PASS | 协议已注册 |

断言项：中性性；选择后过滤器命中 > 0；期望 ASDU 全覆盖；COT/FUN/INF/DPI/CP56Time2a 非空；
点表名（如 `距离I段动作`、`过流I段动作`、`定值组`）出现在解析树；无 `Malformed`。

## 2. 实机联调

| 用例 | 方式 | 中性 | 选择后 | 抓包 |
|------|------|------|--------|------|
| 四方串口103 | com0com COM6/COM7，9600-8E1，双向 | PASS | PASS | `out/sifang_serial_live.pcap`（104 帧，主站 26 / 从站 26） |
| 深圳南瑞串口103 | com0com COM6/COM7，9600-8E1，双向 | PASS | PASS | `out/sznari_serial_live.pcap`（104 帧） |
| 四方网络103 | 127.0.0.1 UDP 1888/1889 | PASS | PASS | `out/sifang_net_live.pcap`（21 报文） |
| 南瑞网络103 | 127.0.0.1 TCP 1048 + UDP 1032 | PASS | PASS | `out/nrelectric_net_live.pcap` |

实机串口双向抓包选择解析器后解码出的 ASDU 类型：
`1, 2, 3, 5, 6, 7, 8, 10, 23, 24, 25, 26, 27, 28, 29, 30, 31`。

## 3. 崩溃修复（0.10.11 后续）

用户报告：打开 `sznari_serial.pcap` 后点"深圳南瑞串口103规约解析"崩溃。
Windows 事件日志异常码 `0xc0000374` = **heap corruption**。

根因：`serial_raw` 的试解变量同时交给 preference 系统和菜单管理。prefs 用
`wmem_free()` 释放字符串，菜单用 `g_free()` —— 分配器混用导致堆损坏，GUI 在
re-dissect 时崩溃（`tshark` 单次运行不复现，因为不触发 prefs 回写）。

修复：

| 问题 | 修复 |
|------|------|
| 分配器混用（崩溃根因） | 运行时变量 `g_runtime_payload` 由本模块 `g_strdup`/`g_free` 独占；prefs 变量 `g_pref_payload` 交给 prefs，通过 apply 回调复制，不再共享指针 |
| 试解失败留空树 | 厂商解析器返回 0 时回退到 `Serial Raw` 并标注"did not match" |
| 点表 2 MB 空数组 / 逐条 `g_free` | 改为 `GHashTable`（仅实际条目），在 handoff 阶段加载一次 |
| ASDU30 NDV 越界读 | 先检查剩余长度再读 NDV |
| ASDU10/21 条目越界读 | 循环条件改为 `pos + 6 <= end` |
| ASDU2 短帧长度错误 | 移到 `asdu_pdu_len()`，CP56 不足时回退 CP32 |

## 4. 崩溃与内存回归（安装版）

| 检查 | 方法 | 结果 |
|------|------|------|
| GUI 菜单点击 | UI Automation 真实点击 `串口103` 子项 4 轮，含反复切换厂商（共 24 次） | PASS，进程全程存活 |
| 内存泄漏 | 每轮点击 5 次后采样私有字节，6 轮 | PASS，`-0.1%`（149.58 MB → 149.45 MB） |
| 崩溃日志 | 事件日志自 09:45 后无 `Application Error` | PASS |
| 截断/损坏报文 | 873 帧串口 + 415 帧网络 + 400 帧随机变异 | PASS |
| 重复试解 | 4 家厂商 × 2 个 pcap × 3 次 + 错误厂商后改正 | PASS |

复现与回归脚本：

```bat
powershell -File tools\iec103-tests\gui_click_test.ps1
powershell -File tools\iec103-tests\memory_check.ps1
python tools\iec103-tests\stress_trydecode.py
python tools\iec103-tests\fuzz_iec103.py
```

## 5. 交互序列（模拟保护）

```
复位通信单元(FCB=0, FCV=0)
  → 确认(ACD=1)
  → 召唤1级数据 → ASDU5 标识
  → 总查询 ASDU7 → ASDU2 保护事件 / ASDU3 测量 / ASDU10 通用分类 → ASDU8 终止
  → 时间同步 ASDU6（FCV=0 广播式）
  → 录波：ASDU24 → ASDU26 → ASDU25 → ASDU27 → ASDU28 → ASDU29 → ASDU30 → ASDU31
```

## 6. 金智 / 积成专项（`verify_jinzhi_jicheng.py`）

| 用例 | 目的 | 结果 |
|------|------|------|
| `jinzhi_ctrl12` | 12 字节控制域 | PASS |
| `jinzhi_ctrl13` | 13 字节控制域 | PASS |
| `jinzhi_packed` | 单个 TCP 段含 5 个 APDU | PASS（全部拆出） |
| `jinzhi_truncated` | 截断 APDU 不越界、不崩溃 | PASS（只校验崩溃/越界） |
| `jinzhi_ext` | 扩展 ASDU 5/8/10/220/222–227/229/204 | PASS |
| `jicheng_tcp` | TCP 6185 主从流 | PASS |
| `jicheng_udp6185` | UDP 6185 广播校时 | PASS |

模糊测试新增金智 630 帧、积成 356 帧截断/腐蚀样本，均无崩溃与越界。

GUI 回归：网络103 菜单 8 项交替点击 3 轮（24 次），进程全程存活；
6 轮点击后私有字节 155.48 MB → 155.34 MB（-0.1%）。

## 7. 武汉中原录波器（ZH 系列）

### 规约差异

这不是 IEC 103，而是武汉中元华电专有二进制协议（TCP 30282），文件名带「103」
仅因定值文件 `ZHREC.FDZ.103` 用了 103-ASDU-10 格式。

### 结果（`verify_zh_recorder.py`）

| 用例 | 断言 | 结果 |
|------|------|------|
| `zh_neutral` | 未选择时零帧解析为 `zh_recorder` | PASS |
| `zh_type1` | 类型一帧 + 21 种 TYP 全覆盖 | PASS |
| `zh_structures` | FILE_INFO/FILE_GET/FILE_VER/ZHREC_YC/YX/日期字段非空 | PASS |
| `zh_enums` | 型号 `ZH-2B+`、错误码「没有所请求的数据」显示 | PASS |
| `zh_type2` | STX/CHS/ETX 解析，CHS 全部校验通过 | PASS |
| `zh_bad_chs` | 篡改 CHS 被标记「校验和错误」且不崩溃 | PASS |
| `zh_oversize_len` | LEN=0xFFFFFFFF / 16377 / 短头 / 空包 安全停止 | PASS |
| `zh_truncated` | 399 帧逐字节截断，无崩溃无越界 | PASS |
| `zh_reassembly` | 4 个文件重组逐字节一致（含 2 包 `.dat`） | PASS |

### 多包重组实测

| 文件 | 大小 | 包数 | 重组结果 |
|------|------|------|----------|
| ZHREC.SCFF | 290 | 1 | 一致 |
| REC001.cfg | 658 | 1 | 一致 |
| REC001.dat | 2048 | 2 | 一致 |
| RECENT.LST | 1004 | 1 | 一致 |

### 其它回归

| 项 | 结果 |
|----|------|
| `stress_trydecode.py`（含类型一/类型二各 3 轮 + 两遍解析） | ALL PASSED |
| `fuzz_iec103.py`（ZH 27158 帧截断/腐蚀） | PASSED |
| GUI 点击「录波器规约 → 武汉中原录波器规约解析」，过滤栏变为 `zh_recorder` | PASS |
| 6 轮菜单切换内存 | 127.65 MB 恒定，增长 0% |

## 8. 点表
`resources/share/wireshark/iec103/points/{sifang,sznari,nrelectric,nari}.csv`

| 厂商 | 行数 | 说明 |
|------|------|------|
| 四方 | 54 | 含 DL/T 667 兼容范围 + 四方实施细则中的 SCL/RPV/RFA/TOO 等 |
| 深圳南瑞 | 53 | 含通用分类组（定值/测量/软压板）与 ASDU5 初始化 |
| 南瑞 | 50 | 含系统状态字与定值区 |
| 南自 | 48 | 含扩展远动测量组与 ASDU17 |
| **金智** | **64** | **应用层规范 4.1–4.22 全部通用分类组 + 读组标题/读组/遥控校验** |
| **积成** | **50** | **通用分类组 + INF 230 召唤 + 读命令组** |

`source` 列标注 `std`（DL/T 667 兼容范围）、`public`（公开文档明示）、
`inferred`（按公开报文样例推定）。厂商内部工程点表未公开，见 `tools/iec103-docs/SOURCES.md`。

## 9. 已知限制

- 四方网络 103 仅实现 **UDP 1888/1889 的 103 ASDU 承载**；CSC2000 私有"网络变量"
  （遥测/遥信/遥控各有类型码）格式未纳入。
- 金智控制域按链路层规范 V2.0 的 12/13 字节实现；讨论稿 PDF 的标准 4 字节版本
  由同一解析器自适应（偏好 `jinzhi.apci_ctrl_len` 可锁定 12 或 13）。
- 金智文件传输 ASDU 223–227 在报文正文里的字段宽度依赖厂商实际实现，
  当前按应用层规范表格解析；异常宽度会回退为原始字节显示。
- 积成 UDP 6185 广播按原文"控制域无意义"处理，不解释序列号。
- 各厂商私有扩展 ASDU（如南自 ASDU17）按原始字节显示，未逐字段解码。
- 点表中 `inferred` 行的工程点号需以现场实际点表校准。
- 武汉中原 ZH 录波器规约按 2.1 版实现；类型二帧的 CHS 为 TYP+LEN+DAT 的字节累加和，
  若现场固件用其他校验算法，会在解析树中标为「校验和错误」但不影响字段解析。
- ZH 协议的通道名称来自 `ZHREC.SCFF` 文件内容（不在报文里），本实现不解析该文件格式。





