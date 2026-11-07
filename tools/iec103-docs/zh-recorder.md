# 武汉中原（中元华电 ZH 系列）录波器以太网通信规约

依据（本机）：
`D:\研发\各个大厂的103规约文本\ZH-2 ZH-3 ZH-5系列电力故障录波装置通信规约(公开部分).pdf`
（ZH-2 系列电力故障录波装置以太网通信规约，2.1 版，武汉中元华电科技有限公司，2004-07-21）

> **注意**：这是武汉中元华电的**专有二进制协议**，不是 IEC 60870-5-103。
> 文件名里出现「103」只是因为定值文件 `ZHREC.FDZ.103` 采用 103-ASDU-10 格式。

适用装置：ZH-2、ZH-2A、ZH-2B、ZH-2B+、ZH-101、ZH-3、ZH-5 系列电力故障录波分析装置。

## 通信接口

| 项 | 值 |
|----|-----|
| 接口 | 10M/100M 自适应以太网 |
| 协议 | TCP/IP |
| 端口 | 764AH = **30282** |
| 传输模式 | 平衡传输 |
| 主从 | 录波装置为**从机（服务端）**，主站为客户端 |
| 字节序 | **低字节在前**（小端） |
| 报文最大长度 | 16384 字节 |

## 报文结构

### 类型一（基础格式）

| 偏移 | 域 | 类型 | 意义 |
|------|-----|------|------|
| 0—3 | TYP | DWORD | 报文类型（32 位无符号） |
| 4—7 | LEN | DWORD | DAT 域长度 |
| 8—(8+LEN-1) | DAT | 任意 | 报文数据 |

`LEN` 最大 `16384 - 8 = 16376`。

### 类型二（8.6 版以后，带帧同步）

| 偏移 | 域 | 类型 | 意义 |
|------|-----|------|------|
| 0—3 | STX | DWORD | `76337692H` |
| 4—7 | STX | DWORD | `76337692H` |
| 8—11 | TYP | DWORD | 报文类型 |
| 12—15 | LEN | DWORD | DAT 域长度 |
| 16—(16+LEN-1) | DAT | 任意 | 报文数据 |
| (17+LEN)—(20+LEN) | CHS | DWORD | TYP、LEN、DAT 域的字节累加和 |
| (21+LEN)—(24+LEN) | ETX | DWORD | `76927633H` |
| (25+LEN)—(28+LEN) | ETX | DWORD | `76927633H` |

**字符串**：以 `00H` 结束。`"ABC"` 占 4 字节：`41 42 43 00`。

## 报文类型（TYP）

### 控制方向（主站 → 录波器）

| TYP | 常量 | 含义 |
|-----|------|------|
| 00000001H | PTYPE_RETURN | 对上一条命令的响应 |
| 00000002H | PTYPE_TIME | 设置/修改装置时钟 |
| 00000003H | PTYPE_PACKETSIZE | 请求/设置分包大小 |
| 00000004H | PTYPE_FRAMEDELAY | 请求/设置帧间隔 |
| 00000010H | PTYPE_FILE_INFO | 询问单个文件信息 |
| 00000011H | PTYPE_FILE_DATA | 文件数据 |
| 00000012H | PTYPE_FILE_GET | 要求传送指定文件 |
| 00000015H | PTYPE_FILE_VER | 要求传送文件版本 |
| 00000022H | PTYPE_DIR_GET | 要求传送目录信息 |
| 0000003AH | PTYPE_WORK_PATH | 要求回应程序工作目录 |
| 0000003BH | PTYPE_DATA_PATH | 要求回应录波数据目录 |
| 0000006EH | PTYPE_CANCEL | 中止当前传输 |
| 00000205H | PTYPE_RECORD | 遥控录波 |
| 01000010H | PTYPE_RECORDERINFO | 请求录波器信息 |
| 01000025H | PTYPE_GETMODEL | 请求录波器型号 |
| 00000300H | PTYPE_GETNEWSTATUS | 请求新状态 |
| 00000301H | PTYPE_RESETNEWSTATUS | 复归新状态 |
| 00000303H | PTYPE_YC | 请求基本遥测量 |
| 00000304H | PTYPE_YX | 请求遥信量 |
| 00000305H | PTYPE_YCEX | 请求扩展遥测量 |
| 76337692H | PTYPE_CHKFRMFMT | 检查帧格式 |

### 监视方向（录波器 → 主站）

同上的 RETURN、PACKETSIZE、FRAMEDELAY、FILE_INFO、FILE_DATA、CANCEL、RECORDERINFO、
GETMODEL、GETNEWSTATUS、YC、YX、YCEX、CHKFRMFMT，另加：

| TYP | 常量 | 含义 |
|-----|------|------|
| 00000013H | PTYPE_FILE_PUT | 要求对方接收文件 |
| 0000003AH | PTYPE_WORK_PATH | 回应工作目录 |
| 0000003BH | PTYPE_DATA_PATH | 回应数据目录 |

## 结构体

### DATE_TIME（16 字节）

| 偏移 | 域 | 类型 | 范围 |
|------|-----|------|------|
| 0—1 | year | WORD | 1980—2100 |
| 2—3 | month | WORD | 1—12 |
| 4—5 | day | WORD | 1—31 |
| 6—7 | hour | WORD | 0—23 |
| 8—9 | minute | WORD | 0—59 |
| 10—11 | second | WORD | 0—59 |
| 12—13 | ms | WORD | 0—999 |
| 14—15 | us | WORD | 0—999 |

### SYSTEM_TIME（16 字节）

year(1900—2099)、month(1—12)、day_of_week(0—6)、day_of_month(1—31)、hour、
minute、second、milliseconds，各 WORD。

### PACKET_RETURN（264 字节）

| 偏移 | 域 | 类型 |
|------|-----|------|
| 0—3 | code | DWORD |
| 4—7 | sender | DWORD |
| 8—263 | message | char[256] |

`sender`：0 未知 / 1 录波装置 / 2 分站 / 3 主站。

`code`：

| 值 | 名称 | 含义 |
|----|------|------|
| 71000 | ECONN_REMOTECLOSE | 远方已经关闭 |
| 71001 | ECONN_TOOMANY | 连接太多 |
| 71002 | ECONN_NOACK | 远方没有应答 |
| 71003 | ECONN_PTYPE | 数据包类型错误 |
| 71004 | ECONN_REMOTECANCEL | 远方取消当前操作 |
| 71005 | ECONN_LOCALCANCEL | 本地取消当前操作 |
| 71006 | ECONN_NOUNITID | 没有找到指定设备 |
| 71200 | ECONN_FILECREATE | 创建文件失败 |
| 71201 | ECONN_FILEOPEN | 打开文件失败 |
| 71202 | ECONN_MEMORY | 内存分配失败 |
| 71250 | ECONN_DBCONN | 连接数据库失败 |
| 71300 | ECONN_NODLLFUN | 动态库中无函数 |
| 71301 | ECONN_COMMAND | 无效命令 |
| 71302 | ECONN_NO_DATA | 没有所请求的数据 |
| 71303 | ECONN_DB_EXCEPTION | 数据库异常 |
| 71304 | ECONN_BUSY | 系统繁忙 |
| 71305 | ECONN_PARAM | 参数错误或无效 |
| 0 | ECONN_SUCCESS | 成功（无错误） |

### FILE_INFO（292 字节）

| 偏移 | 域 | 类型 | 说明 |
|------|-----|------|------|
| 0—3 | from | DWORD | 0 = 来源于磁盘 |
| 4—19 | time | DATE_TIME | 文件时间 |
| 20—23 | size | DWORD | 文件大小 |
| 24—27 | attr | DWORD | 文件属性（位定义） |
| 28—31 | offset | DWORD | 本次发送的文件偏移 |
| 32—35 | length | DWORD | 本次发送的文件长度 |
| 36—291 | name | char[256] | 文件名 |

`attr` 位：`0x01` 只读 / `0x02` 隐藏 / `0x04` 系统 / `0x10` 文件夹 / `0x20` 存档 /
`0x80` 一般 / `0x100` 临时。

### FILE_GET（268 字节）

| 偏移 | 域 | 类型 |
|------|-----|------|
| 0—1 | from | WORD |
| 2—3 | flag | WORD |
| 4—7 | offset | DWORD |
| 8—11 | fid | long |
| 12—267 | name | char[256] |

`flag`：`0x01` 传送前压缩 / `0x02` 传送后删除。`flag = 0` 时 `fid` 也为 0。

### FILE_VER（324 字节）

`ver` char[32]（如 `"7.6.9.8"`）+ `info` FILE_INFO(292)。

### FAULT_INFO（502 字节）

| 偏移 | 域 | 类型 | 说明 |
|------|-----|------|------|
| 0—1 | type | WORD | 文件类型 |
| 2—3 | datnum | short | 数据文件数目（总为 1） |
| 4—5 | jmp | WORD | 跳闸相别：`0x0008` A / `0x0004` B / `0x0002` C |
| 6—9 | faultid | long | 故障编号 |
| 10—13 | filesize | DWORD | 文件大小 |
| 14—17 | devid | long | 设备节点 ID（总 0） |
| 18—19 | code | WORD | 启动码 |
| 20—21 | — | WORD | 未使用 |
| 22—25 | staid | long | 子站节点 ID（总 0） |
| 26—29 | faulttype | DWORD | 故障类型 |
| 30—37 | fdist | double | 故障距离（km） |
| 38—53 | time | DATE_TIME | 故障时间 |
| 54—117 | linename | char[64] | 故障元件名称 |
| 118—373 | filename | char[256] | 故障文件名称 |
| 374—501 | sti | char[128] | 启动信息 |

`faulttype`：`0x0000` 无故障 / `0x0001` A 相接地 / `0x0002` B 相接地 / `0x0004` C 相接地 /
`0x0008` AB 短路 / `0x0010` BC 短路 / `0x0020` CA 短路 / `0x0040` AB 短路接地 /
`0x0080` BC 短路接地 / `0x0100` CA 短路接地 / `0x0200` 三相短路 / `0x0400` 三相短路接地 /
`0x0800` 其他 / `0x1000` 母线故障 / `0x2000` 区外故障 / `0x2001` 变压器内部故障 /
`0x7FFF` 尚未分析。

### ZHREC_YC（82 字节）

| 偏移 | 域 | 类型 | 说明 |
|------|-----|------|------|
| 0 | gno | BYTE | 组号：20 基本遥测 / 21 扩展遥测 |
| 1 | ino | BYTE | 条目号 |
| 2—5 | fv | float | 标准值 |
| 6—9 | fa2 | float | 二次侧系数，S2 = fv × fa2 |
| 10—13 | fa1 | float | 一次侧斜率，S1 = fv × fa1 + fb1 |
| 14—17 | fb1 | float | 一次侧截距 |
| 18—65 | name | char[48] | 描述 |
| 66—73 | unit1 | char[8] | 一次侧量纲 |
| 74—81 | unit2 | char[8] | 二次侧量纲 |

### ZHREC_YX（66 字节）

| 偏移 | 域 | 类型 | 说明 |
|------|-----|------|------|
| 0 | gno | BYTE | 组号 = 30 |
| 1 | ino | BYTE | 条目号 1—160 |
| 2—5 | fv | float | 标准值 |
| 6—9 | fa2 | float | 二次侧系数 |
| 10—13 | fa1 | float | 一次侧斜率 |
| 14—17 | fb1 | float | 一次侧截距 |
| 18—65 | name | char[48] | 描述 |

## 通信流程

1. **初始化**：建立 socket 连接 → 录波器回 `PTYPE_RETURN`（code 表示成功/失败）
2. **列目录**：`PTYPE_DIR_GET` + FILE_GET（`name` 为过滤串，如 `f:\*.zyd`）→ 回 `PTYPE_RETURN`，随后用若干 `PTYPE_FILE_DATA` 传送 N 个 FILE_INFO
3. **召唤文件**：`PTYPE_FILE_GET` + FILE_GET（全路径名）→ 回 RETURN，随后多个 `PTYPE_FILE_DATA` 拼接为文件
4. **查新状态**：`PTYPE_GETNEWSTATUS`（LEN=0）→ 回 RETURN，`newstatus` 为 DWORD：bit0 新录波 / bit1 定值改变 / bit2 配置改变。重连后首次总为 `FFFFFFFFH`
5. **复归新状态**：`PTYPE_RESETNEWSTATUS` + DWORD（`0x1` 新录波 / `0x2` 定值改变）
6. **工作目录 / 型号**：`PTYPE_WORK_PATH` / `PTYPE_GETMODEL`，均回 RETURN，`path` 为 char[]（含结尾 `\`，如 `E:\ZYHD\`）
7. **分包大小**：`PTYPE_PACKETSIZE` + WORD（248—16376，或 `FFFFH` 查询当前值）
8. **帧间隔**：`PTYPE_FRAMEDELAY` + WORD（0—30000 ms，或 `FFFFH` 查询）
9. **对时**：`PTYPE_TIME` + SYSTEM_TIME(16)，**无回答**
10. **遥控录波**：`PTYPE_RECORD`（LEN=0），**无回答**
11. **遥测/遥信**：`PTYPE_YC` / `PTYPE_YX`（LEN=0）→ 回 RETURN，随后 `PTYPE_YC` / `PTYPE_YX` 报文，DAT 为若干连续 ZHREC_YC / ZHREC_YX
12. **检查帧格式**：`PTYPE_CHKFRMFMT`（LEN=2）→ 回 `PTYPE_RETURN`（LEN=0）。收到 LEN=0 的 RETURN 表示支持类型二

`model`：`0x0002` ZH-2 / `0x002A` ZH-2A / `0x002B` ZH-2B / `0x02BA` ZH-2B+ / `0x0101` ZH-101。

## 大数据传输

文件传输、目录结果集、查询结果集均为"大数据"，按 `pktsize` 分多包：

- **平衡模式**（`#frmdelay=0`）：子站连续发送，不等确认
- **非平衡模式**（`#frmdelay=N`）：子站收到主站确认或等 N 毫秒后发下一包

确认报文：`TYP = PTYPE_RETURN, LEN = 0`。

## 专用文件

| 文件名 | 类型 | 说明 |
|--------|------|------|
| ZHREC.SCFF | BINARY | 通道配置文件 |
| ZHREC.FDZ | BINARY | 定值文件 |
| ZHREC.INI | BINARY | 系统工作环境配置 |
| ZHREC.FDZ.103 | ASCII | 定值文件的 103-ASDU-10 格式 |
| GAIN.INI | ASCII | ZH-101 通道增益配置 |
| RECENT.LST | BINARY | 最近 100 个故障录波文件列表（FAULT_INFO 结构，时间递增） |
| COMM.INI | ASCII | 通信参数配置 |
| *.zyd | BINARY | 原始格式故障录波数据 |
| *.sti | ASCII | 启动信息记录 |
| *.rpt | ASCII | 故障分析报告（可作 hdr） |
| *.cfg / *.dat / *.ext | ASCII/BINARY | COMTRADE 配置/数据/扩展 |

## COMM.INI 关键字

`#model=`（装置型号）、`#timeout=`（1—30 分钟，默认 5）、`#maxconn=`（1—20，默认 5）、
`#pktsize=`（248—16376，默认 16376）、`#frmdelay=`（0—30000 ms，默认 0）。

## 本实现范围

- 逐包解析：两种帧格式、全部 TYP、7 个结构体、枚举中文映射
- 多包文件重组：按 `FILE_INFO.name` 分组、按 `offset` 排序拼接 `FILE_DATA`，导出为文件
- 端口不绑定，通过「录波器规约 → 武汉中原录波器规约解析」触发 Decode As（中性抓包）
