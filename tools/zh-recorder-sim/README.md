# 武汉中原（中元华电 ZH 系列）录波器规约 — 仿真与验证

## 目录

| 路径 | 作用 |
|------|------|
| `zh_core.py` | 帧组装（类型一/类型二）、7 个结构体打包、分帧与解析、中性 pcap 写入 |
| `zh_recorder.py` | 模拟录波器（TCP **30282 服务端**） |
| `zh_master.py` | 模拟主站（TCP 客户端），也可只生成 pcap |
| `run_zh_demo.py` | 一键起录波器 + 主站并生成基准 pcap |

规约摘要在 [`tools/iec103-docs/zh-recorder.md`](../iec103-docs/zh-recorder.md)。

## 快速开始

```bat
:: 只生成基准抓包（类型一 / 类型二）
python tools\zh-recorder-sim\run_zh_demo.py --pcap-only
python tools\zh-recorder-sim\run_zh_demo.py --pcap-only --type2

:: 本机联调：录波器 + 主站
python tools\zh-recorder-sim\run_zh_demo.py
python tools\zh-recorder-sim\run_zh_demo.py --type2 --pkt-size 512
```

单独运行：

```bat
python tools\zh-recorder-sim\zh_recorder.py --host 127.0.0.1 --port 30282 --pkt-size 512
python tools\zh-recorder-sim\zh_master.py --host 127.0.0.1 --port 30282
```

## 在界面里解析

1. 打开抓包（协议列为普通 `TCP`，**不含任何协议提示**）
2. 点 **录波器规约 → 武汉中原录波器规约解析**
3. 协议列变为「武汉中原录波器」，过滤栏变为 `zh_recorder`

## 导出录波文件

点 **录波器规约 → 导出录波文件…**，选择输出目录。导出器按包顺序拼接
`PTYPE_FILE_DATA`，文件名取自 `PTYPE_FILE_INFO.name`。

- 拼接长度与 `FILE_INFO.size` 不一致的文件会被**跳过并列出原因**
- 只取报文中的文件名（basename），不会写到输出目录之外

## 模拟录波器上的文件

| 文件名 | 大小 | 说明 |
|--------|------|------|
| `D:\ZYHD\BIN\ZHREC.SCFF` | 290 | 通道配置 |
| `D:\ZYHD\DATA\20261107\REC001.cfg` | 658 | COMTRADE 配置 |
| `D:\ZYHD\DATA\20261107\REC001.dat` | 2048 | COMTRADE 数据（**2 包**，验证重组） |
| `D:\ZYHD\DATA\RECENT.LST` | 1004 | 2 条 `FAULT_INFO` |

## 验证

```bat
python tools\iec103-tests\verify_zh_recorder.py
python tools\iec103-tests\stress_trydecode.py
python tools\iec103-tests\fuzz_iec103.py
powershell -File tools\iec103-tests\gui_click_test.ps1
powershell -File tools\iec103-tests\memory_check.ps1
```

`verify_zh_recorder.py` 覆盖：中性性、类型一/类型二、CHS 校验、21 种 TYP、
结构体字段、枚举中文、多包重组逐字节一致、LEN 超限、逐字节截断。
