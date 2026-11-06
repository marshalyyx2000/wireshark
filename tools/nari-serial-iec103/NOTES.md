# 南瑞串口 IEC 60870-5-103 仿真与抓包

## 环境

- com0com 虚拟串口对：`COM10` <-> `COM11`（本机已用 setupc 配置 CNCA0/CNCB0）
- 波特率 9600，8E1

## 一键演示

```bat
python tools\nari-serial-iec103\run_nari_serial_demo.py --open-ui
```

会启动：

1. 模拟保护（从站）`COM11`
2. 模拟客户端（主站）`COM10`
3. 抓包写入 `captures\nari_serial_iec103.pcap`（Exported PDU / `serial_raw`）
4. 另存 `captures\nari_serial_iec103_direct.pcap`（直接标为 `nari_serial_iec103` 便于 tshark 校验）

## 在本软件中解析

打开 `captures\nari_serial_iec103.pcap` 后：

**串口103 → 南瑞串口103规约解析**

## 单独进程

```bat
python nari_serial_protection.py --port COM11
python nari_serial_client.py --port COM10 --pcap ..\..\captures\nari_serial_iec103.pcap
```