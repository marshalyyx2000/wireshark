# 许继串口 IEC 60870-5-103

依据：`许继103通信规约.pdf`（许继电气 CBZ8000，2005-12-11；执行 IEC60870-5-103 / DL/T 667-1999）。

## 物理 / 链路

- RS232/RS485，异步 **8E1**，**9600 bit/s**，主从（装置为从站）
- 固定帧：`10H | C | A | CS | 16H`（CS=C+A）
- 可变帧：`68H | L | L | 68H | C | A | ASDU | CS | 16H`（`L = ASDU字节数+2`）
- 广播地址：链路/COMADDR = `0xFF`

## ASDU

串口 ASDU 头为 **6 字节**：`TYPE | VSQ | COT | COMADDR | FUN | INF`。正文按许继定义（ASDU5 型号/版本、遥信 CP32、录波 26/27/30 等）。

## 抓包（中性，与禹舜 Modbus 相同）

**不要**把规约名写进 Exported PDU。用 FT1.2 分帧 + `serial_raw`：

```text
python xuji_serial_iec103_sim.py --mode wire --port CNCA0
serialdump --port CNCB0 --baudrate 9600 --parity even --framing ft12 --protocol serial_raw --fifo captures/xuji_serial_iec103.pcap --capture
```

打开抓包后协议列为 **Serial Raw**。再点主菜单：

**串口103 → 许继串口103规约解析**

即可试解为 `xuji_serial_iec103`（与禹舜：MODBUS → 禹舜… 相同流程）。

| 组件 | 路径 |
|------|------|
| 解析器 | `epan/dissectors/packet-xuji-serial-iec103.c` |
| 仿真 | `tools/xuji-serial-iec103/xuji_serial_iec103_sim.py` |
