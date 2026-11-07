# IEC 60870-5-103 仿真与测试

本目录提供四套厂商 103 仿真工具与验证脚本。串口走 com0com 虚拟串口对，网络走本机回环。

## 中性抓包原则

**抓包文件不带任何协议提示。** 现场抓包时并不知道是哪家的 103，甚至不确定是不是 103，
因此：

- 串口抓包一律是 `serial_raw`（显示为 `Serial Raw`），不写入厂商解析器名
- 网络抓包是普通 Ethernet/IPv4/TCP/UDP 帧，所有 103 解析器**默认不绑定端口**
- 解析只在用户从菜单选择规约后才发生：
  - 串口：`串口103 → 四方/深圳南瑞/许继/南自串口103规约解析`（设置 `serial_raw.payload_dissector`）
  - 网络：`网络103 → 四方/南瑞/南自/许继/深圳南瑞/山东`（对端口应用 Decode As）

`verify.py` 会先断言"未选择时不出现任何 103 协议"，再断言选择后的解析结果。

## 目录

| 路径 | 作用 |
|------|------|
| `tools/iec103-sim/iec103_core.py` | FT1.2 组帧、ASDU 构造、点表读取、pcap 写入 |
| `tools/iec103-sim/iec103_serial_sim.py` | 四方 / 深圳南瑞串口 103 的模拟保护与模拟客户端 |
| `tools/iec103-sim/iec103_net_sim.py` | 四方 UDP 网络 103、南瑞 TCP 1048 + UDP 1032 |
| `tools/iec103-tests/build_pcaps.py` | 生成中性基准 pcap（不需要串口/网卡） |
| `tools/iec103-tests/verify.py` | 中性性 + ASDU 覆盖 + 字段 + 点表 + malformed 断言 |
| `tools/iec103-tests/run_serial_live.py` | com0com 实机双向联调 |
| `tools/iec103-tests/run_net_live.py` | 本机 UDP/TCP 回环联调 |
| `tools/iec103-docs/` | 公开规约资料摘要与 `SOURCES.md` |
| `resources/share/wireshark/iec103/points/*.csv` | 厂商点表（FUN/INF → 点名） |

## 串口仿真（com0com）

```bat
python tools\iec103-sim\iec103_serial_sim.py --vendor sifang --mode both --port COM6 --peer COM7
python tools\iec103-sim\iec103_serial_sim.py --vendor sznari --mode protection --port COM7
python tools\iec103-sim\iec103_serial_sim.py --vendor sifang --mode wire --port COM6 --pcap out.pcap
```

参数：9600 / 8E1。`--mode wire` 用于配合 serialdump 抓 `serial_raw`；抓包后在界面走
**串口103 → 四方/深圳南瑞串口103规约解析**。

## 网络仿真

```bat
python tools\iec103-sim\iec103_net_sim.py --vendor sifang --mode both
python tools\iec103-sim\iec103_net_sim.py --vendor nrelectric --mode both
```

- 四方：UDP 1888（装置发）/ 1889（主站发），载荷为裸 103 ASDU
- 南瑞：TCP 1048 主站为服务端、装置为客户端；UDP 1032 为 41 字节主站在线广播

## 验证

```bat
python tools\iec103-tests\build_pcaps.py
python tools\iec103-tests\verify.py
python tools\iec103-tests\run_serial_live.py --vendor sifang --master COM6 --peer COM7
python tools\iec103-tests\run_serial_live.py --vendor sznari --master COM6 --peer COM7
python tools\iec103-tests\run_net_live.py --vendor sifang
python tools\iec103-tests\run_net_live.py --vendor nrelectric
```

`verify.py` 的断言项：

1. **中性性**：不加任何选择时，该 pcap 不出现任何 103 协议
2. 选择解析器后过滤器命中帧数 > 0
3. 期望的 ASDU 类型全部出现
4. COT / FUN / INF / DPI / CP56Time2a 等关键字段非空
5. 点表名称出现在解析树中
6. 无 `Malformed`

结果汇总见 `REPORT.md`。仿真器需要 `pip install pyserial`（仅串口模式）。
