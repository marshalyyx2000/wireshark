# NARI network 103 test harness (Python)

Simulates **master** (TCP server :1048 + UDP :1032) and **slave** (TCP client) per 国电南自以太网 103 规约.  
录波流程仿照 `171_nz_103_net.txt`（ASDU23/24/25/26/27/29/30/31）。

## Quick test (no capture)

```powershell
cd tools\nari-net-iec103
python nari_net_master.py --host 127.0.0.1 --addr 3
# another terminal:
python nari_net_slave.py --host 127.0.0.1 --addr 3
```

Master 顺序：
1. 对地址 1/2/3 发 ASDU24(TOO=24) 召唤录波列表 → 收 ASDU23
2. ASDU24 选择故障 → ASDU26
3. ASDU24 请求通道表 → ASDU29/31
4. 逐通道 ASDU25 → ASDU27 → ASDU24 确认 → ASDU30 数据 → ASDU31

## Capture + Wireshark verify (loopback)

```powershell
powershell -ExecutionPolicy Bypass -File tools\nari-net-iec103\run_local_capture_verify.ps1
```

Opens `tools/nari-net-iec103/out/nari_net_103_loopback.pcapng` — filter `nari_net_iec103`.

Manual capture filter: `host 127.0.0.1 and (tcp port 1048 or udp port 1032)`

## Modules

| File | Role |
|------|------|
| `nari_net_iec103_codec.py` | ASDU/UDP builders, stream split |
| `nari_wave_recording.py` | 录波 ASDU23–31 编解码与样例数据 |
| `nari_wave_master.py` | 主站录波召唤状态机 |
| `nari_wave_slave.py` | 子站录波响应状态机 |
| `nari_net_master.py` / `nari_net_slave.py` | TCP 主从入口 |
