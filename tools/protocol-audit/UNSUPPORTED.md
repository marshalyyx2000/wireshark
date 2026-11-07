# 未能实现规约解析的厂家（依据审计结论）

本文件记录 `tools/现场运行的各种规约程序/PROTOCOL` 下 87 家厂家实现中，
**无法从参考源码推导出可验证帧格式**的那几家，以及具体原因。这样做的目的是
避免"看起来支持、实际靠猜"的解析器——那比不支持更危险。

## 一、纯对时 / GPS 授时类（按需求不做规约解析）

这些厂家目录里没有保护规约报文，只有 GPS/授时设备的 ASCII 或定长二进制
授时报文，参考实现的动作是 `SetLocalTime()` 把时钟写进本机。

| 目录 | 帧特征（参考实现） |
|---|---|
| `GPS_JC_DDX_COM` | GPS 授时 |
| `GPS_MH202` | GPS 授时 |
| `GPS_SF_CSN_1A_COM` | GPS 授时 |
| `GPS_VatechHydro_TCR510SAT_COM` | GPS 授时 |
| `KH_12` / `KH_20` | `'S' 'T' <hh mm ss dd MM yy> 'A'`，54 字节定长 |
| `KH_2000` / `KH_2000_` / `KH_2022` | `'S' 'T' <14 字节 BCD> <校验> 'A'` |
| `BSS_3` | `0x01` … `0x0D 0x0A`，20 字节 |
| `BSS_3II` / `BSS_3_YongHe` | `0x00 0xFF 0x81 <年 月 日 时 分 秒>` |
| `ARBITER_1088AB` | `0x01` … `0x20 0x0D 0x0A` |
| `SX_TD_04` / `SX_TD_2000` | `'D'`/`0x44` 命令，BCD 时标 |
| `SDZR_CEP220B_COM` | `'S' 'T' <hh mm ss dd MM yyyy> 'A'` |
| `SDZR_CEP223_COM` | `'A' 'T' <hh mm ss dd MM yy>` |
| `HJTF_HJ201_COM` | `$GPRMC` NMEA 语句 |
| `SZ_4U_ASCII` | `'B' 'J' 'T'` 前缀 ASCII |
| `SZ_ZU_ASCII` | `0x02` (STX) 前缀 ASCII |

## 二、帧由闭源动态库构造（源码中无 buf 布局）

| 目录 | 原因 |
|---|---|
| `WHFount_FTR_TCP` | 收发与组帧全部通过 `SttpEngineC.dll` 的导出函数完成，源码只有 socket 管理与业务回调，没有任何 `buf[i++] = ...` 序列可据以还原帧结构。 |
| `Toshiba_Com_RSM` | 组帧由闭源 `GrComm` 库（`_GrCommSendReceive`）完成；源码里唯一可见的帧内容是文件写出用的 ASCII 时间戳，与通信帧无关。<br>**已实现部分**：以 `tosbia_com_rsm` 注册，做帧边界与原始主体呈现，不解释字段。 |
| `ABB103` | `SttpEngineC.dll` 负责规约引擎，但源码里仍有完整的 FT1.2 可变帧构造（`Rtu.cpp`），因此**已实现**为 `abb103_serial_iec103`。 |

## 三、非通信协议（文件转换 / 目录监视）

| 目录 | 实际功能 |
|---|---|
| `HZ1000` | 只做录波文件格式转换（`FindFirstFile` + 解析本地文件），没有通信帧。 |
| `DataSpy` | 目录监视 + 自动文件发送，走 Windows 文件共享/FTP，没有自有规约帧。 |
| `ShareDir` | 共享目录扫描 + ICMP 探测，同上。 |
| `FtpClient` | 标准 FTP 客户端（`CXJ_FTP`），报文是标准 FTP 命令，由 Wireshark 的 `ftp`/`ftp-data` 解析器覆盖。 |
| `HathAwayIDM` | 监听 TCP 后按 `Structs.h` 的定长结构体拷贝，结构体是主机字节序的内存布局而非线路格式。 |

## 结论

- 87 家中 **61 家**已实现并逐个厂家做了模拟器 + 中性 pcap 断言。
- **20 家**为纯对时/GPS 授时类，按需求不做规约解析。
- **6 家**因上述客观原因无法从参考实现推导帧格式；其中 `Toshiba_Com_RSM`
  仍提供帧边界与主体呈现，其余 5 家建议使用现有的通用解析器
  （`ftp`、`smb`、`ftp-data`）或等待实机抓包补充。
