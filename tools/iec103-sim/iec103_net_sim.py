# -*- coding: utf-8 -*-
"""Vendor simulator: 四方 (sifang) UDP network 103 and 南瑞 (nrelectric) TCP 103.

sifang (CSC2000): master listens on UDP 1888, device sends ASDUs to 1888 and the
master replies on 1889. Each datagram carries exactly one raw 103 ASDU.

nrelectric: master is a TCP *server* on 1048, device connects as client and both
sides stream raw ASDUs (no APCI). UDP 1032 carries the 41-byte master broadcast.

Usage
    python iec103_net_sim.py --vendor sifang --mode both
    python iec103_net_sim.py --vendor nrelectric --mode both
    python iec103_net_sim.py --vendor sifang --mode emit --pcap out.pcap
"""
from __future__ import annotations

import argparse
import socket
import struct
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import iec103_core as c103  # noqa: E402

SIFANG_DEV_PORT = 1888
SIFANG_MASTER_PORT = 1889
SIFANG_MCAST = "236.8.8.8"

NR_TCP_PORT = 1048
NR_UDP_PORT = 1032
NR_BCAST_LEN = 41

ADDR = 0x03


# ---------------------------------------------------------------- Ethernet io

def _mac(text: str) -> bytes:
    return bytes(int(x, 16) for x in text.split(":"))


def _ip(text: str) -> bytes:
    return bytes(int(x) for x in text.split("."))


def _cksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_udp(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes,
             src_mac: str = "00:11:22:33:44:55",
             dst_mac: str = "01:00:5e:08:08:08") -> bytes:
    udp = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0x4000, 1, 17, 0,
                     _ip(src_ip), _ip(dst_ip))
    ip = ip[:10] + struct.pack(">H", _cksum(ip)) + ip[12:]
    return _mac(dst_mac) + _mac(src_mac) + struct.pack(">H", 0x0800) + ip + udp


def ipv4_tcp(src_ip: str, dst_ip: str, sport: int, dport: int, seq: int,
             ack: int, flags: int, payload: bytes = b"",
             src_mac: str = "00:11:22:33:44:55",
             dst_mac: str = "00:11:22:33:44:66") -> bytes:
    tcp = struct.pack(">HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, 8192, 0, 0)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 0,
                     0x4000, 1, 6, 0, _ip(src_ip), _ip(dst_ip))
    ip = ip[:10] + struct.pack(">H", _cksum(ip)) + ip[12:]
    return _mac(dst_mac) + _mac(src_mac) + struct.pack(">H", 0x0800) + ip + tcp + payload


def write_net_pcap(path: Path, records: List[Tuple[float, bytes, str]]) -> None:
    """Write plain Ethernet frames; the dissector tag in ``records`` is unused.

    Network captures must stay protocol-neutral, so no Exported PDU header or
    dissector name is written. The third tuple element is ignored on purpose.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame, _tag in records:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            fh.write(frame)


def sifang_asdus(addr: int = ADDR) -> List[bytes]:
    """Device (slave) side ASDUs for 四方 network 103."""
    return [
        c103.asdu_ident(addr, desc=b"SIFANG CSC2000 103"),
        c103.asdu_protection_event(addr, c103.FUN_DISTANCE, 16, dpi=2),
        c103.asdu_protection_event(addr, c103.FUN_DISTANCE, 17, dpi=2),
        c103.asdu_protection_event(addr, c103.FUN_OVERCURRENT, 16, dpi=2),
        c103.asdu_measured(addr, c103.FUN_OVERCURRENT, 0, [1.732, 2.045, 1.998]),
        c103.asdu_time_tagged(addr, c103.FUN_DISTANCE, 16, dpi=2),
        c103.asdu_generic(addr, [
            c103.gdd_entry(1, 1, 0x01, 7, 4, b"\x41\x20\x00\x00"),
            c103.gdd_entry(2, 1, 0x01, 2, 1, b"\x01"),
        ], cot=c103.COT_SPONT),
        c103.asdu_dist_header(addr, 1, [(7, 0x03, None)]),
        c103.asdu_dist_cmd(addr, 24),
        c103.asdu_dist_ready(addr, 1, 7, 1, 1, 0),
        c103.asdu_chan_ready(addr, 1, 7, 1, 100.0, 1.0, 0.01),
        c103.asdu_flag_ready(addr, 1, 7, 2),
        c103.asdu_flag_data(addr, 1),
        c103.asdu_dist_data(addr, [1000, 1200, 1400, 1600]),
        c103.asdu_dist_end(addr, 32),
    ]


def sifang_master_asdus(addr: int = ADDR) -> List[bytes]:
    return [
        c103.asdu_gi_start(addr, scn=1),
        c103.asdu_time_sync(addr),
        c103.asdu_command(addr, dco=0x02, rii=3),
        c103.asdu_dist_cmd(addr, 24),
        c103.asdu_dist_ack(addr, 64),
        c103.asdu_generic_cmd(addr, 1, [
            c103.gdd_entry(1, 1, 0x01, 0, 0, b""),
        ]),
    ]


def run_sifang(host: str, pcap: Path | None, duration: float, emit_only: bool) -> int:
    """Emit neutral Ethernet/IPv4/UDP frames on the documented 1888/1889 ports.

    Nothing in the capture marks the payload as 103; the user picks the
    dissector from 网络103 → 四方网络103规约解析.
    """
    records: List[Tuple[float, bytes, str]] = []
    start = time.time()

    for asdu in sifang_master_asdus():
        records.append((time.time() - start,
                        ipv4_udp("192.168.10.20", "236.8.8.8", SIFANG_MASTER_PORT,
                                 SIFANG_DEV_PORT, asdu), ""))
        time.sleep(0.01)
    for asdu in sifang_asdus():
        records.append((time.time() - start,
                        ipv4_udp("192.168.10.30", "236.8.8.8", SIFANG_DEV_PORT,
                                 SIFANG_DEV_PORT, asdu), ""))
        time.sleep(0.01)

    if pcap:
        write_net_pcap(pcap, records)
        print(f"pcap: {pcap} ({len(records)} datagrams, neutral Ethernet)")
    _ = (duration, emit_only, host)
    return 0


def nr_broadcast(dt: datetime | None = None) -> bytes:
    dt = dt or datetime.now()
    ms = dt.microsecond // 1000 + dt.second * 1000
    dow = dt.isoweekday() % 7
    body = bytes((
        0xFF, 0x01,
        ms & 0xFF, (ms >> 8) & 0xFF,
        dt.minute & 0x3F, dt.hour & 0x1F,
        (dt.day & 0x1F) | ((dow & 0x07) << 5),
        dt.month & 0x0F, dt.year % 100,
    ))
    body += bytes(16)      # master free-form
    body += bytes(16)      # zero padding
    assert len(body) == NR_BCAST_LEN
    return body


def nrelectric_asdus(addr: int = ADDR) -> List[bytes]:
    return [
        c103.asdu_ident(addr, desc=b"NRELEC  PRS-103  V1.0"),
        c103.asdu_time_tagged(addr, c103.FUN_OVERCURRENT, 18, dpi=1),
        c103.asdu_time_sync(addr),
        c103.asdu_gi_start(addr, scn=2),
        c103.asdu_protection_event(addr, c103.FUN_DISTANCE, 16, dpi=2),
        c103.asdu_protection_event(addr, c103.FUN_LINE_DIFF, 16, dpi=2),
        c103.asdu_protection_event(addr, c103.FUN_TRAFO_DIFF, 16, dpi=1),
        c103.asdu_measured(addr, c103.FUN_OVERCURRENT, 0, [0.95, 1.02, 0.88]),
        c103.asdu_generic(addr, [
            c103.gdd_entry(30, 1, 0x01, 3, 1, b"\x05"),
            c103.gdd_entry(32, 1, 0x01, 7, 4, b"\x42\x20\x00\x00"),
            c103.gdd_entry(36, 1, 0x01, 2, 1, b"\x02"),
        ], cont=True),
        c103.asdu_gi_end(addr, scn=2),
        c103.asdu_dist_header(addr, 2, [(7, 0x03, None), (8, 0x02, None)]),
        c103.asdu_dist_cmd(addr, 24),
        c103.asdu_dist_ack(addr, 64),
        c103.asdu_dist_ready(addr, 1, 7, 2, 1, 0),
        c103.asdu_chan_ready(addr, 1, 7, 1, 110.0, 1.0, 0.1),
        c103.asdu_flag_ready(addr, 1, 7, 2),
        c103.asdu_flag_data(addr, 1),
        c103.asdu_dist_data(addr, [500, 900, 1400, 2100, 1800]),
        c103.asdu_dist_end(addr, 32),
    ]


def run_nrelectric(host: str, pcap: Path | None, duration: float, emit_only: bool) -> int:
    records: List[Tuple[float, bytes, str]] = []
    start = time.time()

    if emit_only:
        ts = start
        records.append((ts, ipv4_udp("192.168.10.20", "192.168.10.30", 50000, NR_UDP_PORT,
                                     nr_broadcast(), dst_mac="00:11:22:33:44:66"),
                        ""))
        ts += 0.02
        seq_c, seq_s = 1000, 5000
        records.append((ts, ipv4_tcp("192.168.10.30", "192.168.10.20", 49000, NR_TCP_PORT,
                                     seq_c, 0, 0x02, dst_mac="00:11:22:33:44:55"), ""))
        ts += 0.01
        records.append((ts, ipv4_tcp("192.168.10.20", "192.168.10.30", NR_TCP_PORT, 49000,
                                     seq_s, seq_c + 1, 0x12,
                                     dst_mac="00:11:22:33:44:66"), ""))
        ts += 0.01
        records.append((ts, ipv4_tcp("192.168.10.30", "192.168.10.20", 49000, NR_TCP_PORT,
                                     seq_c + 1, seq_s + 1, 0x10,
                                     dst_mac="00:11:22:33:44:55"), ""))
        ts += 0.02
        for asdu in nrelectric_asdus():
            records.append((ts, ipv4_tcp("192.168.10.30", "192.168.10.20", 49000, NR_TCP_PORT,
                                         seq_c + 1, seq_s + 1, 0x18, asdu,
                                         dst_mac="00:11:22:33:44:55"), ""))
            records.append((ts + 0.005,
                            ipv4_tcp("192.168.10.20", "192.168.10.30", NR_TCP_PORT, 49000,
                                     seq_s + 1, seq_c + 1 + len(asdu), 0x10,
                                     dst_mac="00:11:22:33:44:66"), ""))
            seq_c += len(asdu)
            ts += 0.02
        if pcap:
            write_net_pcap(pcap, records)
            print(f"pcap: {pcap} ({len(records)} frames, neutral Ethernet)")
        return 0

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, NR_TCP_PORT))
    server.listen(1)
    server.settimeout(duration)

    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind((host, 0))

    try:
        udp.sendto(nr_broadcast(), (host, NR_UDP_PORT))
        conn, _peer = server.accept()
        conn.settimeout(2.0)
        frames = nrelectric_asdus()
        for asdu in frames:
            conn.sendall(asdu)
            records.append((time.time() - start, asdu, "nrelectric_net_iec103"))
            time.sleep(0.02)
        try:
            echo = conn.recv(4096)
            if echo:
                records.append((time.time() - start, echo, "nrelectric_net_iec103"))
        except socket.timeout:
            pass
        conn.close()
    finally:
        server.close()
        udp.close()

    if pcap:
        c103.write_pcap(pcap, records)
        print(f"pcap: {pcap} ({len(records)} frames)")
    return 0


# ---------------------------------------------------------------- 金智 (TCP 6000)

JZ_TCP_PORT = 6000
JZ_CTRL_LEN = 12          # 12- or 13-byte control field; see jinzhi.md


def jz_apdu(asdu: bytes, ctrl_len: int = JZ_CTRL_LEN, ns: int = 0, nr: int = 0,
            src_station: int = 1, src_dev: int = 0x0101,
            dst_station: int = 1, dst_dev: int = 0xFEFE,
            u_func: int | None = None) -> bytes:
    """Build one 金智 APDU: 68H + LE length + extended control + ASDU.

    The length field counts control + ASDU only; it excludes the 3-byte prefix
    (jinzhi.md, 链路层规范 传输层控制报文).
    """
    if u_func is not None:
        ctrl = bytes((u_func, 0, 0, 0))
    elif asdu:
        ctrl = bytes((((ns & 0x7F) << 1) | 0x00, (ns >> 7) & 0xFF,
                      ((nr & 0x7F) << 1) | 0x00, (nr >> 7) & 0xFF))
    else:
        ctrl = bytes(((nr & 0x7F) << 1, (nr >> 7) & 0xFF, 0, 0))
        ctrl = bytes((0x01, 0, ((nr & 0x7F) << 1) | 0x00, (nr >> 7) & 0xFF))
    addr = bytes((src_station & 0xFF, src_dev & 0xFF, (src_dev >> 8) & 0xFF,
                  dst_station & 0xFF, dst_dev & 0xFF, (dst_dev >> 8) & 0xFF))
    ctrl = ctrl + addr + bytes(ctrl_len - 10)
    body = ctrl + asdu
    return bytes((0x68, len(body) & 0xFF, (len(body) >> 8) & 0xFF)) + body


def jinzhi_asdus(addr: int = ADDR) -> List[bytes]:
    """Protection (server) side ASDUs for 金智 network 103."""
    return [
        c103.asdu_ident(addr, desc=b"JINZHI  WKB-801  V2.00"),
        c103.asdu_gi_end(addr, scn=1),
        # 通用分类：组号放在 INF，条目标题在 GDD 内（应用层规范 4.x）
        c103.asdu_generic(addr, [
            c103.gdd_entry(1, 0, 0x01, 7, 4, struct.pack(">f", 5.0)),
        ], cot=c103.COT_SPONT, fun=c103.FUN_GENERIC, inf=5),      # 动作元件
        c103.asdu_generic(addr, [
            c103.gdd_entry(1, 0, 0x01, 3, 1, b"\x00"),
        ], cot=c103.COT_SPONT, fun=c103.FUN_GENERIC, inf=6),      # 装置自检
        c103.asdu_generic(addr, [
            c103.gdd_entry(1, 0, 0x01, 3, 1, b"\x00"),
        ], cot=c103.COT_SPONT, fun=c103.FUN_GENERIC, inf=7),      # 运行告警        # ASDU220 通用历史数据查询
        c103.asdu_header(0xDC, 0x80, addr, c103.FUN_GLOBAL, 0)
        + bytes((1,)) + c103.cp56() + c103.cp56() + bytes((9,)),
        # ASDU222 文件目录响应：FNAM(2) FLEN(4) SOF(1) FTIM(7)
        c103.asdu_header(0xDE, 0x82, 0xFF, c103.FUN_GLOBAL, 0)
        + bytes((0x01, 0x00)) + struct.pack("<I", 4096) + bytes((0x01,)) + c103.cp56(),
        # ASDU223 文件准备就绪：FNAM(2) SNAM(1) FLEN(4) FRQ(1)
        c103.asdu_header(0xDF, 0x82, 0xFF, c103.FUN_GLOBAL, 0)
        + bytes((0x01, 0x00, 0x00)) + struct.pack("<I", 4096) + bytes((0x00,)),
        # ASDU224 节准备就绪：FNAM(2) SNAM(1) SLEN(4) SRQ(1)
        c103.asdu_header(0xE0, 0x82, 0xFF, c103.FUN_GLOBAL, 0)
        + bytes((0x01, 0x00, 0x00)) + struct.pack("<I", 2048) + bytes((0x00,)),
        # ASDU225 段的发送：FNAM(2) SNAM(1) DLEN(2) data
        c103.asdu_header(0xE1, 0x82, 0xFF, c103.FUN_GLOBAL, 0)
        + bytes((0x01, 0x00, 0x00)) + struct.pack("<H", 8) + bytes(range(8)),
        # ASDU226 最后段/末节：FNAM(2) LSQ(1)
        c103.asdu_header(0xE2, 0x82, 0xFF, c103.FUN_GLOBAL, 0)
        + bytes((0x01, 0x00, 0x04)),
        # ASDU227 确认：AFQ
        c103.asdu_header(0xE3, 0x82, 0xFF, c103.FUN_GLOBAL, 0) + bytes((0x03,)),
        # ASDU229 遥控校验结果：RII NOG FADDR(2) DADDR(2) GIN(2) OTP
        c103.asdu_header(0xE5, 0x14, 0xFF, 0xFE, 0xF4)
        + bytes((0x01, 0x01)) + struct.pack("<H", 1) + struct.pack("<H", 0x0101)
        + struct.pack("<H", 0x0801) + bytes((0x01,)),
        # 联锁数据发送 0xCC：GIN(2) LDT(1) VALUE
        c103.asdu_header(0xCC, 0x01, 0xFF, 0xFF, 0)
        + struct.pack("<H", 0x0801) + bytes((0x00, 0x01)),
    ]


def jinzhi_master_asdus(addr: int = ADDR) -> List[bytes]:
    return [
        c103.asdu_time_sync(addr),
        c103.asdu_gi_start(addr, scn=1),
        # ASDU220 历史数据查询：事件类型 + 起止 CP56 + RII
        c103.asdu_header(0xDC, 0x80, 0xFF, 0xFF, 0)
        + bytes((0xFF,)) + c103.cp56() + c103.cp56() + bytes((0x01,)),
        # ASDU221 文件召唤/选择：FNAM(2) SNAM(1) SCQ(1)
        c103.asdu_header(0xDD, 0x82, 0xFF, 0xFF, 0)
        + bytes((0x01, 0x00, 0x00, 0x07)),
        # ASDU228 遥控校验命令
        c103.asdu_header(0xE4, 0x14, 0xFF, 0xFE, 0xF4)
        + bytes((0x01, 0x01)) + struct.pack("<H", 1) + struct.pack("<H", 0x0101)
        + struct.pack("<H", 0x0801) + bytes((0x02,)),
        # 联锁数据请求 0xCB：LQT + {DADDR GIN} + RII
        c103.asdu_header(0xCB, 0x14, 0xFF, 0xFF, 0)
        + bytes((0x00,)) + struct.pack("<H", 0x0101) + struct.pack("<H", 0x0801)
        + bytes((0x01,)),
    ]

def run_jinzhi(host: str, pcap: Path | None, duration: float, emit_only: bool) -> int:
    """Neutral Ethernet capture of a 金智 master/slave conversation on TCP 6000."""
    records: List[Tuple[float, bytes, str]] = []
    ts = time.time()

    seq_m, seq_s = 0, 0          # APDU sequence numbers (N(S) / N(R))
    isn_m, isn_s = 1000, 5000    # TCP initial sequence numbers
    off_m, off_s = 0, 0          # TCP byte offsets

    frames: List[tuple[bytes, bool]] = []
    frames.append((jz_apdu(b"", u_func=0x07, src_dev=0xFEFE, dst_dev=0x0101), True))
    frames.append((jz_apdu(b"", u_func=0x0B, src_dev=0x0101, dst_dev=0xFEFE), False))
    for asdu in jinzhi_master_asdus():
        frames.append((jz_apdu(asdu, ns=seq_m, nr=seq_s, src_dev=0xFEFE, dst_dev=0x0101), True))
        seq_m += 1
    for asdu in jinzhi_asdus():
        frames.append((jz_apdu(asdu, ns=seq_s, nr=seq_m, src_dev=0x0101, dst_dev=0xFEFE), False))
        seq_s += 1

    for payload, master_to_slave in frames:
        if master_to_slave:
            frame = ipv4_tcp("192.168.20.10", "192.168.20.30", 52000, JZ_TCP_PORT,
                             isn_m + off_m, isn_s + off_s, 0x18, payload,
                             dst_mac="00:11:22:33:44:66")
            off_m += len(payload)
        else:
            frame = ipv4_tcp("192.168.20.30", "192.168.20.10", JZ_TCP_PORT, 52000,
                             isn_s + off_s, isn_m + off_m, 0x18, payload,
                             dst_mac="00:11:22:33:44:55")
            off_s += len(payload)
        records.append((ts, frame, ""))
        ts += 0.02

    if pcap:
        write_net_pcap(pcap, records)
        print(f"pcap: {pcap} ({len(records)} frames, neutral Ethernet)")
    _ = (duration, emit_only, host)
    return 0


# ---------------------------------------------------------------- 积成 (TCP/UDP 6185)

JC_PORT = 6185


def jc_apdu(asdu: bytes, ns: int = 0, nr: int = 0, u_func: int | None = None) -> bytes:
    """Build one 积成 APDU: 68H + length + 4-byte control + ASDU."""
    if u_func is not None:
        ctrl = bytes((u_func, 0, 0, 0))
    elif asdu:
        ctrl = bytes((((ns & 0x7F) << 1) | 0x00, (ns >> 7) & 0xFF,
                      ((nr & 0x7F) << 1) | 0x00, (nr >> 7) & 0xFF))
    else:
        ctrl = bytes((0x01, 0, ((nr & 0x7F) << 1) | 0x00, (nr >> 7) & 0xFF))
    body = ctrl + asdu
    return bytes((0x68, len(body) & 0xFF)) + body


def jicheng_asdus(addr: int = ADDR) -> List[bytes]:
    """IED (server) side ASDUs for 积成 IES-N103."""
    return [
        c103.asdu_ident(addr, desc=b"JICHENG  iES-N103"),
        # 通用分类读响应 COT=42，组 09 保护测量
        c103.asdu_generic(addr, [
            c103.gdd_entry(9, 1, 0x01, 7, 4, struct.pack(">f", 1.0)),
            c103.gdd_entry(9, 2, 0x01, 7, 4, struct.pack(">f", 2.0)),
        ], cot=42, fun=254, inf=9),
        # 事件主动上送 COT=1
        c103.asdu_generic(addr, [
            c103.gdd_entry(5, 1, 0x01, 3, 1, b"\x01"),
        ], cot=c103.COT_SPONT, fun=254, inf=5),
        # 定值组读响应 COT=42
        c103.asdu_generic(addr, [
            c103.gdd_entry(4, 1, 0x01, 7, 4, struct.pack(">f", 5.0)),
        ], cot=42, fun=254, inf=4),
        c103.asdu_dist_header(addr, 1, [(7, 0x03, None)]),
        c103.asdu_dist_cmd(addr, 24),
        c103.asdu_dist_ack(addr, 64),
        c103.asdu_dist_ready(addr, 1, 7, 1, 1, 0),
        c103.asdu_chan_ready(addr, 1, 7, 1, 100.0, 1.0, 0.01),
        c103.asdu_flag_ready(addr, 1, 7, 2),
        c103.asdu_flag_data(addr, 1),
        c103.asdu_dist_data(addr, [500, 900, 1400, 2100]),
        c103.asdu_dist_end(addr, 32),
    ]


def jicheng_master_asdus(addr: int = ADDR) -> List[bytes]:
    return [
        c103.asdu_time_sync(addr),
        # 通用分类读命令 COT=42，INF F1 读一组全部条目
        c103.asdu_header(0x15, 0x81, 42, addr, 254, 9)
        + bytes((1, 9, 0, 1)),
        # 通用分类写命令 COT=40
        c103.asdu_header(0x0A, 0x81, 40, addr, 254, 0xF2) + bytes((1, 1)),
        # 一般命令 COT=20
        c103.asdu_command(addr, dco=0x02, rii=3),
        c103.asdu_dist_cmd(addr, 24),
        c103.asdu_dist_ack(addr, 64),
    ]


def jicheng_broadcast(addr: int = 0xFF) -> bytes:
    """UDP 6185 broadcast time sync (control field carries no meaning)."""
    asdu = c103.asdu_time_sync(addr)
    return bytes((0x68, 4 + len(asdu), 0, 0, 0, 0)) + asdu


def run_jicheng(host: str, pcap: Path | None, duration: float, emit_only: bool) -> int:
    """Neutral Ethernet capture of a 积成 master/IED conversation on 6185."""
    records: List[Tuple[float, bytes, str]] = []
    ts = time.time()

    # UDP broadcast first (master -> IED).
    records.append((ts, ipv4_udp("192.168.30.10", "192.168.30.255", JC_PORT, JC_PORT,
                                 jicheng_broadcast(), dst_mac="ff:ff:ff:ff:ff:ff"), ""))
    ts += 0.02

    seq_m, seq_s = 0, 0
    isn_m, isn_s = 3000, 7000
    off_m, off_s = 0, 0

    frames: List[tuple[bytes, bool]] = []
    frames.append((jc_apdu(b"", u_func=0x07), True))
    frames.append((jc_apdu(b"", u_func=0x0B), False))
    for asdu in jicheng_master_asdus():
        frames.append((jc_apdu(asdu, ns=seq_m, nr=seq_s), True))
        seq_m += 1
    for asdu in jicheng_asdus():
        frames.append((jc_apdu(asdu, ns=seq_s, nr=seq_m), False))
        seq_s += 1

    for payload, master_to_slave in frames:
        if master_to_slave:
            frame = ipv4_tcp("192.168.30.10", "192.168.30.30", 53000, JC_PORT,
                             isn_m + off_m, isn_s + off_s, 0x18, payload,
                             dst_mac="00:11:22:33:44:66")
            off_m += len(payload)
        else:
            frame = ipv4_tcp("192.168.30.30", "192.168.30.10", JC_PORT, 53000,
                             isn_s + off_s, isn_m + off_m, 0x18, payload,
                             dst_mac="00:11:22:33:44:55")
            off_s += len(payload)
        records.append((ts, frame, ""))
        ts += 0.02

    if pcap:
        write_net_pcap(pcap, records)
        print(f"pcap: {pcap} ({len(records)} frames, neutral Ethernet)")
    _ = (duration, emit_only, host)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="IEC 60870-5-103 network simulator")
    ap.add_argument("--vendor", choices=["sifang", "nrelectric", "jinzhi", "jicheng"],
                    default="sifang")
    ap.add_argument("--mode", choices=["both", "emit"], default="both")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--pcap", type=Path, default=None)
    ap.add_argument("--duration", type=float, default=10.0)
    args = ap.parse_args()

    emit_only = args.mode == "emit"
    if args.vendor == "sifang":
        return run_sifang(args.host, args.pcap, args.duration, emit_only)
    if args.vendor == "jinzhi":
        return run_jinzhi(args.host, args.pcap, args.duration, emit_only)
    if args.vendor == "jicheng":
        return run_jicheng(args.host, args.pcap, args.duration, emit_only)
    return run_nrelectric(args.host, args.pcap, args.duration, emit_only)


if __name__ == "__main__":
    raise SystemExit(main())
