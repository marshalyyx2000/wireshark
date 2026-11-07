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


def main() -> int:
    ap = argparse.ArgumentParser(description="IEC 60870-5-103 network simulator")
    ap.add_argument("--vendor", choices=["sifang", "nrelectric"], default="sifang")
    ap.add_argument("--mode", choices=["both", "emit"], default="both")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--pcap", type=Path, default=None)
    ap.add_argument("--duration", type=float, default=10.0)
    args = ap.parse_args()

    emit_only = args.mode == "emit"
    if args.vendor == "sifang":
        return run_sifang(args.host, args.pcap, args.duration, emit_only)
    return run_nrelectric(args.host, args.pcap, args.duration, emit_only)


if __name__ == "__main__":
    raise SystemExit(main())
