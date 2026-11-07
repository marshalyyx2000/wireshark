# -*- coding: utf-8 -*-
"""Build reference pcaps for every vendor/link combination.

Output: tools/iec103-tests/out/<vendor>_<link>.pcap

Serial records carry an Exported PDU dissector name so the vendor FT1.2
dissector runs directly (the GUI also supports neutral serial_raw + try-decode).
Network records cover the real transport framing:
  * sifang     -> Ethernet/IPv4/UDP:1888 datagrams, one raw ASDU each
  * nrelectric -> Ethernet/IPv4/TCP:1048 stream plus a UDP:1032 broadcast
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path
from typing import List, Tuple

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "iec103-sim"))

import iec103_core as c103  # noqa: E402
import iec103_serial_sim as ssim  # noqa: E402
import iec103_net_sim as nsim  # noqa: E402

OUT = HERE / "out"
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
    total_len = 20 + len(udp)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total_len, 0, 0x4000, 1, 17, 0,
                     _ip(src_ip), _ip(dst_ip))
    ip = ip[:10] + struct.pack(">H", _cksum(ip)) + ip[12:]
    eth = _mac(dst_mac) + _mac(src_mac) + struct.pack(">H", 0x0800)
    return eth + ip + udp


def ipv4_tcp(src_ip: str, dst_ip: str, sport: int, dport: int, seq: int,
             ack: int, flags: int, payload: bytes = b"",
             src_mac: str = "00:11:22:33:44:55",
             dst_mac: str = "00:11:22:33:44:66") -> bytes:
    offset_flags = (5 << 12) | flags
    tcp = struct.pack(">HHIIHHHH", sport, dport, seq, ack, offset_flags, 8192, 0, 0)
    total_len = 20 + len(tcp) + len(payload)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, total_len, 0, 0x4000, 1, 6, 0,
                     _ip(src_ip), _ip(dst_ip))
    ip = ip[:10] + struct.pack(">H", _cksum(ip)) + ip[12:]
    eth = _mac(dst_mac) + _mac(src_mac) + struct.pack(">H", 0x0800)
    return eth + ip + tcp + payload


def write_eth_pcap(path: Path, records: List[Tuple[float, bytes]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in records:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            fh.write(frame)


# ---------------------------------------------------------------- builders

def serial_records(vendor: str) -> List[Tuple[float, bytes, str]]:
    """Serial captures are protocol-neutral: every record is serial_raw."""
    out: List[Tuple[float, bytes, str]] = []
    ts = 1_700_000_000.0
    for _direction, frame in ssim.build_conversation(vendor, ADDR):
        out.append((ts, frame, "serial_raw"))
        ts += 0.03
    _ = vendor
    return out


def sifang_net_records() -> List[Tuple[float, bytes]]:
    """Neutral Ethernet/IPv4/UDP frames: nothing marks them as 103."""
    out: List[Tuple[float, bytes]] = []
    ts = 1_700_000_000.0
    for asdu in nsim.sifang_master_asdus() + nsim.sifang_asdus():
        out.append((ts, ipv4_udp("192.168.10.20", "236.8.8.8", 1889, 1888, asdu)))
        ts += 0.02
    return out


def nrelectric_net_records() -> List[Tuple[float, bytes]]:
    out: List[Tuple[float, bytes]] = []
    ts = 1_700_000_000.0

    # UDP 1032 master broadcast (master -> device)
    out.append((ts, ipv4_udp("192.168.10.20", "192.168.10.30", 50000, 1032,
                             nsim.nr_broadcast(), dst_mac="00:11:22:33:44:66")))
    ts += 0.02

    # TCP handshake: device (client) -> master (server) on 1048
    seq_c, seq_s = 1000, 5000
    out.append((ts, ipv4_tcp("192.168.10.30", "192.168.10.20", 49000, 1048,
                             seq_c, 0, 0x02, dst_mac="00:11:22:33:44:55")))
    ts += 0.01
    out.append((ts, ipv4_tcp("192.168.10.20", "192.168.10.30", 1048, 49000,
                             seq_s, seq_c + 1, 0x12, dst_mac="00:11:22:33:44:66")))
    ts += 0.01
    out.append((ts, ipv4_tcp("192.168.10.30", "192.168.10.20", 49000, 1048,
                             seq_c + 1, seq_s + 1, 0x10, dst_mac="00:11:22:33:44:55")))
    ts += 0.02

    for asdu in nsim.nrelectric_asdus():
        out.append((ts, ipv4_tcp("192.168.10.30", "192.168.10.20", 49000, 1048,
                                 seq_c + 1, seq_s + 1, 0x18, asdu,
                                 dst_mac="00:11:22:33:44:55")))
        out.append((ts + 0.005, ipv4_tcp("192.168.10.20", "192.168.10.30", 1048,
                                         49000, seq_s + 1, seq_c + 1 + len(asdu),
                                         0x10, dst_mac="00:11:22:33:44:66")))
        seq_c += len(asdu)
        ts += 0.02
    return out


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    produced = []

    for vendor in ("sifang", "sznari"):
        path = OUT / f"{vendor}_serial.pcap"
        c103.write_pcap(path, serial_records(vendor))
        produced.append((path, len(serial_records(vendor))))

    path = OUT / "sifang_net.pcap"
    write_eth_pcap(path, sifang_net_records())
    produced.append((path, len(sifang_net_records())))

    path = OUT / "nrelectric_net.pcap"
    write_eth_pcap(path, nrelectric_net_records())
    produced.append((path, len(nrelectric_net_records())))

    # 金智 / 积成: reuse the neutral Ethernet writers from the simulator.
    for vendor in ("jinzhi", "jicheng"):
        path = OUT / f"{vendor}_net.pcap"
        runner = nsim.run_jinzhi if vendor == "jinzhi" else nsim.run_jicheng
        runner("127.0.0.1", path, 1.0, True)
        produced.append((path, 0))

    for path, count in produced:
        suffix = f"{count} frames" if count else "see simulator output"
        print(f"{path.relative_to(ROOT)}  ({suffix}, {path.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
