# -*- coding: utf-8 -*-
"""Copy an exported-PDU pcap and replace dissector name tag value."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

PCAP_HEADER = 24
EXP_PDU_TAG_DISSECTOR_NAME = 12


def retag(src: Path, dst: Path, new_proto: str) -> int:
    data = src.read_bytes()
    if len(data) < PCAP_HEADER:
        raise SystemExit("short pcap")
    out = bytearray(data[:PCAP_HEADER])
    off = PCAP_HEADER
    n = 0
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, orig = struct.unpack_from("<IIII", data, off)
        off += 16
        pkt = bytearray(data[off : off + incl])
        off += incl
        # parse first TLV
        if len(pkt) >= 4:
            tag, tlen = struct.unpack_from(">HH", pkt, 0)
            if tag == EXP_PDU_TAG_DISSECTOR_NAME:
                name = new_proto.encode("ascii") + b"\x00"
                name_len = (len(name) + 3) & ~3
                namebuf = name + b"\x00" * (name_len - len(name))
                # find end_opt after old name
                old_name_len = tlen
                rest = pkt[4 + old_name_len :]
                # rest starts with end_opt(4) + payload
                new_pkt = bytearray()
                new_pkt += struct.pack(">HH", EXP_PDU_TAG_DISSECTOR_NAME, name_len)
                new_pkt += namebuf
                new_pkt += rest
                pkt = new_pkt
                incl = len(pkt)
                orig = incl
        out += struct.pack("<IIII", ts_sec, ts_usec, incl, orig)
        out += pkt
        n += 1
    dst.write_bytes(out)
    print(f"retag {n} packets -> {dst} proto={new_proto}")
    return n


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: retag_pcap_proto.py src.pcap dst.pcap proto")
    retag(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])