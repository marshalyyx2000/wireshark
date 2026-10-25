#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""NARI network 103 slave (TCP client → master :1048)."""

from __future__ import annotations

import argparse
import logging
import socket
import struct
import time

from nari_net_iec103_codec import (
    TCP_PORT,
    COT_GEN_READ,
    COT_SPONT,
    asdu_gen_data_entry,
    asdu_identification,
    ParsedAsdu,
    split_asdu_stream,
)
from nari_wave_slave import WaveSlaveResponder

LOG = logging.getLogger("nari_slave")


class NariNetSlave:
    def __init__(self, host: str = "127.0.0.1", port: int = TCP_PORT, addr: int = 3) -> None:
        self.host = host
        self.port = port
        self.addr = addr
        self.wave = WaveSlaveResponder(addr)

    def respond(self, parsed: ParsedAsdu) -> list[bytes]:
        if parsed.typ in (6, 7, 24, 25):
            return self.wave.respond(parsed)

        replies: list[bytes] = []
        if parsed.typ == 21:
            if parsed.inf == 241:
                replies.append(
                    asdu_gen_data_entry(
                        self.addr,
                        group=6,
                        entry=1,
                        kod=10,
                        datatype=1,
                        width=2,
                        number=1,
                        gid=b"Ia",
                        cot=COT_GEN_READ,
                        inf=241,
                        rii=parsed.payload[0] if parsed.payload else 0,
                    )
                )
            else:
                replies.append(
                    asdu_gen_data_entry(
                        self.addr,
                        group=6,
                        entry=1,
                        kod=1,
                        datatype=7,
                        width=4,
                        number=1,
                        gid=struct.pack("<f", 1.0),
                        cot=COT_GEN_READ,
                        rii=parsed.payload[0] if parsed.payload else 0,
                    )
                )
        return replies

    def run_once(self, session_sec: float = 30.0) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.host, self.port))
            LOG.info("Connected to master %s:%s (addr=%s)", self.host, self.port, self.addr)

            sock.sendall(asdu_identification(self.addr, cot=COT_SPONT))
            LOG.info("Slave sent ASDU5 identification")

            buf = bytearray()
            sock.settimeout(1.0)
            deadline = time.time() + session_sec
            while time.time() < deadline:
                try:
                    chunk = sock.recv(8192)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                buf.extend(chunk)
                frames, buf = split_asdu_stream(buf)
                for frame in frames:
                    parsed = ParsedAsdu.parse(frame)
                    if not parsed:
                        continue
                    LOG.info("Slave received: %s", parsed)
                    for reply in self.respond(parsed):
                        sock.sendall(reply)
                        LOG.info("Slave sent %d bytes: %s", len(reply), reply.hex(" "))
                        time.sleep(0.02)

            time.sleep(0.2)


def main() -> None:
    parser = argparse.ArgumentParser(description="NARI network 103 slave (TCP client)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=TCP_PORT)
    parser.add_argument("--addr", type=int, default=3, help="ASDU device address (3 matches 171_nz_103_net.txt)")
    parser.add_argument("--session-sec", type=float, default=30.0)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(message)s",
    )
    NariNetSlave(args.host, args.port, args.addr).run_once(args.session_sec)


if __name__ == "__main__":
    main()
