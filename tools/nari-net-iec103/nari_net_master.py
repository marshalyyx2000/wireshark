#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""NARI network 103 master (TCP server :1048, UDP broadcast :1032)."""

from __future__ import annotations

import argparse
import logging
import socket
import threading
import time

from nari_net_iec103_codec import (
    TCP_PORT,
    UDP_PORT,
    asdu_general_interrogation,
    asdu_gen_read_group,
    asdu_gen_read_entry,
    asdu_time_sync,
    udp_master_online,
    ParsedAsdu,
    split_asdu_stream,
)
from nari_wave_master import WaveMasterSequence, make_recv_loop

LOG = logging.getLogger("nari_master")


class NariNetMaster:
    def __init__(
        self,
        host: str = "127.0.0.1",
        tcp_port: int = TCP_PORT,
        primary_addr: int = 3,
        wave_addrs: list[int] | None = None,
    ) -> None:
        self.host = host
        self.tcp_port = tcp_port
        self.primary_addr = primary_addr
        self.wave_addrs = wave_addrs or [1, 2, 3]
        self._stop = threading.Event()
        self._rii = 0

    def _next_rii(self) -> int:
        self._rii = (self._rii + 1) & 0xFF
        return self._rii

    def udp_broadcast_loop(self, interval: float = 5.0) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError:
            pass
        target = (self.host, UDP_PORT)
        LOG.info("UDP master online → %s:%s every %.1fs", *target, interval)
        while not self._stop.is_set():
            pkt = udp_master_online(include_time=True, name="NARI-MASTER")
            try:
                sock.sendto(pkt, target)
                sock.sendto(pkt, ("255.255.255.255", UDP_PORT))
            except OSError as exc:
                LOG.warning("UDP send: %s", exc)
            self._stop.wait(interval)

    def handle_slave(self, conn: socket.socket, addr: tuple) -> None:
        LOG.info("Slave connected from %s", addr)
        buf = bytearray()
        addr_dev = self.primary_addr

        def send_asdu(payload: bytes) -> None:
            conn.sendall(payload)
            LOG.info("Master sent %d bytes: %s", len(payload), payload.hex(" "))

        def log_received(parsed: ParsedAsdu) -> None:
            LOG.info("Master received: %s", parsed)

        recv = make_recv_loop(conn, buf)

        # Bring-up (short)
        send_asdu(asdu_time_sync())
        time.sleep(0.05)
        send_asdu(asdu_general_interrogation(addr_dev))
        time.sleep(0.05)
        send_asdu(asdu_gen_read_group(addr_dev, group=6, entry=0, kod=10, rii=self._next_rii()))
        time.sleep(0.05)
        send_asdu(asdu_gen_read_entry(addr_dev, group=6, entry=1, kod=1, rii=self._next_rii()))
        time.sleep(0.1)

        # Drain bring-up replies
        for parsed in recv(0.5):
            log_received(parsed)

        # Full disturbance list + waveform transfer
        wave = WaveMasterSequence(
            primary_addr=self.primary_addr,
            list_addrs=self.wave_addrs,
            fan=1,
        )

        def send_and_log(payload: bytes) -> None:
            send_asdu(payload)

        def recv_and_log(timeout: float) -> list[ParsedAsdu]:
            frames = recv(timeout)
            for p in frames:
                log_received(p)
            return frames

        wave.run(send_and_log, recv_and_log)
        time.sleep(0.2)
        conn.close()
        LOG.info("Slave %s disconnected", addr)

    def serve(self) -> None:
        udp_thread = threading.Thread(target=self.udp_broadcast_loop, daemon=True)
        udp_thread.start()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.tcp_port))
            srv.listen(5)
            srv.settimeout(1.0)
            LOG.info("Master listening TCP %s:%s", self.host, self.tcp_port)
            while not self._stop.is_set():
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(
                    target=self.handle_slave, args=(conn, addr), daemon=True
                ).start()

    def stop(self) -> None:
        self._stop.set()


def main() -> None:
    parser = argparse.ArgumentParser(description="NARI network 103 master (TCP server)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=TCP_PORT)
    parser.add_argument("--addr", type=int, default=3, help="Primary device address for wave transfer")
    parser.add_argument("--wave-addrs", default="1,2,3", help="Comma-separated addresses for list query")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()
    wave_addrs = [int(x.strip()) for x in args.wave_addrs.split(",") if x.strip()]
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(message)s",
    )
    master = NariNetMaster(args.host, args.port, args.addr, wave_addrs)
    try:
        master.serve()
    except KeyboardInterrupt:
        master.stop()
        LOG.info("Stopped")


if __name__ == "__main__":
    main()
