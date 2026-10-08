#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
禹舜通道 Modbus RTU 主站客户端 — 复现捕获日志中的轮询流程.

默认连接 server.py 提供的 TCP RTU 端口，按原日志节奏发送 5 段 FC03 读请求。

用法:
  # 终端 1
  python server.py

  # 终端 2
  python client.py
  python client.py --host 127.0.0.1 --port 502 --cycles 3
  python client.py --serial COM4 --baudrate 9600
"""

from __future__ import annotations

import argparse
import logging
import socket
import sys
import time
from datetime import datetime
from typing import List, Optional, Tuple

from modbus_rtu import build_read_holding_registers, hex_line, verify_crc

LOG = logging.getLogger("yushun-client")

CHANNEL_NAME = "禹舜通道"
RECV_BUFFER_SIZE = 5120

# Same schedule as the user's Wireshark / gateway log.
POLL_SEQUENCE: List[Tuple[int, int, float]] = [
    (0x1388, 0x0078, 0.401),  # 5000, 120 regs, ~401 ms until response
    (0x1405, 0x0078, 0.401),
    (0x147D, 0x0076, 0.400),
    (0x14F8, 0x0078, 0.401),
    (0x1570, 0x0012, 0.200),  # shorter tail segment in capture
]

CYCLE_GAP_SEC = 4.007  # ~4 s between full poll rounds in the capture


def log_send(frame: bytes) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"{ts} {CHANNEL_NAME}-Send: {hex_line(frame)}")
    print(f"{ts} 接收缓冲区剩余:{RECV_BUFFER_SIZE}")


def log_recv(frame: bytes) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    print(f"{ts} {CHANNEL_NAME}-Recv: {hex_line(frame)}")


def read_response(sock: socket.socket, timeout: float) -> bytes:
    sock.settimeout(timeout)
    chunks = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            piece = sock.recv(4096)
        except socket.timeout:
            break
        if not piece:
            break
        chunks.extend(piece)
        if len(chunks) >= 5 and verify_crc(bytes(chunks)):
            return bytes(chunks)
    if chunks:
        return bytes(chunks)
    raise TimeoutError("no Modbus response within timeout")


class TcpRtuClient:
    def __init__(self, host: str, port: int, slave: int = 1) -> None:
        self.host = host
        self.port = port
        self.slave = slave
        self._sock: Optional[socket.socket] = None

    def connect(self) -> None:
        self._sock = socket.create_connection((self.host, self.port), timeout=5.0)
        LOG.info("connected to %s:%d", self.host, self.port)

    def close(self) -> None:
        if self._sock:
            self._sock.close()
            self._sock = None

    def transact(self, start: int, quantity: int, response_timeout: float) -> bytes:
        if self._sock is None:
            raise RuntimeError("not connected")
        request = build_read_holding_registers(self.slave, start, quantity)
        log_send(request)
        self._sock.sendall(request)
        response = read_response(self._sock, response_timeout)
        log_recv(response)
        if not verify_crc(response):
            raise ValueError(f"response CRC mismatch: {hex_line(response)}")
        expected_bytes = quantity * 2
        if len(response) < 5 or response[0] != self.slave or response[1] != 0x03:
            raise ValueError(f"unexpected response header: {hex_line(response)}")
        byte_count = response[2]
        if byte_count != expected_bytes:
            LOG.warning(
                "byte count %d != expected %d for qty %d",
                byte_count,
                expected_bytes,
                quantity,
            )
        return response


class SerialRtuClient:
    def __init__(self, port: str, baudrate: int, slave: int = 1) -> None:
        try:
            import serial  # type: ignore
        except ImportError:
            raise RuntimeError("pyserial is required for --serial (pip install pyserial)")
        self._serial_mod = serial
        self.port = port
        self.baudrate = baudrate
        self.slave = slave
        self._ser = None

    def connect(self) -> None:
        self._ser = self._serial_mod.Serial(
            port=self.port,
            baudrate=self.baudrate,
            timeout=0.1,
        )
        LOG.info("opened serial %s @ %d", self.port, self.baudrate)

    def close(self) -> None:
        if self._ser:
            self._ser.close()
            self._ser = None

    def transact(self, start: int, quantity: int, response_timeout: float) -> bytes:
        if self._ser is None:
            raise RuntimeError("not connected")
        request = build_read_holding_registers(self.slave, start, quantity)
        log_send(request)
        self._ser.reset_input_buffer()
        self._ser.write(request)
        deadline = time.monotonic() + response_timeout
        chunks = bytearray()
        while time.monotonic() < deadline:
            piece = self._ser.read(512)
            if piece:
                chunks.extend(piece)
                if len(chunks) >= 5 and verify_crc(bytes(chunks)):
                    break
            else:
                time.sleep(0.01)
        if not chunks:
            raise TimeoutError("no Modbus response within timeout")
        response = bytes(chunks)
        log_recv(response)
        return response


def run_poll_cycle(client, cycle_index: int) -> None:
    LOG.info("=== poll cycle %d ===", cycle_index)
    for step, (start, quantity, response_timeout) in enumerate(POLL_SEQUENCE, start=1):
        try:
            client.transact(start, quantity, response_timeout)
        except Exception as exc:
            LOG.error("step %d failed (start=%d qty=%d): %s", step, start, quantity, exc)
            raise
        # Small gap between requests in the same cycle (capture shows ~4 s between cycles,
        # requests within a cycle are back-to-back on the wire).
        time.sleep(0.01)


def main() -> None:
    parser = argparse.ArgumentParser(description="禹舜 Modbus RTU 轮询客户端")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument("--slave", type=int, default=1)
    parser.add_argument("--serial", help="Use serial port instead of TCP, e.g. COM4")
    parser.add_argument("--baudrate", type=int, default=9600)
    parser.add_argument("--cycles", type=int, default=0, help="0 = run forever")
    parser.add_argument("--cycle-gap", type=float, default=CYCLE_GAP_SEC)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if args.serial:
        client = SerialRtuClient(args.serial, args.baudrate, args.slave)
    else:
        client = TcpRtuClient(args.host, args.port, args.slave)

    client.connect()
    cycle = 1
    try:
        while args.cycles == 0 or cycle <= args.cycles:
            run_poll_cycle(client, cycle)
            if args.cycles != 0 and cycle >= args.cycles:
                break
            time.sleep(args.cycle_gap)
            cycle += 1
    except KeyboardInterrupt:
        LOG.info("stopped by user")
    finally:
        client.close()


if __name__ == "__main__":
    main()
