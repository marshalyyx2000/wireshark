#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
禹舜 YS800-W Modbus RTU 汇聚单元模拟服务端.

默认在 TCP 端口上接收裸 RTU 帧（无 MBAP 头），便于本机联调。
也可通过 --serial 绑定 COM 口模拟 RS485 从站。

用法:
  python server.py
  python server.py --host 0.0.0.0 --port 502
  python server.py --serial COM3 --baudrate 9600
"""

from __future__ import annotations

import argparse
import logging
import socket
import sys
import threading
import time
from typing import Optional

from device_data import YushunDevice
from modbus_rtu import build_read_response, hex_line, parse_request, verify_crc

LOG = logging.getLogger("yushun-server")

# Captured master poll pattern (start register, quantity).
POLL_SEQUENCE = [
    (0x1388, 0x0078),  # 5000, 120
    (0x1405, 0x0078),  # 5125, 120
    (0x147D, 0x0076),  # 5245, 118
    (0x14F8, 0x0078),  # 5368, 120
    (0x1570, 0x0012),  # 5488, 18
]


class FrameBuffer:
    """Accumulate bytes until a complete Modbus RTU request is available."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        self._buf.extend(data)
        frames: list[bytes] = []
        while True:
            frame = self._try_extract()
            if frame is None:
                break
            frames.append(frame)
        return frames

    def _try_extract(self) -> Optional[bytes]:
        if len(self._buf) < 8:
            return None
        # Read-holding-registers request is always 8 bytes including CRC.
        candidate = bytes(self._buf[:8])
        if verify_crc(candidate):
            del self._buf[:8]
            return candidate
        # Resync on bad leading byte.
        del self._buf[0]
        return self._try_extract()


class YushunServer:
    def __init__(self, device: YushunDevice, slave_id: int = 1) -> None:
        self.device = device
        self.slave_id = slave_id
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def _handle_request(self, frame: bytes) -> Optional[bytes]:
        parsed = parse_request(frame)
        if parsed is None:
            LOG.warning("ignored invalid frame: %s", hex_line(frame))
            return None
        slave, _function, start, quantity = parsed
        if slave != self.slave_id:
            LOG.debug("foreign slave %s ignored", slave)
            return None
        try:
            data = self.device.read_registers(start, quantity)
        except (IndexError, ValueError) as exc:
            LOG.warning("read failed for %04X x%d: %s", start, quantity, exc)
            return None
        response = build_read_response(slave, data)
        LOG.info(
            "Req FC03 start=%d qty=%d -> %d bytes",
            start,
            quantity,
            len(data),
        )
        return response

    def serve_connection(self, conn: socket.socket, peer: str) -> None:
        LOG.info("client connected: %s", peer)
        buffer = FrameBuffer()
        conn.settimeout(1.0)
        try:
            while not self._stop.is_set():
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                for frame in buffer.feed(chunk):
                    LOG.info("Recv: %s", hex_line(frame))
                    response = self._handle_request(frame)
                    if response:
                        conn.sendall(response)
                        LOG.info("Send: %s", hex_line(response))
        finally:
            conn.close()
            LOG.info("client disconnected: %s", peer)

    def serve_tcp(self, host: str, port: int) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((host, port))
            server.listen(5)
            LOG.info("TCP RTU server listening on %s:%d (slave=%d)", host, port, self.slave_id)
            server.settimeout(1.0)
            while not self._stop.is_set():
                try:
                    conn, addr = server.accept()
                except socket.timeout:
                    continue
                thread = threading.Thread(
                    target=self.serve_connection,
                    args=(conn, f"{addr[0]}:{addr[1]}"),
                    daemon=True,
                )
                thread.start()

    def serve_serial(self, port: str, baudrate: int) -> None:
        try:
            import serial  # type: ignore
        except ImportError:
            LOG.error("pyserial is required for --serial (pip install pyserial)")
            sys.exit(1)

        buffer = FrameBuffer()
        with serial.Serial(port=port, baudrate=baudrate, timeout=0.1) as ser:
            LOG.info("serial RTU server on %s @ %d baud (slave=%d)", port, baudrate, self.slave_id)
            while not self._stop.is_set():
                chunk = ser.read(256)
                if chunk:
                    for frame in buffer.feed(chunk):
                        LOG.info("Recv: %s", hex_line(frame))
                        response = self._handle_request(frame)
                        if response:
                            ser.write(response)
                            LOG.info("Send: %s", hex_line(response))
                time.sleep(0.01)


def background_tick(device: YushunDevice, stop_event: threading.Event, interval: float) -> None:
    while not stop_event.is_set():
        device.tick()
        stop_event.wait(interval)


def main() -> None:
    parser = argparse.ArgumentParser(description="禹舜 Modbus RTU 汇聚单元模拟服务端")
    parser.add_argument("--host", default="127.0.0.1", help="TCP bind host")
    parser.add_argument("--port", type=int, default=502, help="TCP bind port")
    parser.add_argument("--slave", type=int, default=1, help="Modbus slave address")
    parser.add_argument("--serial", help="Use serial port instead of TCP, e.g. COM3")
    parser.add_argument("--baudrate", type=int, default=9600, help="Serial baud rate")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    device = YushunDevice()
    server = YushunServer(device, slave_id=args.slave)
    stop_event = threading.Event()
    ticker = threading.Thread(
        target=background_tick,
        args=(device, stop_event, 0.5),
        daemon=True,
    )
    ticker.start()

    try:
        if args.serial:
            server.serve_serial(args.serial, args.baudrate)
        else:
            server.serve_tcp(args.host, args.port)
    except KeyboardInterrupt:
        LOG.info("shutting down")
    finally:
        stop_event.set()
        server.stop()


if __name__ == "__main__":
    main()
