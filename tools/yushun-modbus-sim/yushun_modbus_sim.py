#!/usr/bin/env python3
"""Simulate 禹舜MODBUS-下端电压硬压板 on TCP:502 (RTU framing, no MBAP).

Matches packet-yushun-modbus.c: holding regs 5000+, 9 regs/point, magic 0x4459.
"""

from __future__ import annotations

import argparse
import socket
import struct
import threading
import time


MAGIC = 0x4459
REG_BASE = 5000
UNIT_REGS = 9


def modbus_crc(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def append_crc(pdu: bytes) -> bytes:
    crc = modbus_crc(pdu)
    return pdu + struct.pack("<H", crc)


def build_unit_bytes(
    voltage: float,
    comm_state: int = 0x00,
    plate_state: int = 0x00,
    spare: int = 0,
    zero_coeff: float = 0.0,
    full_coeff: float = 1.0,
) -> bytes:
    return (
        struct.pack("<f", voltage)
        + bytes([comm_state & 0xFF, plate_state & 0xFF])
        + struct.pack(">H", spare & 0xFFFF)
        + struct.pack("<f", zero_coeff)
        + struct.pack("<f", full_coeff)
        + struct.pack(">H", MAGIC)
    )


def handle_request(req: bytes) -> bytes | None:
    if len(req) < 8:
        return None
    unit_id, func = req[0], req[1]
    if func != 0x03:
        # Exception: illegal function
        return append_crc(bytes([unit_id, func | 0x80, 0x01]))

    start = struct.unpack(">H", req[2:4])[0]
    qty = struct.unpack(">H", req[4:6])[0]
    if qty == 0 or qty > 125:
        return append_crc(bytes([unit_id, func | 0x80, 0x03]))

    data = bytearray()
    for i in range(qty):
        reg = start + i
        if reg < REG_BASE:
            data += b"\x00\x00"
            continue
        unit_idx = (reg - REG_BASE) // UNIT_REGS
        unit_base = REG_BASE + unit_idx * UNIT_REGS
        off = (reg - unit_base) * 2
        # Synthesize stable demo values per point.
        voltage = 110.0 + unit_idx * 0.5
        plate = 0x00 if (unit_idx % 2 == 0) else 0x01
        unit = build_unit_bytes(voltage=voltage, plate_state=plate, zero_coeff=0.0, full_coeff=220.0)
        data += unit[off : off + 2]

    # Ensure we only return qty*2 bytes
    data = data[: qty * 2]
    while len(data) < qty * 2:
        data += b"\x00"
    return append_crc(bytes([unit_id, 0x03, len(data)]) + data)


def serve_client(conn: socket.socket, addr) -> None:
    print(f"[server] client {addr}", flush=True)
    conn.settimeout(30.0)
    buf = bytearray()
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            # One RTU frame per TCP write for this sim (matches typical device).
            while True:
                if len(buf) < 8:
                    break
                # Read-holding request is always 8 bytes with CRC.
                if buf[1] == 0x03 and len(buf) >= 8:
                    frame = bytes(buf[:8])
                    del buf[:8]
                    resp = handle_request(frame)
                    if resp:
                        conn.sendall(resp)
                        print(
                            f"[server] req={frame.hex(' ')} -> rsp={resp.hex(' ')}",
                            flush=True,
                        )
                    continue
                # Unknown: drop one byte and resync.
                del buf[0]
    except (TimeoutError, ConnectionResetError, OSError) as exc:
        print(f"[server] {addr} closed: {exc}", flush=True)
    finally:
        conn.close()


def run_server(host: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5)
        print(f"[server] listening on {host}:{port}", flush=True)
        while True:
            conn, addr = sock.accept()
            threading.Thread(target=serve_client, args=(conn, addr), daemon=True).start()


def run_client(host: str, port: int, unit: int, start: int, qty: int, count: int, interval: float) -> None:
    req = append_crc(struct.pack(">BBHH", unit, 0x03, start, qty))
    for i in range(count):
        with socket.create_connection((host, port), timeout=5) as sock:
            sock.sendall(req)
            rsp = sock.recv(4096)
            print(f"[client {i+1}] req={req.hex(' ')} rsp={rsp.hex(' ')}", flush=True)
        time.sleep(interval)


def main() -> None:
    ap = argparse.ArgumentParser(description="Yushun MODBUS RTU-over-TCP simulator")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=502)
    ap.add_argument("--mode", choices=("server", "client", "both"), default="both")
    ap.add_argument("--unit", type=int, default=1)
    ap.add_argument("--start", type=int, default=REG_BASE)
    ap.add_argument("--qty", type=int, default=UNIT_REGS * 2)  # two points
    ap.add_argument("--count", type=int, default=5)
    ap.add_argument("--interval", type=float, default=0.3)
    args = ap.parse_args()

    if args.mode in ("server", "both"):
        t = threading.Thread(target=run_server, args=(args.host, args.port), daemon=True)
        t.start()
        time.sleep(0.3)

    if args.mode in ("client", "both"):
        run_client(args.host, args.port, args.unit, args.start, args.qty, args.count, args.interval)
        if args.mode == "both":
            time.sleep(0.5)
    else:
        while True:
            time.sleep(3600)


if __name__ == "__main__":
    main()
