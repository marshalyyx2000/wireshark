#!/usr/bin/env python3
"""Simulate 禹舜MODBUS-下端电压硬压板 on a COM port (Modbus RTU).

Typical use with com0com CNCA0 <-> CNCB0:
  - interactive: master on one end, slave on the other
  - wire: emit req/rsp frames on --port so serialdump on the peer can capture
"""

from __future__ import annotations

import argparse
import struct
import sys
import threading
import time

try:
    import serial
except ImportError:
    print("pyserial required: pip install pyserial", file=sys.stderr)
    raise

# Reuse PDU helpers from the TCP sim when available.
from yushun_modbus_sim import (  # noqa: E402
    REG_BASE,
    UNIT_REGS,
    append_crc,
    handle_request,
)


def open_port(name: str, baud: int) -> serial.Serial:
    path = name if name.startswith("\\\\.\\") else f"\\\\.\\{name}"
    return serial.Serial(
        path,
        baudrate=baud,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        timeout=0.2,
        write_timeout=2.0,
    )


def run_slave(port: str, baud: int, duration: float) -> None:
    ser = open_port(port, baud)
    print(f"[slave] {ser.name} baud={baud}", flush=True)
    buf = bytearray()
    deadline = time.time() + duration
    try:
        while time.time() < deadline:
            chunk = ser.read(256)
            if not chunk:
                continue
            buf += chunk
            while len(buf) >= 8:
                if buf[1] == 0x03:
                    frame = bytes(buf[:8])
                    del buf[:8]
                    rsp = handle_request(frame)
                    if rsp:
                        ser.write(rsp)
                        ser.flush()
                        print(
                            f"[slave] req={frame.hex(' ')} -> rsp={rsp.hex(' ')}",
                            flush=True,
                        )
                    continue
                del buf[0]
    finally:
        ser.close()
        print("[slave] closed", flush=True)


def run_master(
    port: str,
    baud: int,
    unit: int,
    start: int,
    qty: int,
    count: int,
    interval: float,
) -> None:
    req = append_crc(struct.pack(">BBHH", unit, 0x03, start, qty))
    ser = open_port(port, baud)
    print(f"[master] {ser.name} baud={baud} count={count}", flush=True)
    try:
        for i in range(count):
            ser.reset_input_buffer()
            ser.write(req)
            ser.flush()
            time.sleep(0.05)
            rsp = ser.read(256)
            print(
                f"[master {i+1}] req={req.hex(' ')} rsp={rsp.hex(' ') if rsp else '<empty>'}",
                flush=True,
            )
            time.sleep(interval)
    finally:
        ser.close()


def run_wire(
    port: str,
    baud: int,
    unit: int,
    start: int,
    qty: int,
    count: int,
    interval: float,
) -> None:
    """Emit request+response frames one-way so a peer serialdump can capture both."""
    req = append_crc(struct.pack(">BBHH", unit, 0x03, start, qty))
    rsp = handle_request(req)
    assert rsp is not None
    ser = open_port(port, baud)
    print(f"[wire] {ser.name} baud={baud} frames={count*2}", flush=True)
    try:
        for i in range(count):
            ser.write(req)
            ser.flush()
            print(f"[wire {i+1}] req={req.hex(' ')}", flush=True)
            time.sleep(0.08)  # let serialdump ReadFile delimit frames
            ser.write(rsp)
            ser.flush()
            print(f"[wire {i+1}] rsp={rsp.hex(' ')}", flush=True)
            time.sleep(interval)
    finally:
        ser.close()
        print("[wire] done", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="Yushun MODBUS RTU serial simulator")
    ap.add_argument(
        "--mode",
        choices=("slave", "master", "both", "wire"),
        default="wire",
        help="both=master+slave on two ports; wire=emit req/rsp for serialdump",
    )
    ap.add_argument("--port", default="CNCA0", help="COM port (or CNCA0)")
    ap.add_argument("--peer", default="CNCB0", help="peer port for mode=both")
    ap.add_argument("--baud", type=int, default=9600)
    ap.add_argument("--unit", type=int, default=1)
    ap.add_argument("--start", type=int, default=REG_BASE)
    ap.add_argument("--qty", type=int, default=UNIT_REGS * 2)
    ap.add_argument("--count", type=int, default=6)
    ap.add_argument("--interval", type=float, default=0.15)
    ap.add_argument("--duration", type=float, default=15.0, help="slave listen seconds")
    args = ap.parse_args()

    if args.mode == "slave":
        run_slave(args.port, args.baud, args.duration)
    elif args.mode == "master":
        run_master(
            args.port, args.baud, args.unit, args.start, args.qty, args.count, args.interval
        )
    elif args.mode == "wire":
        run_wire(
            args.port, args.baud, args.unit, args.start, args.qty, args.count, args.interval
        )
    else:
        t = threading.Thread(
            target=run_slave, args=(args.peer, args.baud, args.duration), daemon=True
        )
        t.start()
        time.sleep(0.3)
        run_master(
            args.port, args.baud, args.unit, args.start, args.qty, args.count, args.interval
        )
        time.sleep(0.5)


if __name__ == "__main__":
    main()
