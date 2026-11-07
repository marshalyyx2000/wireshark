# -*- coding: utf-8 -*-
"""模拟武汉中原 ZH 系列录波器主站（TCP 客户端）。

流程：查帧格式 -> 查型号/目录 -> 查/复归新状态 -> 列目录 -> 取文件 -> 遥测遥信

用法
    python zh_master.py --host 127.0.0.1 --port 30282 --type2
    python zh_master.py --pcap out.pcap        # 只生成中性抓包，不联网
"""
from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parent))
import zh_core as zh  # noqa: E402


def recv_frame(sock: socket.socket, buf: bytearray, timeout: float = 3.0) -> bytes | None:
    """读一个完整帧（依赖 zh.frame_len 分帧）。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        n = zh.frame_len(bytes(buf))
        if n > 0:
            frame = bytes(buf[:n])
            del buf[:n]
            return frame
        try:
            sock.settimeout(max(0.1, deadline - time.time()))
            data = sock.recv(65536)
        except (socket.timeout, OSError):
            return None
        if not data:
            return None
        buf.extend(data)
    return None


def recv_expect(sock: socket.socket, buf: bytearray, typ: int,
                timeout: float = 3.0) -> dict | None:
    """跳过中间帧，直到收到指定 TYP。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        frame = recv_frame(sock, buf, max(0.1, deadline - time.time()))
        if frame is None:
            return None
        parsed = zh.parse_frame(frame)
        if parsed and parsed["typ"] == typ:
            return parsed
    return None


class ZhMaster:
    def __init__(self, host: str, port: int, type2: bool):
        self.host = host
        self.port = port
        self.type2 = type2
        self.sock: socket.socket | None = None
        self.buf = bytearray()
        self.log: List[str] = []

    def connect(self) -> None:
        self.sock = socket.create_connection((self.host, self.port), timeout=5)
        self.buf.clear()
        self.log.append(f"connected {self.host}:{self.port}")

    def close(self) -> None:
        if self.sock:
            self.sock.close()
            self.sock = None

    def _send(self, typ: int, dat: bytes = b"") -> None:
        assert self.sock is not None
        self.sock.sendall(zh.frame(typ, dat, type2=self.type2))

    def request(self, typ: int, dat: bytes = b"", expect_typ: int | None = None,
                timeout: float = 3.0) -> dict | None:
        self._send(typ, dat)
        want = expect_typ if expect_typ is not None else zh.PTYPE_RETURN
        return recv_expect(self.sock, self.buf, want, timeout)

    def run_session(self) -> List[str]:
        assert self.sock is not None
        out = self.log

        r = self.request(zh.PTYPE_CHKFRMFMT, b"\x00\x00")
        out.append(f"CHKFRMFMT -> {r['typ'] if r else 'no reply'}")

        r = self.request(zh.PTYPE_GETMODEL)
        out.append(f"GETMODEL -> {zh.cstr_decode(r['dat'][8:264]) if r else 'no reply'}")

        r = self.request(zh.PTYPE_GETNEWSTATUS)
        if r:
            out.append(f"GETNEWSTATUS -> {zh.cstr_decode(r['dat'][8:264])}")
        status = recv_expect(self.sock, self.buf, zh.PTYPE_GETNEWSTATUS)
        if status and len(status["dat"]) >= 4:
            import struct
            out.append(f"newstatus = 0x{struct.unpack_from('<I', status['dat'])[0]:08X}")

        self.request(zh.PTYPE_RESETNEWSTATUS, b"\x01\x00\x00\x00")

        self.request(zh.PTYPE_DIR_GET, zh.file_get("D:\\ZYHD\\DATA\\*.lst"))
        seen = 0
        while True:
            frame = recv_frame(self.sock, self.buf, 2.0)
            if frame is None:
                break
            parsed = zh.parse_frame(frame)
            if not parsed:
                continue
            if parsed["typ"] == zh.PTYPE_FILE_INFO:
                seen += 1
            elif parsed["typ"] != zh.PTYPE_FILE_DATA:
                break
        out.append(f"DIR_GET -> {seen} file(s)")

        for name in ("D:\\ZYHD\\BIN\\ZHREC.SCFF",
                     "D:\\ZYHD\\DATA\\20261107\\REC001.cfg",
                     "D:\\ZYHD\\DATA\\20261107\\REC001.dat"):
            self.request(zh.PTYPE_FILE_GET, zh.file_get(name))
            total = 0
            chunks = 0
            while True:
                frame = recv_frame(self.sock, self.buf, 2.0)
                if frame is None:
                    break
                parsed = zh.parse_frame(frame)
                if not parsed:
                    continue
                if parsed["typ"] == zh.PTYPE_FILE_DATA:
                    total += parsed["len"]
                    chunks += 1
                else:
                    break
            out.append(f"FILE_GET {Path(name).name} -> {chunks} chunk(s), {total} bytes")

        self.request(zh.PTYPE_YC)
        yc = recv_expect(self.sock, self.buf, zh.PTYPE_YC)
        out.append(f"YC -> {len(yc['dat']) // 82 if yc else 0} point(s)")

        self.request(zh.PTYPE_YX)
        yx = recv_expect(self.sock, self.buf, zh.PTYPE_YX)
        out.append(f"YX -> {len(yx['dat']) // 66 if yx else 0} point(s)")

        # 对时与遥控录波无回答
        self._send(zh.PTYPE_TIME, zh.system_time())
        self._send(zh.PTYPE_RECORD)
        return out


def main() -> int:
    ap = argparse.ArgumentParser(description="ZH recorder master simulator")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=zh.DEFAULT_PORT)
    ap.add_argument("--type2", action="store_true")
    ap.add_argument("--pcap", type=Path, default=None,
                    help="write a neutral pcap instead of talking to a device")
    args = ap.parse_args()

    if args.pcap:
        files = zh.ZhFiles.demo()
        seq = zh.build_session(files, pkt_size=1024, type2=args.type2)
        zh.write_eth_pcap(args.pcap, zh.tcp_records(seq))
        print(f"pcap: {args.pcap} ({len(seq)} frames)")
        return 0

    m = ZhMaster(args.host, args.port, args.type2)
    m.connect()
    try:
        for line in m.run_session():
            print(line)
    finally:
        m.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
