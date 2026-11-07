# -*- coding: utf-8 -*-
"""模拟武汉中原 ZH 系列录波器（TCP 30282 服务端）。

用法
    python zh_recorder.py --host 127.0.0.1 --port 30282 --type2
    python zh_recorder.py --pkt-size 512 --once
"""
from __future__ import annotations

import argparse
import socket
import struct
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import zh_core as zh  # noqa: E402


class ZhRecorder:
    def __init__(self, host: str, port: int, pkt_size: int, type2: bool,
                 files: zh.ZhFiles):
        self.host = host
        self.port = port
        self.pkt_size = pkt_size
        self.type2 = type2
        self.files = files
        self.new_status = 0xFFFFFFFF
        self._stop = threading.Event()
        self._srv: socket.socket | None = None

    # ---------------------------------------------------------------- helpers
    def _send(self, conn: socket.socket, typ: int, dat: bytes = b"") -> None:
        conn.sendall(zh.frame(typ, dat, type2=self.type2))

    def _ret(self, conn: socket.socket, code: int = zh.ECONN_SUCCESS,
             msg: str = "成功") -> None:
        self._send(conn, zh.PTYPE_RETURN, zh.packet_return(code, 1, msg))

    def _send_file(self, conn: socket.socket, name: str) -> None:
        payload = self.files.files.get(name)
        if payload is None:
            self._ret(conn, zh.ECONN_NO_DATA, "没有所请求的数据")
            return
        self._ret(conn)
        self._send(conn, zh.PTYPE_FILE_INFO, zh.file_info(name, len(payload)))
        for chunk in zh.file_data_chunks(payload, self.pkt_size, type2=self.type2):
            conn.sendall(chunk)

    def _handle(self, conn: socket.socket) -> None:
        buf = b""
        while not self._stop.is_set():
            try:
                data = conn.recv(65536)
            except OSError:
                return
            if not data:
                return
            buf += data
            while True:
                n = zh.frame_len(buf)
                if n <= 0:
                    break
                raw, buf = buf[:n], buf[n:]
                parsed = zh.parse_frame(raw)
                if parsed is None:
                    continue
                self._dispatch(conn, parsed["typ"], parsed["dat"])

    def _dispatch(self, conn: socket.socket, typ: int, dat: bytes) -> None:
        if typ == zh.PTYPE_CHKFRMFMT:
            self._ret(conn)
        elif typ == zh.PTYPE_RECORDERINFO:
            self._ret(conn, msg="ZH-2B+ V7.6.9.8")
        elif typ == zh.PTYPE_GETMODEL:
            self._ret(conn)
            self._send(conn, zh.PTYPE_GETMODEL, struct.pack("<I", 0x02BA))
        elif typ == zh.PTYPE_WORK_PATH:
            self._ret(conn)
            self._send(conn, zh.PTYPE_WORK_PATH, b"E:\\ZYHD\\\x00")
        elif typ == zh.PTYPE_DATA_PATH:
            self._ret(conn)
            self._send(conn, zh.PTYPE_DATA_PATH, b"D:\\ZYHD\\DATA\\\x00")
        elif typ == zh.PTYPE_PACKETSIZE:
            if len(dat) >= 2:
                v = struct.unpack_from("<H", dat, 0)[0]
                if v != 0xFFFF and 248 <= v <= zh.MAX_LEN:
                    self.pkt_size = v
                self._ret(conn)
                self._send(conn, zh.PTYPE_PACKETSIZE, struct.pack("<H", self.pkt_size))
        elif typ == zh.PTYPE_FRAMEDELAY:
            self._ret(conn)
            self._send(conn, zh.PTYPE_FRAMEDELAY, struct.pack("<H", 0))
        elif typ == zh.PTYPE_GETNEWSTATUS:
            self._ret(conn)
            self._send(conn, zh.PTYPE_GETNEWSTATUS, struct.pack("<I", self.new_status))
            self.new_status = 0
        elif typ == zh.PTYPE_RESETNEWSTATUS:
            if len(dat) >= 4:
                bits = struct.unpack_from("<I", dat, 0)[0]
                self.new_status &= ~bits & 0xFFFFFFFF
            self._ret(conn)
        elif typ == zh.PTYPE_TIME:
            pass   # 无回答
        elif typ == zh.PTYPE_RECORD:
            self.new_status |= 0x01
        elif typ == zh.PTYPE_CANCEL:
            pass
        elif typ in (zh.PTYPE_FILE_GET, zh.PTYPE_FILE_INFO, zh.PTYPE_FILE_VER):
            name = zh.cstr_decode(dat[12:268]) if len(dat) >= 268 else ""
            if typ == zh.PTYPE_FILE_VER:
                payload = self.files.files.get(name)
                self._ret(conn)
                self._send(conn, zh.PTYPE_FILE_VER,
                           zh.file_ver("7.6.9.8", name, len(payload or b"")))
            elif typ == zh.PTYPE_FILE_INFO:
                payload = self.files.files.get(name)
                if payload is None:
                    self._ret(conn, zh.ECONN_NO_DATA, "没有所请求的数据")
                else:
                    self._ret(conn)
                    self._send(conn, zh.PTYPE_FILE_INFO,
                               zh.file_info(name, len(payload)))
            else:
                self._send_file(conn, name)
        elif typ == zh.PTYPE_DIR_GET:
            pattern = zh.cstr_decode(dat[12:268]) if len(dat) >= 268 else ""
            self._ret(conn)
            for name, payload in self.files.files.items():
                if pattern and not _match(pattern, name):
                    continue
                self._send(conn, zh.PTYPE_FILE_INFO, zh.file_info(name, len(payload)))
                for chunk in zh.file_data_chunks(payload, self.pkt_size,
                                                 type2=self.type2):
                    conn.sendall(chunk)
        elif typ == zh.PTYPE_YC:
            self._ret(conn)
            self._send(conn, zh.PTYPE_YC,
                       zh.zrec_yc(20, 1, 1.732, "UA") + zh.zrec_yc(20, 2, 1.745, "UB"))
        elif typ == zh.PTYPE_YX:
            self._ret(conn)
            self._send(conn, zh.PTYPE_YX,
                       zh.zrec_yx(30, 1, 1.0, "断路器合位")
                       + zh.zrec_yx(30, 2, 0.0, "弹簧未储能"))
        elif typ == zh.PTYPE_YCEX:
            self._ret(conn)
            self._send(conn, zh.PTYPE_YCEX, zh.zrec_yc(21, 1, 5.0, "扩展通道 1"))
        else:
            self._ret(conn, zh.ECONN_COMMAND, "无效的命令")

    # ------------------------------------------------------------------ serve
    def serve_forever(self, once: bool = False) -> None:
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((self.host, self.port))
        self._srv.listen(4)
        self._srv.settimeout(1.0)
        print(f"ZH recorder listening on {self.host}:{self.port} "
              f"(pkt_size={self.pkt_size}, type2={self.type2})")
        try:
            while not self._stop.is_set():
                try:
                    conn, peer = self._srv.accept()
                except socket.timeout:
                    continue
                print(f"client {peer[0]}:{peer[1]} connected")
                try:
                    self._handle(conn)
                finally:
                    conn.close()
                    if once:
                        break
        finally:
            self._srv.close()

    def stop(self) -> None:
        self._stop.set()


def _match(pattern: str, name: str) -> bool:
    """仅支持末尾 * 的通配，够用即可。"""
    if pattern.endswith("*"):
        return name.lower().startswith(pattern[:-1].lower())
    return pattern.lower() == name.lower()


def main() -> int:
    ap = argparse.ArgumentParser(description="ZH recorder simulator (TCP server)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=zh.DEFAULT_PORT)
    ap.add_argument("--pkt-size", type=int, default=1024)
    ap.add_argument("--type2", action="store_true", help="use framed (type 2) packets")
    ap.add_argument("--once", action="store_true", help="serve a single connection")
    args = ap.parse_args()

    rec = ZhRecorder(args.host, args.port, args.pkt_size, args.type2, zh.ZhFiles.demo())
    try:
        rec.serve_forever(once=args.once)
    except KeyboardInterrupt:
        rec.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
