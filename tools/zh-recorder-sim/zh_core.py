# -*- coding: utf-8 -*-
"""武汉中元华电 ZH 系列录波器规约编解码。

帧格式（全部小端）：
  类型一: TYP(4) LEN(4) DAT(LEN)
  类型二: STX(4) STX(4) TYP(4) LEN(4) DAT(LEN) CHS(4) ETX(4) ETX(4)

字符串以 00H 结束：'ABC' 占 4 字节。
参考 tools/iec103-docs/zh-recorder.md。
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, List, Optional, Sequence

STX = 0x76337692
ETX = 0x76927633
MAX_LEN = 16376
DEFAULT_PORT = 30282

# 报文类型
PTYPE_RETURN = 0x00000001
PTYPE_TIME = 0x00000002
PTYPE_PACKETSIZE = 0x00000003
PTYPE_FRAMEDELAY = 0x00000004
PTYPE_FILE_INFO = 0x00000010
PTYPE_FILE_DATA = 0x00000011
PTYPE_FILE_GET = 0x00000012
PTYPE_FILE_PUT = 0x00000013
PTYPE_FILE_VER = 0x00000015
PTYPE_DIR_GET = 0x00000022
PTYPE_WORK_PATH = 0x0000003A
PTYPE_DATA_PATH = 0x0000003B
PTYPE_CANCEL = 0x0000006E
PTYPE_RECORD = 0x00000205
PTYPE_RECORDERINFO = 0x01000010
PTYPE_GETMODEL = 0x01000025
PTYPE_GETNEWSTATUS = 0x00000300
PTYPE_RESETNEWSTATUS = 0x00000301
PTYPE_YC = 0x00000303
PTYPE_YX = 0x00000304
PTYPE_YCEX = 0x00000305
PTYPE_CHKFRMFMT = 0x76337692

# 错误码
ECONN_SUCCESS = 0
ECONN_COMMAND = 71301
ECONN_NO_DATA = 71302


# --------------------------------------------------------------------------
# 结构体
# --------------------------------------------------------------------------

def cstr(text: str, width: int) -> bytes:
    """定长字符串，00H 结尾，不足补 0。"""
    raw = text.encode("utf-8", errors="replace")
    if len(raw) > width - 1:
        raw = raw[: width - 1]
    return raw + b"\x00" * (width - len(raw))


def cstr_decode(raw: bytes) -> str:
    """读取 00H 结尾的字符串。"""
    end = raw.find(b"\x00")
    if end >= 0:
        raw = raw[:end]
    return raw.decode("utf-8", errors="replace")


@dataclass
class DateTime:
    year: int = 2026
    month: int = 11
    day: int = 7
    hour: int = 12
    minute: int = 30
    second: int = 15
    ms: int = 250
    us: int = 0

    def pack(self) -> bytes:
        return struct.pack("<8H", self.year, self.month, self.day, self.hour,
                           self.minute, self.second, self.ms, self.us)

    @classmethod
    def now(cls) -> "DateTime":
        d = datetime.now()
        return cls(d.year, d.month, d.day, d.hour, d.minute, d.second,
                   d.microsecond // 1000, d.microsecond % 1000)


def system_time(dt: Optional[datetime] = None) -> bytes:
    dt = dt or datetime(2026, 11, 7, 12, 30, 15, 250000)
    dow = dt.isoweekday() % 7
    return struct.pack("<8H", dt.year, dt.month, dow, dt.day, dt.hour,
                       dt.minute, dt.second, dt.microsecond // 1000)


def packet_return(code: int = ECONN_SUCCESS, sender: int = 1,
                  message: str = "成功") -> bytes:
    return struct.pack("<II", code, sender) + cstr(message, 256)


def file_info(name: str, size: int, offset: int = 0, length: int = 0,
              dt: Optional[DateTime] = None, attr: int = 0x80,
              from_where: int = 0) -> bytes:
    dt = dt or DateTime()
    body = struct.pack("<I", from_where)
    body += dt.pack()
    body += struct.pack("<IIII", size, attr, offset, length)
    body += cstr(name, 256)
    assert len(body) == 292, len(body)
    return body


def file_get(name: str, from_where: int = 0, flag: int = 0,
             offset: int = 0, fid: int = 0) -> bytes:
    body = struct.pack("<HHII", from_where, flag, offset, fid) + cstr(name, 256)
    assert len(body) == 268, len(body)
    return body


def file_ver(ver: str, name: str, size: int) -> bytes:
    body = cstr(ver, 32) + file_info(name, size)
    assert len(body) == 324, len(body)
    return body


def fault_info(name: str, faulttype: int = 0x0002, jmp: int = 0x0008,
               faultid: int = 1001, size: int = 4096, dist: float = 12.5,
               linename: str = "220kV 母线 I", sti: str = "过流I段 动作",
               dt: Optional[DateTime] = None) -> bytes:
    dt = dt or DateTime()
    body = struct.pack("<HhH", 1, 1, jmp)
    body += struct.pack("<i", faultid)
    body += struct.pack("<I", size)
    body += struct.pack("<i", 0)
    body += struct.pack("<H", 1)
    body += struct.pack("<H", 0)
    body += struct.pack("<i", 0)
    body += struct.pack("<I", faulttype)
    body += struct.pack("<d", dist)
    body += dt.pack()
    body += cstr(linename, 64)
    body += cstr(name, 256)
    body += cstr(sti, 128)
    assert len(body) == 502, len(body)
    return body


def zrec_yc(gno: int, ino: int, fv: float, name: str,
            unit1: str = "kV", unit2: str = "V",
            fa2: float = 1.0, fa1: float = 1000.0, fb1: float = 0.0) -> bytes:
    body = bytes((gno & 0xFF, ino & 0xFF))
    body += struct.pack("<4f", fv, fa2, fa1, fb1)
    body += cstr(name, 48)
    body += cstr(unit1, 8)
    body += cstr(unit2, 8)
    assert len(body) == 82, len(body)
    return body


def zrec_yx(gno: int, ino: int, fv: float, name: str,
            fa2: float = 1.0, fa1: float = 1.0, fb1: float = 0.0) -> bytes:
    body = bytes((gno & 0xFF, ino & 0xFF))
    body += struct.pack("<4f", fv, fa2, fa1, fb1)
    body += cstr(name, 48)
    assert len(body) == 66, len(body)
    return body


# --------------------------------------------------------------------------
# 帧组装
# --------------------------------------------------------------------------

def frame(typ: int, dat: bytes = b"", type2: bool = False,
          bad_chs: bool = False) -> bytes:
    """组装一个 ZH 报文。"""
    if len(dat) > MAX_LEN:
        raise ValueError("DAT too long")
    if not type2:
        return struct.pack("<II", typ, len(dat)) + dat

    body = struct.pack("<II", typ, len(dat)) + dat
    chs = sum(body) & 0xFFFFFFFF
    if bad_chs:
        chs = (chs + 1) & 0xFFFFFFFF
    return (struct.pack("<I", STX) + struct.pack("<I", STX) + body
            + struct.pack("<I", chs) + struct.pack("<I", ETX) + struct.pack("<I", ETX))


def frame2(typ: int, dat: bytes = b"", bad_chs: bool = False) -> bytes:
    return frame(typ, dat, type2=True, bad_chs=bad_chs)


def file_data_chunks(payload: bytes, pkt_size: int = 1024,
                     type2: bool = False) -> List[bytes]:
    out: List[bytes] = []
    for off in range(0, len(payload), pkt_size):
        out.append(frame(PTYPE_FILE_DATA, payload[off:off + pkt_size], type2=type2))
    return out


# --------------------------------------------------------------------------
# 帧解析（用于主站与测试断言）
# --------------------------------------------------------------------------

def parse_frame(data: bytes) -> Optional[dict]:
    """解析一个 ZH 报文，返回 {type2, typ, len, dat, chs_ok}。"""
    if len(data) < 8:
        return None
    typ2 = (len(data) >= 16
            and struct.unpack_from("<I", data, 0)[0] == STX
            and struct.unpack_from("<I", data, 4)[0] == STX)
    if typ2:
        if len(data) < 16:
            return None
        typ, ln = struct.unpack_from("<II", data, 8)
        dat = data[16:16 + ln]
        chs_ok = None
        if len(data) >= 16 + ln + 12:
            chs = struct.unpack_from("<I", data, 16 + ln)[0]
            chs_ok = (chs == (sum(data[8:16 + ln]) & 0xFFFFFFFF))
        return {"type2": True, "typ": typ, "len": ln, "dat": dat, "chs_ok": chs_ok}
    typ, ln = struct.unpack_from("<II", data, 0)
    return {"type2": False, "typ": typ, "len": ln, "dat": data[8:8 + ln], "chs_ok": None}


def frame_len(buf: bytes) -> int:
    """返回缓冲区首帧的完整长度；不足或不合法返回 -1。"""
    if len(buf) < 8:
        return -1
    typ2 = (len(buf) >= 16
            and struct.unpack_from("<I", buf, 0)[0] == STX
            and struct.unpack_from("<I", buf, 4)[0] == STX)
    ln = struct.unpack_from("<I", buf, 12 if typ2 else 4)[0]
    if ln > MAX_LEN:
        return -1
    total = ln + (16 + 12 if typ2 else 8)
    return total if total <= len(buf) else -1


def split_frames(stream: bytes) -> List[bytes]:
    out: List[bytes] = []
    pos = 0
    while pos < len(stream):
        n = frame_len(stream[pos:])
        if n <= 0:
            break
        out.append(stream[pos:pos + n])
        pos += n
    return out


# --------------------------------------------------------------------------
# 抓包写入（中性以太网）
# --------------------------------------------------------------------------

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


def ipv4_tcp(src_ip: str, dst_ip: str, sport: int, dport: int, seq: int,
             ack: int, flags: int, payload: bytes = b"",
             src_mac: str = "00:11:22:33:44:55",
             dst_mac: str = "00:11:22:33:44:66") -> bytes:
    tcp = struct.pack(">HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, 8192, 0, 0)
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 0,
                     0x4000, 1, 6, 0, _ip(src_ip), _ip(dst_ip))
    ip = ip[:10] + struct.pack(">H", _cksum(ip)) + ip[12:]
    return _mac(dst_mac) + _mac(src_mac) + struct.pack(">H", 0x0800) + ip + tcp + payload


def write_eth_pcap(path, records: Iterable[tuple]) -> None:
    """records: (timestamp, ethernet_frame)."""
    import struct as _s
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.write(_s.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame_bytes in records:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            fh.write(_s.pack("<IIII", sec, usec, len(frame_bytes), len(frame_bytes)))
            fh.write(frame_bytes)


# --------------------------------------------------------------------------
# 会话脚本（主站 <-> 录波器），用于仿真与 pcap 生成
# --------------------------------------------------------------------------

@dataclass
class ZhFiles:
    """模拟录波器上的文件集合。"""
    files: dict = field(default_factory=dict)

    @classmethod
    def demo(cls) -> "ZhFiles":
        cfg = b"ZH-2 RECORDER CFG\n" + b"; sample config\n" * 40
        dat = bytes((i * 7) & 0xFF for i in range(2048))
        lst = fault_info("D:\\ZYHD\\DATA\\20261107\\REC001.zyd",
                         faulttype=0x0008, jmp=0x0008, faultid=1001, size=2048)
        lst += fault_info("D:\\ZYHD\\DATA\\20261107\\REC002.zyd",
                          faulttype=0x0001, jmp=0x0008, faultid=1002, size=1024)
        return cls(files={
            "D:\\ZYHD\\BIN\\ZHREC.SCFF": b"SCFF-V2.1\n" + b"channel table\n" * 20,
            "D:\\ZYHD\\DATA\\20261107\\REC001.cfg": cfg,
            "D:\\ZYHD\\DATA\\20261107\\REC001.dat": dat,
            "D:\\ZYHD\\DATA\\RECENT.LST": lst,
        })


def build_session(files: ZhFiles, pkt_size: int = 1024,
                  type2: bool = False) -> List[tuple]:
    """构造一次完整交互，返回 [(方向, 帧字节)] 供仿真或 pcap 使用。

    方向：'m2s' 主站→录波器，'s2m' 录波器→主站。
    """
    seq: List[tuple] = []

    def m2s(typ: int, dat: bytes = b"") -> None:
        seq.append(("m2s", frame(typ, dat, type2=type2)))

    def s2m(typ: int, dat: bytes = b"", bad_chs: bool = False) -> None:
        seq.append(("s2m", frame(typ, dat, type2=type2, bad_chs=bad_chs)))

    # 1. 检查帧格式
    m2s(PTYPE_CHKFRMFMT, struct.pack("<H", 0))
    s2m(PTYPE_RETURN, packet_return(ECONN_SUCCESS, 1, "支持类型二"))

    # 2. 查询录波器信息 / 型号 / 工作目录 / 数据目录
    m2s(PTYPE_RECORDERINFO)
    s2m(PTYPE_RETURN, packet_return(ECONN_SUCCESS, 1, "ZH-2B+ V7.6.9.8"))
    m2s(PTYPE_GETMODEL)
    s2m(PTYPE_RETURN, packet_return(ECONN_SUCCESS, 1, "ZH-2B+"))
    s2m(PTYPE_GETMODEL, struct.pack("<I", 0x02BA))
    m2s(PTYPE_WORK_PATH)
    s2m(PTYPE_RETURN, packet_return())
    s2m(PTYPE_WORK_PATH, b"E:\\ZYHD\\\x00")
    m2s(PTYPE_DATA_PATH)
    s2m(PTYPE_RETURN, packet_return())
    s2m(PTYPE_DATA_PATH, b"D:\\ZYHD\\DATA\\\x00")

    # 3. 分包大小 / 帧间隔
    m2s(PTYPE_PACKETSIZE, struct.pack("<H", pkt_size))
    s2m(PTYPE_RETURN, packet_return())
    m2s(PTYPE_FRAMEDELAY, struct.pack("<H", 0))
    s2m(PTYPE_RETURN, packet_return())

    # 4. 查询新状态，复归
    m2s(PTYPE_GETNEWSTATUS)
    s2m(PTYPE_RETURN, packet_return())
    s2m(PTYPE_GETNEWSTATUS, struct.pack("<I", 0x00000003))
    m2s(PTYPE_RESETNEWSTATUS, struct.pack("<I", 0x00000001))
    s2m(PTYPE_RETURN, packet_return())

    # 5. 列目录（RECENT.LST 内容为 FAULT_INFO 数组）
    m2s(PTYPE_DIR_GET, file_get("D:\\ZYHD\\DATA\\*.lst"))
    s2m(PTYPE_RETURN, packet_return())
    lst = files.files.get("D:\\ZYHD\\DATA\\RECENT.LST", b"")
    s2m(PTYPE_FILE_INFO, file_info("D:\\ZYHD\\DATA\\RECENT.LST", len(lst)))
    for chunk in file_data_chunks(lst, pkt_size, type2=type2):
        seq.append(("s2m", chunk))

    # 6. 召唤每个文件（含多包 .dat）
    for name in ("D:\\ZYHD\\BIN\\ZHREC.SCFF",
                 "D:\\ZYHD\\DATA\\20261107\\REC001.cfg",
                 "D:\\ZYHD\\DATA\\20261107\\REC001.dat"):
        payload = files.files.get(name, b"")
        m2s(PTYPE_FILE_GET, file_get(name))
        s2m(PTYPE_RETURN, packet_return())
        s2m(PTYPE_FILE_INFO, file_info(name, len(payload)))
        for chunk in file_data_chunks(payload, pkt_size, type2=type2):
            seq.append(("s2m", chunk))

    # 7. 文件版本
    m2s(PTYPE_FILE_VER, file_get("D:\\ZYHD\\BIN\\ZHREC.SCFF"))
    s2m(PTYPE_RETURN, packet_return())
    s2m(PTYPE_FILE_VER, file_ver("7.6.9.8", "D:\\ZYHD\\BIN\\ZHREC.SCFF", 512))

    # 8. 遥测 / 遥信 / 扩展遥测
    m2s(PTYPE_YC)
    s2m(PTYPE_RETURN, packet_return())
    s2m(PTYPE_YC, zrec_yc(20, 1, 1.732, "UA") + zrec_yc(20, 2, 1.745, "UB"))
    m2s(PTYPE_YX)
    s2m(PTYPE_RETURN, packet_return())
    s2m(PTYPE_YX, zrec_yx(30, 1, 1.0, "断路器合位") + zrec_yx(30, 2, 0.0, "弹簧未储能"))
    m2s(PTYPE_YCEX)
    s2m(PTYPE_RETURN, packet_return())
    s2m(PTYPE_YCEX, zrec_yc(21, 1, 5.0, "扩展通道 1"))

    # 9. 对时（无回答）、遥控录波（无回答）、取消
    m2s(PTYPE_TIME, system_time())
    m2s(PTYPE_RECORD)
    m2s(PTYPE_CANCEL)

    # 10. 一次错误应答，验证错误码显示
    m2s(PTYPE_FILE_GET, file_get("D:\\ZYHD\\DATA\\MISSING.zyd"))
    s2m(PTYPE_RETURN, packet_return(ECONN_NO_DATA, 1, "没有所请求的数据"))

    return seq


def tcp_records(seq: Sequence[tuple], host: str = "192.168.50.10",
                client: str = "192.168.50.20", port: int = DEFAULT_PORT,
                sport: int = 54000, start: float = 1_700_000_000.0) -> List[tuple]:
    """把会话转成以太网帧记录（中性，不带协议标记）。"""
    out: List[tuple] = []
    ts = start
    seq_c, seq_s = 1000, 5000
    off_c, off_s = 0, 0

    for direction, payload in seq:
        if direction == "m2s":
            frame_bytes = ipv4_tcp(client, host, sport, port, seq_c + off_c,
                                   seq_s + off_s, 0x18, payload,
                                   dst_mac="00:11:22:33:44:66")
            off_c += len(payload)
        else:
            frame_bytes = ipv4_tcp(host, client, port, sport, seq_s + off_s,
                                   seq_c + off_c, 0x18, payload,
                                   dst_mac="00:11:22:33:44:55")
            off_s += len(payload)
        out.append((ts, frame_bytes))
        ts += 0.01
    return out
