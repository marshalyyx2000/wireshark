#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Master-side disturbance (录波) list + full transfer sequence."""

from __future__ import annotations

import logging
import socket
import time
from typing import Callable, List, Optional

from nari_net_iec103_codec import ParsedAsdu, split_asdu_stream
from nari_wave_recording import (
    ChannelPlan,
    asdu24_ack_segment,
    asdu24_channel_tags,
    asdu24_list_request,
    asdu24_select_fault,
    asdu25_select_channel,
)

LOG = logging.getLogger("nari_wave_master")

SendFn = Callable[[bytes], None]
RecvFn = Callable[[float], List[ParsedAsdu]]


class WaveMasterSequence:
    """Drive list query + full waveform transfer (ASDU23–31)."""

    def __init__(
        self,
        primary_addr: int = 3,
        list_addrs: Optional[List[int]] = None,
        fan: int = 1,
        plan: Optional[ChannelPlan] = None,
    ) -> None:
        self.primary_addr = primary_addr
        self.list_addrs = list_addrs or [1, 2, 3]
        self.fan = fan
        self.plan = plan or ChannelPlan(segments_per_channel=3)

    def run(self, send: SendFn, recv: RecvFn) -> None:
        LOG.info("=== 召唤录波列表 (ASDU24/23) ===")
        for addr in self.list_addrs:
            send(asdu24_list_request(addr, self.fan))
            time.sleep(0.05)
            got = self._wait_types(recv, {23}, timeout=3.0)
            LOG.info("  addr=%s: received ASDU types %s", addr, sorted(got))

        LOG.info("=== 选择录波 + 通道表 (ASDU24/26/29/31) ===")
        send(asdu24_select_fault(self.primary_addr, self.fan))
        self._wait_types(recv, {26}, timeout=3.0)

        send(asdu24_channel_tags(self.primary_addr, self.fan))
        self._wait_types(recv, {29, 31}, timeout=3.0, require_any=True)

        LOG.info("=== 召唤完整录波 (ASDU25/27/24/30/31) ===")
        channels = [acc for acc, _dpi in self.plan.channels]
        # Demo uses first 3 channels to keep capture size reasonable.
        for acc in channels[:3]:
            LOG.info("  channel ACC=%s", acc)
            send(asdu25_select_channel(self.primary_addr, self.fan, acc))
            self._wait_types(recv, {27}, timeout=3.0, require_any=True)

            seg_markers = [1, 8, 8][: self.plan.segments_per_channel]
            for marker in seg_markers:
                send(asdu24_ack_segment(self.primary_addr, self.fan, marker))
                time.sleep(0.05)
                types = self._wait_types(recv, {30, 31}, timeout=4.0, require_any=True)
                if 31 in types:
                    break

        LOG.info("Wave transfer sequence complete")

    def _wait_types(
        self,
        recv: RecvFn,
        expected: set[int],
        timeout: float,
        require_any: bool = False,
    ) -> set[int]:
        deadline = time.time() + timeout
        seen: set[int] = set()
        while time.time() < deadline:
            for parsed in recv(0.15):
                seen.add(parsed.typ)
            if require_any and seen.intersection(expected):
                break
            if not require_any and expected.issubset(seen):
                break
        return seen


def make_recv_loop(conn: socket.socket, buf: bytearray) -> RecvFn:
    def recv(timeout: float) -> List[ParsedAsdu]:
        conn.settimeout(timeout)
        out: List[ParsedAsdu] = []
        try:
            chunk = conn.recv(8192)
            if chunk:
                buf.extend(chunk)
                frames, rest = split_asdu_stream(buf)
                buf.clear()
                buf.extend(rest)
                for frame in frames:
                    p = ParsedAsdu.parse(frame)
                    if p:
                        out.append(p)
        except socket.timeout:
            pass
        except OSError:
            pass
        return out

    return recv
