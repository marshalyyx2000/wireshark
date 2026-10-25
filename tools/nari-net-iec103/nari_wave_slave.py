#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Slave-side disturbance (录波) responses."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from nari_net_iec103_codec import COT_SPONT, asdu_identification, asdu_protection_measurements, ParsedAsdu
from nari_wave_recording import (
    TOO_ACK_DATA,
    TOO_CHANNEL_TAGS,
    TOO_LIST_DISTURBANCES,
    TOO_SELECT_CHANNEL,
    TOO_SELECT_FAULT,
    ChannelPlan,
    WaveCatalog,
    asdu23_disturbance_list,
    asdu26_ready_values,
    asdu27_channel_ready,
    asdu29_channel_list,
    asdu29_end_of_tags,
    asdu30_disturbance_data,
    asdu31_channel_done,
    asdu31_ready_next,
    fan_from_dist_body,
    parse_dist_cmd,
    synthetic_samples,
)


@dataclass
class WaveSlaveState:
    catalog: WaveCatalog = field(default_factory=WaveCatalog.demo)
    plan: ChannelPlan = field(default_factory=ChannelPlan)
    selected_fan: int = 1
    tags_sent: bool = False
    # Per-channel segment index after ASDU25
    channel_acc: int = 0
    segment_idx: int = 0
    awaiting_ack: bool = False


class WaveSlaveResponder:
    def __init__(self, addr: int) -> None:
        self.addr = addr
        self.state = WaveSlaveState()

    def respond(self, parsed: ParsedAsdu) -> List[bytes]:
        if parsed.typ in (6, 7):
            return [
                asdu_identification(self.addr, cot=9 if parsed.typ == 7 else 8),
                asdu_protection_measurements(self.addr),
            ]

        if parsed.typ == 24:
            return self._on_asdu24(parsed)
        if parsed.typ == 25:
            return self._on_asdu25(parsed)
        return []

    def _on_asdu24(self, parsed: ParsedAsdu) -> List[bytes]:
        cmd = parse_dist_cmd(parsed.payload)
        if not cmd:
            return []
        too, _tov, fan, acc = cmd
        self.state.selected_fan = fan or self.state.selected_fan

        if too == TOO_LIST_DISTURBANCES:
            return [self.state.catalog.asdu23_for(parsed.addr)]

        if too == TOO_SELECT_FAULT:
            return [asdu26_ready_values(self.addr, self.state.selected_fan)]

        if too == TOO_CHANNEL_TAGS:
            if not self.state.tags_sent:
                self.state.tags_sent = True
                return [
                    asdu29_channel_list(
                        self.addr,
                        self.state.selected_fan,
                        self.state.plan.channels,
                    ),
                    asdu29_end_of_tags(self.addr, self.state.selected_fan),
                    asdu31_ready_next(self.addr, self.state.selected_fan),
                ]
            return [
                asdu29_end_of_tags(self.addr, self.state.selected_fan),
                asdu31_ready_next(self.addr, self.state.selected_fan),
            ]

        if too == TOO_ACK_DATA:
            return self._send_segment(acc)

        return []

    def _on_asdu25(self, parsed: ParsedAsdu) -> List[bytes]:
        cmd = parse_dist_cmd(parsed.payload)
        if cmd:
            _too, _tov, fan, acc = cmd
        else:
            fan = fan_from_dist_body(parsed.payload)
            acc = 1
        self.state.selected_fan = fan
        self.state.channel_acc = acc
        self.state.segment_idx = 0
        self.state.awaiting_ack = True
        return [asdu27_channel_ready(self.addr, fan, acc)]

    def _send_segment(self, ack_acc: int) -> List[bytes]:
        if not self.state.awaiting_ack:
            return []

        seg = self.state.segment_idx
        fan = self.state.selected_fan
        acc = self.state.channel_acc
        count = self.state.plan.sample_count(seg)
        samples = synthetic_samples(count, seed=acc * 16 + seg)
        nfe = self.state.plan.nfe_for(seg)
        pkt = asdu30_disturbance_data(self.addr, fan, acc, nfe, samples)
        self.state.segment_idx += 1

        if self.state.segment_idx >= self.state.plan.segments_per_channel:
            self.state.awaiting_ack = False
            self.state.segment_idx = 0
            return [pkt, asdu31_channel_done(self.addr, fan, acc)]

        return [pkt]
