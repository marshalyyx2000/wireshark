/* packet-iec103-dfr-common.h
 *
 * 录波器（故障录波器）68 帧共享引擎。
 *
 * 一批国内录波器厂家的私有规约在帧结构上完全一致，只是命令码表和
 * 若干字段的解释不同：
 *
 *   68 | 地址(1) | 命令(1) | 应答标志(1) | 密码/保留(2) | 报文总长(4, 小端) | 主体
 *
 * 报文总长包含前面 10 字节头。校验为逐字节累加（可选）。
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_IEC103_DFR_COMMON_H
#define PACKET_IEC103_DFR_COMMON_H

#include <stdbool.h>
#include <stdint.h>

#include <epan/packet.h>
#include <epan/prefs.h>

#define DFR_HDR_LEN        10
#define DFR_START          0x68
#define DFR_ANSWER_SUCCESS 0x00
#define DFR_ANSWER_FAIL    0x01

/* 命令码，取值来自 PROTOCOL/NFDFR/DFR.h 等参考实现。 */
typedef enum {
	DFR_CMD_WORKSTATUS   = 0x80,  /* 查询最新工作状态 */
	DFR_CMD_SEARCHFILE   = 0x81,  /* 检索录波文件目录 */
	DFR_CMD_DOWNLOADFILE = 0x82,  /* 请求下载文件 */
	DFR_CMD_REQUESTDATA  = 0x84,  /* 请求实时数据 / 定值 */
	DFR_CMD_CONTROL      = 0x85,  /* 遥控 / 启动录波 */
	DFR_CMD_RESETCOMM    = 0x86,  /* 复位通信 */
	DFR_CMD_TIMESYNC     = 0x87,  /* 对时 */
} dfr_cmd_t;

typedef struct dfr_vendor_profile dfr_vendor_profile_t;

/** 一家录波器厂家的描述。 */
struct dfr_vendor_profile {
	int proto;                      /* 由厂家模块填写 */
	const char *col_protocol;
	const char *unknown_cmd_prefix;
	/* 命令码覆盖表，NULL 表示使用内建表。 */
	const struct _value_string *cmd_vals;
	/* 应答标志覆盖表。 */
	const struct _value_string *answer_vals;
	/* TCP 承载时首字节不是 0x68 的情况下，是否仍按 68 帧尝试。 */
	bool lenient_start;
	/* 私有附加命令解码（命令码之外的厂家自有逻辑）。 */
	bool (*dissect_extra_cmd)(tvbuff_t *tvb, int *offset, int end,
				  packet_info *pinfo, proto_tree *tree,
				  const dfr_vendor_profile_t *profile);
};

/** 注册字段/子树/专家信息，并登记到共享表。 */
void dfr_common_register(const dfr_vendor_profile_t *profile);

/** 一个 TCP 流内可能承载多个 68 帧。 */
int dfr_dissect_stream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		       const dfr_vendor_profile_t *profile);

/** 一个 UDP 数据报内通常只有一帧。 */
int dfr_dissect_datagram(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
			 const dfr_vendor_profile_t *profile);

/** 判断 payload 是否像一条 68 帧。 */
bool dfr_looks_like_frame(tvbuff_t *tvb, int offset, int remaining);

/** 该厂家命令码的可读名（用于 COL_INFO 与外部工具）。 */
const char *dfr_cmd_name(const dfr_vendor_profile_t *profile, uint8_t cmd);

#endif /* PACKET_IEC103_DFR_COMMON_H */
