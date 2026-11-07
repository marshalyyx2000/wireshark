/* packet-vendor-generic-frame.h
 *
 * 声明式私有帧引擎。
 *
 * 有一批厂家的"规约"没有公开的字段语义，参考实现里也只有帧头、长度和校验，
 * 真正的内容是厂家自定义的紧凑二进制。对它逐字节发明字段名是错误的，所以
 * 这里只做**可靠可验证**的那一层：
 *   - 帧同步（固定签名）
 *   - 帧长度（长度字段位置/宽度/端序/偏置）
 *   - 校验（和校验 / Modbus CRC16 / 累加和）
 *   - 地址、命令/类型字段
 * 主体以字节形式呈现，并标注"厂家自定义主体"，不做臆测。
 *
 * 依据：tools/现场运行的各种规约程序/PROTOCOL/&lt;vendor&gt; 中各厂家的
 * Send / Request 函数里的 buf 赋值序列。
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_VENDOR_GENERIC_FRAME_H
#define PACKET_VENDOR_GENERIC_FRAME_H

#include <stdbool.h>
#include <stdint.h>

#include <epan/packet.h>
#include <epan/prefs.h>

#define VGF_MAX_SIG 6

typedef enum {
	VGF_CRC_NONE = 0,
	VGF_CRC_SUM8,        /* 逐字节累加，低位在前，尾部 2 字节 */
	VGF_CRC_SUM8_LOW,    /* 逐字节累加，尾部 1 字节 */
	VGF_CRC_MODBUS16,    /* CRC16/Modbus，低字节在前 */
} vgf_crc_t;

typedef enum {
	VGF_CARRIER_SERIAL = 0,   /* FT1.2 之外的裸帧，写在 serial_raw */
	VGF_CARRIER_TCP,
	VGF_CARRIER_UDP,
} vgf_carrier_t;

typedef struct vgf_profile vgf_profile_t;

struct vgf_profile {
	int proto;
	const char *col_protocol;
	const char *note;              /* 显示在根节点上的说明 */
	vgf_carrier_t carrier;

	/* 帧同步签名：synchronised at offset 0 of each frame. */
	unsigned sig_len;
	uint8_t sig[VGF_MAX_SIG];

	/* 帧长度：-1 表示"到报文结束"（一包一帧）。 */
	int len_off;
	int len_size;                  /* 1, 2 or 4 */
	bool len_be;
	int len_bias;                  /* 帧总长 = 长度字段值 + len_bias */
	int min_len;
	int max_len;
	int fixed_len;                 /* >0 表示定长帧，忽略长度字段 */

	/* 地址 / 命令字段的位置，-1 表示该厂家没有。 */
	int addr_off;
	int addr_size;
	int cmd_off;

	vgf_crc_t crc;
	int crc_tail;                  /* 校验占用的尾部字节数 */
	int crc_off;                   /* 校验计算起点（相对帧首），默认 0 */
	/* 文本行帧：帧体是可打印 ASCII，以 CR 结束（ASCII 电表类）。 */
	bool ascii_line;
	/* CRC 之后还有固定尾字节（如 LFP 的 0x03 结束符）时，指出其值。 */
	int crc_tail_extra;
	uint8_t crc_tail_byte;

	/* 命令码名称表，可为 NULL。 */
	const struct _value_string *cmd_vals;
};

void vgf_register(const vgf_profile_t *profile);

int vgf_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

#endif /* PACKET_VENDOR_GENERIC_FRAME_H */
