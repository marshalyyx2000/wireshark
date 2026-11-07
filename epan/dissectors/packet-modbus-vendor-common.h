/* packet-modbus-vendor-common.h
 *
 * Modbus RTU / TCP 厂商变体共享引擎。
 *
 * 一批保护/录波类厂家的"规约"其实就是标准 Modbus：功能码 0x03/0x04 读保持/
 * 输入寄存器，0x10 写多寄存器，帧尾 CRC16（多项式 0xA001，低字节在前）。
 * 参考实现见 PROTOCOL/ModBus、PROTOCOL/GE_Modbus、PROTOCOL/GE_MLINK_MODEM_MODBUS_COM。
 *
 * 本引擎按这些实现实际使用的功能码与寄存器映射解码，而不依赖通用 modbus
 * 解析器（后者需要端口绑定，与"中性抓包 + 菜单触发"策略冲突）。
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_MODBUS_VENDOR_COMMON_H
#define PACKET_MODBUS_VENDOR_COMMON_H

#include <stdbool.h>
#include <stdint.h>

#include <epan/packet.h>
#include <epan/prefs.h>

#define MODBUS_RTU_MIN_LEN 4

typedef struct modbus_vendor_profile modbus_vendor_profile_t;

struct modbus_vendor_profile {
	int proto;
	const char *col_protocol;
	const char *unknown_fn_prefix;
	/* 是否为 Modbus/TCP（MBAP 头：事务号2 + 协议号2 + 长度2 + 单元号1）。 */
	bool tcp_mbap;
	/* 报文之间的最小间隔没有约束，流式承载时需要按 MBAP 长度切分。 */
	bool lenient;
	/* 厂家自定义功能码名。 */
	const struct _value_string *extra_fn_vals;
	/* 寄存器地址语义（地址 -> 名称），可为 NULL。 */
	const struct _value_string *register_vals;
};

void modbus_vendor_register(const modbus_vendor_profile_t *profile, module_t *module);

/** RTU 帧序列（串口或裸 TCP）。 */
int modbus_vendor_dissect_rtu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
			      const modbus_vendor_profile_t *profile);

/** Modbus/TCP（MBAP 头）。 */
int modbus_vendor_dissect_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
			      const modbus_vendor_profile_t *profile);

/** 校验 RTU 帧的 CRC16。 */
bool modbus_vendor_crc_ok(tvbuff_t *tvb, int offset, int len);

#endif /* PACKET_MODBUS_VENDOR_COMMON_H */
