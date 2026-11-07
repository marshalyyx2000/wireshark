/* packet-huaruit_fwk_com.c
 *
 * 华瑞泰 FWK 串口规约
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/HuaRuiT_FWK_COM .
 * AA | 长度 | 地址 | 命令/数据类型 | 时间 | 校验和16LE（Packet.cpp）
 * Frame synchronisation, length and checksum come from
 * packet-vendor-generic-frame.c; the body is vendor-defined and stays as bytes
 * because the reference implementation carries no field semantics for it.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-vendor-generic-frame.h"

void proto_register_huaruit_fwk_com(void);
void proto_reg_handoff_huaruit_fwk_com(void);

static int proto_huaruit_fwk_com;
static dissector_handle_t huaruit_fwk_com_handle;

static const uint8_t huaruit_fwk_com_sig[1] = { 0xAA };

static vgf_profile_t huaruit_fwk_com_profile = {
	0,
	"华瑞泰 FWK 串口规约",
	"AA | 长度 | 地址 | 命令/数据类型 | 时间 | 校验和16LE（Packet.cpp）",
	VGF_CARRIER_SERIAL,
	1, { 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00 },
		1, 1, false, 2, 12, 512, 0,
	2, 1, 3,
		VGF_CRC_SUM8, 2, 1, false, 0, 0,
	NULL
};

static int
dissect_huaruit_fwk_com(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&huaruit_fwk_com_profile);
}

void
proto_register_huaruit_fwk_com(void)
{
	proto_huaruit_fwk_com = proto_register_protocol(
		"华瑞泰 FWK 串口规约",
		"华瑞泰FWK串口",
		"huaruit_fwk_com");

	huaruit_fwk_com_profile.proto = proto_huaruit_fwk_com;

	huaruit_fwk_com_handle = register_dissector("huaruit_fwk_com", dissect_huaruit_fwk_com, proto_huaruit_fwk_com);
	vgf_register(&huaruit_fwk_com_profile);
}

void
proto_reg_handoff_huaruit_fwk_com(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	/* Registered by name only: the menu forces this dissector onto neutral
	 * serial_raw payloads. */
}
