/* packet-lfp_serial.c
 *
 * LFP 串口规约
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/LFP .
 * 固定 13 字节帧：头部 5 字节 | 地址 | 命令 | 2 参数 | CRC16 | 0x03（Rtu.cpp 的 FillMessage）
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

void proto_register_lfp_serial(void);
void proto_reg_handoff_lfp_serial(void);

static int proto_lfp_serial;
static dissector_handle_t lfp_serial_handle;

static const uint8_t lfp_serial_sig[1] = { 0x00 };

static vgf_profile_t lfp_serial_profile = {
	0,
	"LFP 串口规约",
	"固定 13 字节帧：头部 5 字节 | 地址 | 命令 | 2 参数 | CRC16 | 0x03（Rtu.cpp 的 FillMessage）",
	VGF_CARRIER_SERIAL,
	0, { 0x00 },
		-1, 1, false, 0, 13, 13, 13,
	5, 1, 6,
		VGF_CRC_MODBUS16, 2, 5, false, 1, 3,
	NULL
};

static int
dissect_lfp_serial(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&lfp_serial_profile);
}

void
proto_register_lfp_serial(void)
{
	proto_lfp_serial = proto_register_protocol(
		"LFP 串口规约",
		"LFP串口",
		"lfp_serial");

	lfp_serial_profile.proto = proto_lfp_serial;

	lfp_serial_handle = register_dissector("lfp_serial", dissect_lfp_serial, proto_lfp_serial);
	vgf_register(&lfp_serial_profile);
}

void
proto_reg_handoff_lfp_serial(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	/* Registered by name only: the menu forces this dissector onto neutral
	 * serial_raw payloads. */
}
