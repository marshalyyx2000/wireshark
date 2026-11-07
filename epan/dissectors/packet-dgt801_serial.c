/* packet-dgt801_serial.c
 *
 * DGT801 串口规约
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/DGT801 .
 * 地址 | 功能码 | … | CRC16(低字节在前)（Rtu.cpp 的 SendConnectFrame）
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

void proto_register_dgt801_serial(void);
void proto_reg_handoff_dgt801_serial(void);

static int proto_dgt801_serial;
static dissector_handle_t dgt801_serial_handle;

static const uint8_t dgt801_serial_sig[1] = { 0x00 };

static vgf_profile_t dgt801_serial_profile = {
	0,
	"DGT801 串口规约",
	"地址 | 功能码 | … | CRC16(低字节在前)（Rtu.cpp 的 SendConnectFrame）",
	VGF_CARRIER_SERIAL,
	0, { 0x00 },
		-1, 1, false, 0, 5, 1024, 0,
	0, 1, 1,
		VGF_CRC_MODBUS16, 2, 0, false, 0, 0,
	NULL
};

static int
dissect_dgt801_serial(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&dgt801_serial_profile);
}

void
proto_register_dgt801_serial(void)
{
	proto_dgt801_serial = proto_register_protocol(
		"DGT801 串口规约",
		"DGT801串口",
		"dgt801_serial");

	dgt801_serial_profile.proto = proto_dgt801_serial;

	dgt801_serial_handle = register_dissector("dgt801_serial", dissect_dgt801_serial, proto_dgt801_serial);
	vgf_register(&dgt801_serial_profile);
}

void
proto_reg_handoff_dgt801_serial(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	/* Registered by name only: the menu forces this dissector onto neutral
	 * serial_raw payloads. */
}
