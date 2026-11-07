/* packet-ys8_serial.c
 *
 * YS8 录波器
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/YS8 .
 * EB 90 | 68 | 地址 | 0x01 | 扩展码 | 长度16LE | 主体 | CRC16 | 0x10
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

void proto_register_ys8_serial(void);
void proto_reg_handoff_ys8_serial(void);

static int proto_ys8_serial;
static dissector_handle_t ys8_serial_handle;

static const uint8_t ys8_serial_sig[3] = { 0xEB, 0x90, 0x68 };

static vgf_profile_t ys8_serial_profile = {
	0,
	"YS8 录波器",
	"EB 90 | 68 | 地址 | 0x01 | 扩展码 | 长度16LE | 主体 | CRC16 | 0x10",
	VGF_CARRIER_SERIAL,
	3, { 0xEB, 0x90, 0x68, 0x00, 0x00, 0x00 },
		7, 2, false, 6, 10, 2048, 0,
	3, 1, 5,
		VGF_CRC_MODBUS16, 2, 0, false, 0, 0,
	NULL
};

static int
dissect_ys8_serial(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&ys8_serial_profile);
}

void
proto_register_ys8_serial(void)
{
	proto_ys8_serial = proto_register_protocol(
		"YS8 录波器",
		"YS8录波器",
		"ys8_serial");

	ys8_serial_profile.proto = proto_ys8_serial;

	ys8_serial_handle = register_dissector("ys8_serial", dissect_ys8_serial, proto_ys8_serial);
	vgf_register(&ys8_serial_profile);
}

void
proto_reg_handoff_ys8_serial(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	/* Registered by name only: the menu forces this dissector onto neutral
	 * serial_raw payloads. */
}
