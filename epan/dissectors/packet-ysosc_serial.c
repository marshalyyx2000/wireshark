/* packet-ysosc_serial.c
 *
 * YS 录波器(YSOsc)
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/YSOsc .
 * 与 YS8 同构（Distribute.cpp）
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

void proto_register_ysosc_serial(void);
void proto_reg_handoff_ysosc_serial(void);

static int proto_ysosc_serial;
static dissector_handle_t ysosc_serial_handle;

static const uint8_t ysosc_serial_sig[3] = { 0xEB, 0x90, 0x68 };

static vgf_profile_t ysosc_serial_profile = {
	0,
	"YS 录波器(YSOsc)",
	"与 YS8 同构（Distribute.cpp）",
	VGF_CARRIER_SERIAL,
	3, { 0xEB, 0x90, 0x68, 0x00, 0x00, 0x00 },
		7, 2, false, 6, 10, 2048, 0,
	3, 1, 5,
		VGF_CRC_MODBUS16, 2, 0, false, 0, 0,
	NULL
};

static int
dissect_ysosc_serial(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&ysosc_serial_profile);
}

void
proto_register_ysosc_serial(void)
{
	proto_ysosc_serial = proto_register_protocol(
		"YS 录波器(YSOsc)",
		"YS录波器",
		"ysosc_serial");

	ysosc_serial_profile.proto = proto_ysosc_serial;

	ysosc_serial_handle = register_dissector("ysosc_serial", dissect_ysosc_serial, proto_ysosc_serial);
	vgf_register(&ysosc_serial_profile);
}

void
proto_reg_handoff_ysosc_serial(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	/* Registered by name only: the menu forces this dissector onto neutral
	 * serial_raw payloads. */
}
