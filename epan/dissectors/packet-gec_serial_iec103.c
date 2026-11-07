/* packet-gec_serial_iec103.c
 *
 * GEC 串口103
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/GEC .
 * FT1.2 变体：68 | 长度 | 长度 | 68 | 功能码 | 地址（Rtu.cpp）
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

void proto_register_gec_serial_iec103(void);
void proto_reg_handoff_gec_serial_iec103(void);

static int proto_gec_serial_iec103;
static dissector_handle_t gec_serial_iec103_handle;

static const uint8_t gec_serial_iec103_sig[1] = { 0x68 };

static vgf_profile_t gec_serial_iec103_profile = {
	0,
	"GEC 串口103",
	"FT1.2 变体：68 | 长度 | 长度 | 68 | 功能码 | 地址（Rtu.cpp）",
	VGF_CARRIER_SERIAL,
	1, { 0x68, 0x00, 0x00, 0x00, 0x00, 0x00 },
		1, 1, false, 6, 8, 1024, 0,
	5, 1, 4,
		VGF_CRC_SUM8_LOW, 1, 0, false, 0, 0,
	NULL
};

static int
dissect_gec_serial_iec103(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&gec_serial_iec103_profile);
}

void
proto_register_gec_serial_iec103(void)
{
	proto_gec_serial_iec103 = proto_register_protocol(
		"GEC 串口103",
		"GEC串口103",
		"gec_serial_iec103");

	gec_serial_iec103_profile.proto = proto_gec_serial_iec103;

	gec_serial_iec103_handle = register_dissector("gec_serial_iec103", dissect_gec_serial_iec103, proto_gec_serial_iec103);
	vgf_register(&gec_serial_iec103_profile);
}

void
proto_reg_handoff_gec_serial_iec103(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	/* Registered by name only: the menu forces this dissector onto neutral
	 * serial_raw payloads. */
}
