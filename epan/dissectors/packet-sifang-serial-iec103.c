/* packet-sifang-serial-iec103.c
 *
 * 四方（北京四方 CSC）串口 IEC 60870-5-103 (FT1.2).
 *
 * Basis: 《四方保护与测控装置 103 规约实施细则》 (DL/T 667-1999 / idt IEC
 * 60870-5-103). See tools/iec103-docs/sifang.md.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-vendor-common.h"

void proto_register_sifang_serial_iec103(void);
void proto_reg_handoff_sifang_serial_iec103(void);

static int proto_sifang_serial_iec103;

static iec103_vendor_profile_t sifang_serial_profile = {
	0,                              /* proto, set in register */
	"四方串口103",
	"单字符 E5（四方装置可实现）",
	"四方串口103",
	IEC103_POINTS_SIFANG
};

static int
dissect_sifang_serial_iec103(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return iec103_vendor_dissect_ft12(tvb, pinfo, tree, &sifang_serial_profile);
}

void
proto_register_sifang_serial_iec103(void)
{
	proto_sifang_serial_iec103 = proto_register_protocol(
		"四方串口IEC60870-5-103",
		"四方串口103",
		"sifang_serial_iec103");

	sifang_serial_profile.proto = proto_sifang_serial_iec103;

	register_dissector("sifang_serial_iec103", dissect_sifang_serial_iec103,
			   proto_sifang_serial_iec103);

	iec103_vendor_register(&sifang_serial_profile);
	iec103_vendor_register_prefs(
		prefs_register_protocol(proto_sifang_serial_iec103, NULL), "四方串口103");
}

void
proto_reg_handoff_sifang_serial_iec103(void)
{
	/* Registered by name only: neutral serial_raw captures pick this dissector
	 * from the 串口103 menu, which sets serial_raw.payload_dissector. */
	iec103_points_init();
}
