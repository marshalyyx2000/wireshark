/* packet-sf103_csc103a_serial_iec103.c
 *
 * 四方 CSC-103A 串口103 FT1.2 串口
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/SF103_CSC103A .
 * Framing and ASDU layout reuse packet-iec103-vendor-common.c; this file only
 * supplies the vendor identity and its extra TYP/COT names.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-vendor-common.h"

void proto_register_sf103_csc103a_serial_iec103(void);
void proto_reg_handoff_sf103_csc103a_serial_iec103(void);

static int proto_sf103_csc103a_serial_iec103;

static iec103_vendor_profile_t sf103_csc103a_serial_iec103_profile = {
	0,
	"四方 CSC-103A 串口103",
	"单字符 E5",
	"四方 CSC-103A 串口103",
	IEC103_POINTS_SIFANG,
	NULL,
	NULL,
	NULL
};

static int
dissect_sf103_csc103a_serial_iec103(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return iec103_vendor_dissect_ft12(tvb, pinfo, tree, &sf103_csc103a_serial_iec103_profile);
}

void
proto_register_sf103_csc103a_serial_iec103(void)
{
	proto_sf103_csc103a_serial_iec103 = proto_register_protocol(
		"四方 CSC-103A 串口103",
		"四方CSC103A串口103",
		"sf103_csc103a_serial_iec103");

	sf103_csc103a_serial_iec103_profile.proto = proto_sf103_csc103a_serial_iec103;

	register_dissector("sf103_csc103a_serial_iec103", dissect_sf103_csc103a_serial_iec103, proto_sf103_csc103a_serial_iec103);

	iec103_vendor_register(&sf103_csc103a_serial_iec103_profile);
	iec103_vendor_register_prefs(prefs_register_protocol(proto_sf103_csc103a_serial_iec103, NULL),
		"四方 CSC-103A 串口103");
}

void
proto_reg_handoff_sf103_csc103a_serial_iec103(void)
{
	/* Registered by name only: the 串口103 menu forces this dissector
	 * onto neutral serial_raw payloads via serial_raw.payload_dissector. */
	iec103_points_init();
}
