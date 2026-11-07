/* packet-nr103_rcs9691_serial_iec103.c
 *
 * 南瑞 RCS-9691 串口103 FT1.2 串口
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/NR103_RCS9691 .
 * Framing and ASDU layout reuse packet-iec103-vendor-common.c; this file only
 * supplies the vendor identity and its extra TYP/COT names.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-vendor-common.h"

void proto_register_nr103_rcs9691_serial_iec103(void);
void proto_reg_handoff_nr103_rcs9691_serial_iec103(void);

static int proto_nr103_rcs9691_serial_iec103;

static iec103_vendor_profile_t nr103_rcs9691_serial_iec103_profile = {
	0,
	"南瑞 RCS-9691 串口103",
	"单字符 E5",
	"南瑞 RCS-9691 串口103",
	IEC103_POINTS_NARI,
	NULL,
	NULL,
	NULL
};

static int
dissect_nr103_rcs9691_serial_iec103(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return iec103_vendor_dissect_ft12(tvb, pinfo, tree, &nr103_rcs9691_serial_iec103_profile);
}

void
proto_register_nr103_rcs9691_serial_iec103(void)
{
	proto_nr103_rcs9691_serial_iec103 = proto_register_protocol(
		"南瑞 RCS-9691 串口103",
		"南瑞RCS9691串口103",
		"nr103_rcs9691_serial_iec103");

	nr103_rcs9691_serial_iec103_profile.proto = proto_nr103_rcs9691_serial_iec103;

	register_dissector("nr103_rcs9691_serial_iec103", dissect_nr103_rcs9691_serial_iec103, proto_nr103_rcs9691_serial_iec103);

	iec103_vendor_register(&nr103_rcs9691_serial_iec103_profile);
	iec103_vendor_register_prefs(prefs_register_protocol(proto_nr103_rcs9691_serial_iec103, NULL),
		"南瑞 RCS-9691 串口103");
}

void
proto_reg_handoff_nr103_rcs9691_serial_iec103(void)
{
	/* Registered by name only: the 串口103 menu forces this dissector
	 * onto neutral serial_raw payloads via serial_raw.payload_dissector. */
	iec103_points_init();
}
