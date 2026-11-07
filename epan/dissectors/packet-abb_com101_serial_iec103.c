/* packet-abb_com101_serial_iec103.c
 *
 * ABB 串口101(ABB_COM_101)
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/ABB_COM_101 .
 * Framing and ASDU layout reuse packet-iec103-vendor-common.c; this file only
 * supplies the vendor identity, its carrier and its private APCI.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-vendor-common.h"

void proto_register_abb_com101_serial_iec103(void);
void proto_reg_handoff_abb_com101_serial_iec103(void);

static int proto_abb_com101_serial_iec103;
static dissector_handle_t abb_com101_serial_iec103_handle;

static iec103_vendor_profile_t abb_com101_serial_iec103_profile = {
	0,                              /* proto, filled in at registration */
	"ABB 串口101(ABB_COM_101)",                    /* COL_PROTOCOL */
	"单字符 E5",
	"ABB 串口101(ABB_COM_101)",                    /* unknown-ASDU expert prefix */
	IEC103_POINTS_SIFANG,
	NULL,                           /* extra_asdu_types */
	NULL,                           /* extra_cot */
	NULL,                           /* dissect_extra_asdu */
	1,
	0,
	2,
	NULL
};

static int
dissect_abb_com101_serial_iec103(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return iec103_vendor_dissect_ft12(tvb, pinfo, tree, &abb_com101_serial_iec103_profile);
}

void
proto_register_abb_com101_serial_iec103(void)
{
	proto_abb_com101_serial_iec103 = proto_register_protocol(
		"ABB 串口101(ABB_COM_101)",
		"ABB串口101",
		"abb_com101_serial_iec103");

	abb_com101_serial_iec103_profile.proto = proto_abb_com101_serial_iec103;

	abb_com101_serial_iec103_handle = register_dissector("abb_com101_serial_iec103", dissect_abb_com101_serial_iec103, proto_abb_com101_serial_iec103);

	iec103_vendor_register(&abb_com101_serial_iec103_profile);
	iec103_vendor_register_prefs(prefs_register_protocol(proto_abb_com101_serial_iec103, NULL),
		"ABB 串口101(ABB_COM_101)");
}

void
proto_reg_handoff_abb_com101_serial_iec103(void)
{
	/* Registered by name only: the 串口103 menu forces this dissector onto
	 * neutral serial_raw payloads via serial_raw.payload_dissector. */
	iec103_points_init();
}
