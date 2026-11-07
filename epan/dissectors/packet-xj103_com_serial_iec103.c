/* packet-xj103_com_serial_iec103.c
 *
 * 许继串口103(XJ_103_COM) FT1.2 串口
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/XJ_103_COM .
 * Framing and ASDU layout reuse packet-iec103-vendor-common.c; this file only
 * supplies the vendor identity and its extra TYP/COT names.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-vendor-common.h"

void proto_register_xj103_com_serial_iec103(void);
void proto_reg_handoff_xj103_com_serial_iec103(void);

static int proto_xj103_com_serial_iec103;

static iec103_vendor_profile_t xj103_com_serial_iec103_profile = {
	0,
	"许继串口103(XJ_103_COM)",
	"单字符 E5",
	"许继串口103(XJ_103_COM)",
	IEC103_POINTS_SIFANG,
	NULL,
	NULL,
	NULL,
	/* 参考实现使用 2 字节传送原因（104 风格） */
	2
};

static int
dissect_xj103_com_serial_iec103(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return iec103_vendor_dissect_ft12(tvb, pinfo, tree, &xj103_com_serial_iec103_profile);
}

void
proto_register_xj103_com_serial_iec103(void)
{
	proto_xj103_com_serial_iec103 = proto_register_protocol(
		"许继串口103(XJ_103_COM)",
		"许继串口103(XJ_103_COM)",
		"xj103_com_serial_iec103");

	xj103_com_serial_iec103_profile.proto = proto_xj103_com_serial_iec103;

	register_dissector("xj103_com_serial_iec103", dissect_xj103_com_serial_iec103, proto_xj103_com_serial_iec103);

	iec103_vendor_register(&xj103_com_serial_iec103_profile);
	iec103_vendor_register_prefs(prefs_register_protocol(proto_xj103_com_serial_iec103, NULL),
		"许继串口103(XJ_103_COM)");
}

void
proto_reg_handoff_xj103_com_serial_iec103(void)
{
	/* Registered by name only: the 串口103 menu forces this dissector
	 * onto neutral serial_raw payloads via serial_raw.payload_dissector. */
	iec103_points_init();
}
