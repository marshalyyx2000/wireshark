/* packet-sznari-serial-iec103.c
 *
 * 深圳南瑞（SZNARI）串口 IEC 60870-5-103 (FT1.2).
 *
 * Basis: 《深圳南瑞 IEC-103 规约说明 Ver 2.00.060901》公开章节.
 * See tools/iec103-docs/sznari.md.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-vendor-common.h"

void proto_register_sznari_serial_iec103(void);
void proto_reg_handoff_sznari_serial_iec103(void);

static int proto_sznari_serial_iec103;

static iec103_vendor_profile_t sznari_serial_profile = {
	0,
	"深圳南瑞串口103",
	"单字符 E5（深圳南瑞装置不支持，主站须兼容）",
	"深圳南瑞串口103",
	IEC103_POINTS_SZNARI
};

static int
dissect_sznari_serial_iec103(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return iec103_vendor_dissect_ft12(tvb, pinfo, tree, &sznari_serial_profile);
}

void
proto_register_sznari_serial_iec103(void)
{
	proto_sznari_serial_iec103 = proto_register_protocol(
		"深圳南瑞串口IEC60870-5-103",
		"深圳南瑞串口103",
		"sznari_serial_iec103");

	sznari_serial_profile.proto = proto_sznari_serial_iec103;

	register_dissector("sznari_serial_iec103", dissect_sznari_serial_iec103,
			   proto_sznari_serial_iec103);

	iec103_vendor_register(&sznari_serial_profile);
	iec103_vendor_register_prefs(
		prefs_register_protocol(proto_sznari_serial_iec103, NULL), "深圳南瑞串口103");
}

void
proto_reg_handoff_sznari_serial_iec103(void)
{
	iec103_points_init();
}
