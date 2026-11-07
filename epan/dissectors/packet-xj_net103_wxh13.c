/* packet-xj_net103_wxh13.c
 *
 * 许继网络103(WXH13) 68 帧 + 2 字节 COT
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/XJ_NET103_WXH13 .
 * Framing and ASDU layout reuse packet-iec103-vendor-common.c; this file only
 * supplies the vendor identity and its extra TYP/COT names.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-vendor-common.h"

void proto_register_xj_net103_wxh13(void);
void proto_reg_handoff_xj_net103_wxh13(void);

static int proto_xj_net103_wxh13;
static dissector_handle_t xj_net103_wxh13_handle;

static iec103_vendor_profile_t xj_net103_wxh13_profile = {
	0,
	"许继网络103(WXH13)",
	NULL,
	"许继网络103(WXH13)",
	IEC103_POINTS_SIFANG,
	NULL,
	NULL,
	NULL,
	/* 参考实现使用 2 字节传送原因（104 风格） */
	2
};

static int
dissect_xj_net103_wxh13(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return iec103_vendor_dissect_asdu_stream(tvb, pinfo, tree, &xj_net103_wxh13_profile);
}

void
proto_register_xj_net103_wxh13(void)
{
	proto_xj_net103_wxh13 = proto_register_protocol(
		"许继网络103(WXH13)",
		"许继网络103(WXH13)",
		"xj_net103_wxh13");

	xj_net103_wxh13_profile.proto = proto_xj_net103_wxh13;

	xj_net103_wxh13_handle = register_dissector("xj_net103_wxh13", dissect_xj_net103_wxh13,
		proto_xj_net103_wxh13);

	iec103_vendor_register(&xj_net103_wxh13_profile);
	iec103_vendor_register_prefs(prefs_register_protocol(proto_xj_net103_wxh13, NULL),
		"许继网络103(WXH13)");
}

void
proto_reg_handoff_xj_net103_wxh13(void)
{
	/* Neutral capture policy: no port binding. The 网络103 menu applies
	 * Decode As for this vendor's documented port. */
	 dissector_add_for_decode_as("tcp.port", xj_net103_wxh13_handle);
	iec103_points_init();
}
