/* packet-xj_net103_tcp_iec103.c
 *
 * 许继网络103(XJ_NET103)
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/XJ_NET103 .
 * Framing and ASDU layout reuse packet-iec103-vendor-common.c; this file only
 * supplies the vendor identity, its carrier and its private APCI.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-vendor-common.h"

void proto_register_xj_net103_tcp_iec103(void);
void proto_reg_handoff_xj_net103_tcp_iec103(void);

static int proto_xj_net103_tcp_iec103;
static dissector_handle_t xj_net103_tcp_iec103_handle;

/* 6 字节 APDU 头 (68 | APDU长度 | 发送序号×2 | 接收序号×2) */
static const iec103_apci_desc_t xj_net103_tcp_iec103_apci = {
	"6 字节 APDU 头 (68 | APDU长度 | 发送序号×2 | 接收序号×2)",
	6, 1, 1, 2, false,
	1,
	{ 0 },
	{ 0x68 }
};

static iec103_vendor_profile_t xj_net103_tcp_iec103_profile = {
	0,                              /* proto, filled in at registration */
	"许继网络103(XJ_NET103)",                    /* COL_PROTOCOL */
	NULL,
	"许继网络103(XJ_NET103)",                    /* unknown-ASDU expert prefix */
	IEC103_POINTS_SIFANG,
	NULL,                           /* extra_asdu_types */
	NULL,                           /* extra_cot */
	NULL,                           /* dissect_extra_asdu */
	2,
	0,
	1,
	&xj_net103_tcp_iec103_apci
};

static int
dissect_xj_net103_tcp_iec103(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return iec103_vendor_dissect_asdu_stream(tvb, pinfo, tree, &xj_net103_tcp_iec103_profile);
}

void
proto_register_xj_net103_tcp_iec103(void)
{
	proto_xj_net103_tcp_iec103 = proto_register_protocol(
		"许继网络103(XJ_NET103)",
		"许继网络103(XJ_NET103)",
		"xj_net103_tcp_iec103");

	xj_net103_tcp_iec103_profile.proto = proto_xj_net103_tcp_iec103;

	xj_net103_tcp_iec103_handle = register_dissector("xj_net103_tcp_iec103", dissect_xj_net103_tcp_iec103, proto_xj_net103_tcp_iec103);

	iec103_vendor_register(&xj_net103_tcp_iec103_profile);
	iec103_vendor_register_prefs(prefs_register_protocol(proto_xj_net103_tcp_iec103, NULL),
		"许继网络103(XJ_NET103)");
}

void
proto_reg_handoff_xj_net103_tcp_iec103(void)
{
	/* Neutral capture policy: no port binding. The 网络103 menu applies
	 * Decode As for this vendor's documented port. */
	dissector_add_for_decode_as("tcp.port", xj_net103_tcp_iec103_handle);
	iec103_points_init();
}
