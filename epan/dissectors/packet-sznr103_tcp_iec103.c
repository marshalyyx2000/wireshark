/* packet-sznr103_tcp_iec103.c
 *
 * 深圳南瑞网络103(TCP)
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/SZNR_103_TCP .
 * Framing and ASDU layout reuse packet-iec103-vendor-common.c; this file only
 * supplies the vendor identity, its carrier and its private APCI.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-vendor-common.h"

void proto_register_sznr103_tcp_iec103(void);
void proto_reg_handoff_sznr103_tcp_iec103(void);

static int proto_sznr103_tcp_iec103;
static dissector_handle_t sznr103_tcp_iec103_handle;

static iec103_vendor_profile_t sznr103_tcp_iec103_profile = {
	0,                              /* proto, filled in at registration */
	"深圳南瑞网络103(TCP)",                    /* COL_PROTOCOL */
	NULL,
	"深圳南瑞网络103(TCP)",                    /* unknown-ASDU expert prefix */
	IEC103_POINTS_SZNARI,
	NULL,                           /* extra_asdu_types */
	NULL,                           /* extra_cot */
	NULL,                           /* dissect_extra_asdu */
	1,
	0,
	1,
	NULL
};

static int
dissect_sznr103_tcp_iec103(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return iec103_vendor_dissect_ft12_stream(tvb, pinfo, tree, &sznr103_tcp_iec103_profile);
}

void
proto_register_sznr103_tcp_iec103(void)
{
	proto_sznr103_tcp_iec103 = proto_register_protocol(
		"深圳南瑞网络103(TCP)",
		"深圳南瑞网络103(TCP)",
		"sznr103_tcp_iec103");

	sznr103_tcp_iec103_profile.proto = proto_sznr103_tcp_iec103;

	sznr103_tcp_iec103_handle = register_dissector("sznr103_tcp_iec103", dissect_sznr103_tcp_iec103, proto_sznr103_tcp_iec103);

	iec103_vendor_register(&sznr103_tcp_iec103_profile);
	iec103_vendor_register_prefs(prefs_register_protocol(proto_sznr103_tcp_iec103, NULL),
		"深圳南瑞网络103(TCP)");
}

void
proto_reg_handoff_sznr103_tcp_iec103(void)
{
	/* Neutral capture policy: no port binding. The 网络103 menu applies
	 * Decode As for this vendor's documented port. */
	dissector_add_for_decode_as("tcp.port", sznr103_tcp_iec103_handle);
	iec103_points_init();
}
