/* packet-nr103_net_iec103.c
 *
 * 南瑞网络103(NR_103_NET)
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/NR_103_NET .
 * Framing and ASDU layout reuse packet-iec103-vendor-common.c; this file only
 * supplies the vendor identity, its carrier and its private APCI.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-vendor-common.h"

void proto_register_nr103_net_iec103(void);
void proto_reg_handoff_nr103_net_iec103(void);

static int proto_nr103_net_iec103;
static dissector_handle_t nr103_net_iec103_handle;

static iec103_vendor_profile_t nr103_net_iec103_profile = {
	0,                              /* proto, filled in at registration */
	"南瑞网络103(NR_103_NET)",                    /* COL_PROTOCOL */
	NULL,
	"南瑞网络103(NR_103_NET)",                    /* unknown-ASDU expert prefix */
	IEC103_POINTS_NARI,
	NULL,                           /* extra_asdu_types */
	NULL,                           /* extra_cot */
	NULL,                           /* dissect_extra_asdu */
	1,
	0,
	1,
	NULL
};

static int
dissect_nr103_net_iec103(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return iec103_vendor_dissect_asdu_datagram(tvb, pinfo, tree, &nr103_net_iec103_profile);
}

void
proto_register_nr103_net_iec103(void)
{
	proto_nr103_net_iec103 = proto_register_protocol(
		"南瑞网络103(NR_103_NET)",
		"南瑞网络103(NR_103_NET)",
		"nr103_net_iec103");

	nr103_net_iec103_profile.proto = proto_nr103_net_iec103;

	nr103_net_iec103_handle = register_dissector("nr103_net_iec103", dissect_nr103_net_iec103, proto_nr103_net_iec103);

	iec103_vendor_register(&nr103_net_iec103_profile);
	iec103_vendor_register_prefs(prefs_register_protocol(proto_nr103_net_iec103, NULL),
		"南瑞网络103(NR_103_NET)");
}

void
proto_reg_handoff_nr103_net_iec103(void)
{
	/* Neutral capture policy: no port binding. */
	dissector_add_for_decode_as("udp.port", nr103_net_iec103_handle);
	iec103_points_init();
}
