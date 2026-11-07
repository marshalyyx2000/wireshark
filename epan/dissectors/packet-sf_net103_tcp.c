/* packet-sf_net103_tcp.c
 *
 * 四方网络103(TCP) 28 字节传输头
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/SF_NET103 .
 * Framing and ASDU layout reuse packet-iec103-vendor-common.c; this file only
 * supplies the vendor identity and its extra TYP/COT names.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-vendor-common.h"

void proto_register_sf_net103_tcp(void);
void proto_reg_handoff_sf_net103_tcp(void);

static int proto_sf_net103_tcp;
static dissector_handle_t sf_net103_tcp_handle;

static iec103_vendor_profile_t sf_net103_tcp_profile = {
	0,
	"四方网络103(TCP)",
	NULL,
	"四方网络103(TCP)",
	IEC103_POINTS_SIFANG,
	NULL,
	NULL,
	NULL,
	/* 参考实现使用 2 字节传送原因（104 风格） */
	2
};

static int
dissect_sf_net103_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return iec103_vendor_dissect_asdu_stream(tvb, pinfo, tree, &sf_net103_tcp_profile);
}

void
proto_register_sf_net103_tcp(void)
{
	proto_sf_net103_tcp = proto_register_protocol(
		"四方网络103(TCP)",
		"四方网络103(TCP)",
		"sf_net103_tcp");

	sf_net103_tcp_profile.proto = proto_sf_net103_tcp;

	sf_net103_tcp_handle = register_dissector("sf_net103_tcp", dissect_sf_net103_tcp,
		proto_sf_net103_tcp);

	iec103_vendor_register(&sf_net103_tcp_profile);
	iec103_vendor_register_prefs(prefs_register_protocol(proto_sf_net103_tcp, NULL),
		"四方网络103(TCP)");
}

void
proto_reg_handoff_sf_net103_tcp(void)
{
	/* Neutral capture policy: no port binding. The 网络103 menu applies
	 * Decode As for this vendor's documented port. */
	 dissector_add_for_decode_as("tcp.port", sf_net103_tcp_handle);
	iec103_points_init();
}
