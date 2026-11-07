/* packet-ys_89_net.c
 *
 * YS-89 网络录波器
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/YS_89_NET .
 * Frame layout and command table live in packet-iec103-dfr-common.c.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-dfr-common.h"

void proto_register_ys_89_net(void);
void proto_reg_handoff_ys_89_net(void);

static int proto_ys_89_net;
static dissector_handle_t ys_89_net_tcp_handle;
static dissector_handle_t ys_89_net_udp_handle;

static dfr_vendor_profile_t ys_89_net_profile = {
	0,
	"YS-89 网络录波器",
	"YS-89网络录波器",
	NULL,
	NULL,
	false,
	NULL
};

static int
dissect_ys_89_net_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return dfr_dissect_stream(tvb, pinfo, tree, &ys_89_net_profile);
}

static int
dissect_ys_89_net_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return dfr_dissect_datagram(tvb, pinfo, tree, &ys_89_net_profile);
}

void
proto_register_ys_89_net(void)
{
	proto_ys_89_net = proto_register_protocol(
		"YS-89 网络录波器",
		"YS-89网络录波器",
		"ys_89_net");

	ys_89_net_profile.proto = proto_ys_89_net;
	ys_89_net_tcp_handle = register_dissector("ys_89_net", dissect_ys_89_net_tcp,
		proto_ys_89_net);
	ys_89_net_udp_handle = register_dissector("ys_89_net_udp", dissect_ys_89_net_udp,
		proto_ys_89_net);


	dfr_common_register(&ys_89_net_profile);
	prefs_register_protocol(proto_ys_89_net, NULL);
}

void
proto_reg_handoff_ys_89_net(void)
{
	/* Neutral capture policy: no port binding, the 录波器规约 menu applies
	 * Decode As at runtime. */
	dissector_add_for_decode_as("tcp.port", ys_89_net_tcp_handle);
	dissector_add_for_decode_as("udp.port", ys_89_net_udp_handle);
}
