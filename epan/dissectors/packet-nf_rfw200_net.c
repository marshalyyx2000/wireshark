/* packet-nf_rfw200_net.c
 *
 * 南瑞 RFW200 录波器
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/NF_RFW200_NET .
 * Frame layout and command table live in packet-iec103-dfr-common.c.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-dfr-common.h"

void proto_register_nf_rfw200_net(void);
void proto_reg_handoff_nf_rfw200_net(void);

static int proto_nf_rfw200_net;
static dissector_handle_t nf_rfw200_net_tcp_handle;
static dissector_handle_t nf_rfw200_net_udp_handle;

static dfr_vendor_profile_t nf_rfw200_net_profile = {
	0,
	"南瑞 RFW200 录波器",
	"南瑞RFW200录波器",
	NULL,
	NULL,
	false,
	NULL
};

static int
dissect_nf_rfw200_net_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return dfr_dissect_stream(tvb, pinfo, tree, &nf_rfw200_net_profile);
}

static int
dissect_nf_rfw200_net_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return dfr_dissect_datagram(tvb, pinfo, tree, &nf_rfw200_net_profile);
}

void
proto_register_nf_rfw200_net(void)
{
	proto_nf_rfw200_net = proto_register_protocol(
		"南瑞 RFW200 录波器",
		"南瑞RFW200录波器",
		"nf_rfw200_net");

	nf_rfw200_net_profile.proto = proto_nf_rfw200_net;
	nf_rfw200_net_tcp_handle = register_dissector("nf_rfw200_net", dissect_nf_rfw200_net_tcp,
		proto_nf_rfw200_net);
	nf_rfw200_net_udp_handle = register_dissector("nf_rfw200_net_udp", dissect_nf_rfw200_net_udp,
		proto_nf_rfw200_net);


	dfr_common_register(&nf_rfw200_net_profile);
	prefs_register_protocol(proto_nf_rfw200_net, NULL);
}

void
proto_reg_handoff_nf_rfw200_net(void)
{
	/* Neutral capture policy: no port binding, the 录波器规约 menu applies
	 * Decode As at runtime. */
	dissector_add_for_decode_as("tcp.port", nf_rfw200_net_tcp_handle);
	dissector_add_for_decode_as("udp.port", nf_rfw200_net_udp_handle);
}
