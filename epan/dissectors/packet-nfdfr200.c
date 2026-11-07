/* packet-nfdfr200.c
 *
 * 南自录波器200(NFDFR200)
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/NFDFR200 .
 * Frame layout and command table live in packet-iec103-dfr-common.c.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-dfr-common.h"

void proto_register_nfdfr200(void);
void proto_reg_handoff_nfdfr200(void);

static int proto_nfdfr200;
static dissector_handle_t nfdfr200_tcp_handle;
static dissector_handle_t nfdfr200_udp_handle;

static dfr_vendor_profile_t nfdfr200_profile = {
	0,
	"南自录波器200(NFDFR200)",
	"南自录波器200",
	NULL,
	NULL,
	false,
	NULL
};

static int
dissect_nfdfr200_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return dfr_dissect_stream(tvb, pinfo, tree, &nfdfr200_profile);
}

static int
dissect_nfdfr200_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return dfr_dissect_datagram(tvb, pinfo, tree, &nfdfr200_profile);
}

void
proto_register_nfdfr200(void)
{
	proto_nfdfr200 = proto_register_protocol(
		"南自录波器200(NFDFR200)",
		"南自录波器200",
		"nfdfr200");

	nfdfr200_profile.proto = proto_nfdfr200;
	nfdfr200_tcp_handle = register_dissector("nfdfr200", dissect_nfdfr200_tcp,
		proto_nfdfr200);
	nfdfr200_udp_handle = register_dissector("nfdfr200_udp", dissect_nfdfr200_udp,
		proto_nfdfr200);


	dfr_common_register(&nfdfr200_profile);
	prefs_register_protocol(proto_nfdfr200, NULL);
}

void
proto_reg_handoff_nfdfr200(void)
{
	/* Neutral capture policy: no port binding, the 录波器规约 menu applies
	 * Decode As at runtime. */
	dissector_add_for_decode_as("tcp.port", nfdfr200_tcp_handle);
	dissector_add_for_decode_as("udp.port", nfdfr200_udp_handle);
}
