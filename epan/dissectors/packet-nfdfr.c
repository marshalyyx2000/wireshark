/* packet-nfdfr.c
 *
 * 南自 NFDFR 故障录波器规约（68 帧）。
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/NFDFR .
 * Frame layout and command table live in packet-iec103-dfr-common.c.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-dfr-common.h"

void proto_register_nfdfr(void);
void proto_reg_handoff_nfdfr(void);

static int proto_nfdfr;
static dissector_handle_t nfdfr_tcp_handle;
static dissector_handle_t nfdfr_udp_handle;

static dfr_vendor_profile_t nfdfr_profile = {
	0,
	"南自录波器(NFDFR)",
	"南自录波器",
	NULL,
	NULL,
	false,
	NULL
};

static int
dissect_nfdfr_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return dfr_dissect_stream(tvb, pinfo, tree, &nfdfr_profile);
}

static int
dissect_nfdfr_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return dfr_dissect_datagram(tvb, pinfo, tree, &nfdfr_profile);
}

void
proto_register_nfdfr(void)
{
	proto_nfdfr = proto_register_protocol(
		"南自录波器规约(NFDFR)",
		"南自录波器",
		"nfdfr");

	nfdfr_profile.proto = proto_nfdfr;

	nfdfr_tcp_handle = register_dissector("nfdfr", dissect_nfdfr_tcp, proto_nfdfr);
	nfdfr_udp_handle = register_dissector("nfdfr_udp", dissect_nfdfr_udp, proto_nfdfr);

	dfr_common_register(&nfdfr_profile);
	prefs_register_protocol(proto_nfdfr, NULL);
}

void
proto_reg_handoff_nfdfr(void)
{
	/* Neutral capture policy: no port binding, the 录波器规约 menu applies
	 * Decode As at runtime. */
	dissector_add_for_decode_as("tcp.port", nfdfr_tcp_handle);
	dissector_add_for_decode_as("udp.port", nfdfr_udp_handle);
}
