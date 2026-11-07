/* packet-ys88a.c
 *
 * YS88A 录波器
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/YS88A .
 * Frame layout and command table live in packet-iec103-dfr-common.c.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-dfr-common.h"

void proto_register_ys88a(void);
void proto_reg_handoff_ys88a(void);

static int proto_ys88a;
static dissector_handle_t ys88a_tcp_handle;
static dissector_handle_t ys88a_udp_handle;

static dfr_vendor_profile_t ys88a_profile = {
	0,
	"YS88A 录波器",
	"YS88A录波器",
	NULL,
	NULL,
	false,
	NULL
};

static int
dissect_ys88a_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return dfr_dissect_stream(tvb, pinfo, tree, &ys88a_profile);
}

static int
dissect_ys88a_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return dfr_dissect_datagram(tvb, pinfo, tree, &ys88a_profile);
}

void
proto_register_ys88a(void)
{
	proto_ys88a = proto_register_protocol(
		"YS88A 录波器",
		"YS88A录波器",
		"ys88a");

	ys88a_profile.proto = proto_ys88a;
	ys88a_tcp_handle = register_dissector("ys88a", dissect_ys88a_tcp,
		proto_ys88a);
	ys88a_udp_handle = register_dissector("ys88a_udp", dissect_ys88a_udp,
		proto_ys88a);


	dfr_common_register(&ys88a_profile);
	prefs_register_protocol(proto_ys88a, NULL);
}

void
proto_reg_handoff_ys88a(void)
{
	/* Neutral capture policy: no port binding, the 录波器规约 menu applies
	 * Decode As at runtime. */
	dissector_add_for_decode_as("tcp.port", ys88a_tcp_handle);
	dissector_add_for_decode_as("udp.port", ys88a_udp_handle);
}
