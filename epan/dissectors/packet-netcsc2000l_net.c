/* packet-netcsc2000l_net.c
 *
 * 南自 CSC2000L 网络规约
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/NetCSC2000L .
 * 03 | FF | 主站地址 | 0x20（Csc2000L.cpp）
 * Frame synchronisation, length and checksum come from
 * packet-vendor-generic-frame.c; the body is vendor-defined and stays as bytes
 * because the reference implementation carries no field semantics for it.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-vendor-generic-frame.h"

void proto_register_netcsc2000l_net(void);
void proto_reg_handoff_netcsc2000l_net(void);

static int proto_netcsc2000l_net;
static dissector_handle_t netcsc2000l_net_handle;

static const uint8_t netcsc2000l_net_sig[2] = { 0x03, 0xFF };

static vgf_profile_t netcsc2000l_net_profile = {
	0,
	"南自 CSC2000L 网络规约",
	"03 | FF | 主站地址 | 0x20（Csc2000L.cpp）",
	VGF_CARRIER_UDP,
	2, { 0x03, 0xFF, 0x00, 0x00, 0x00, 0x00 },
		-1, 1, false, 0, 6, 512, 0,
	2, 1, 3,
		VGF_CRC_NONE, 0, 0, false, 0, 0,
	NULL
};

static int
dissect_netcsc2000l_net(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&netcsc2000l_net_profile);
}

void
proto_register_netcsc2000l_net(void)
{
	proto_netcsc2000l_net = proto_register_protocol(
		"南自 CSC2000L 网络规约",
		"CSC2000L网络",
		"netcsc2000l_net");

	netcsc2000l_net_profile.proto = proto_netcsc2000l_net;

	netcsc2000l_net_handle = register_dissector("netcsc2000l_net", dissect_netcsc2000l_net, proto_netcsc2000l_net);
	vgf_register(&netcsc2000l_net_profile);
}

void
proto_reg_handoff_netcsc2000l_net(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	dissector_add_for_decode_as("udp.port", netcsc2000l_net_handle);
}
