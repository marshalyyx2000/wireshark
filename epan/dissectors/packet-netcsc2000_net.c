/* packet-netcsc2000_net.c
 *
 * 南自 CSC2000 网络规约
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/NetCSC2000 .
 * 长度 | 地址 | 组号 | 定值类型（Csc2000.cpp 的报文头）
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

void proto_register_netcsc2000_net(void);
void proto_reg_handoff_netcsc2000_net(void);

static int proto_netcsc2000_net;
static dissector_handle_t netcsc2000_net_handle;

static const uint8_t netcsc2000_net_sig[1] = { 0x00 };

static vgf_profile_t netcsc2000_net_profile = {
	0,
	"南自 CSC2000 网络规约",
	"长度 | 地址 | 组号 | 定值类型（Csc2000.cpp 的报文头）",
	VGF_CARRIER_TCP,
	0, { 0x00 },
		0, 1, false, 0, 6, 4096, 0,
	1, 1, 2,
		VGF_CRC_NONE, 0, 0, false, 0, 0,
	NULL
};

static int
dissect_netcsc2000_net(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&netcsc2000_net_profile);
}

void
proto_register_netcsc2000_net(void)
{
	proto_netcsc2000_net = proto_register_protocol(
		"南自 CSC2000 网络规约",
		"CSC2000网络",
		"netcsc2000_net");

	netcsc2000_net_profile.proto = proto_netcsc2000_net;

	netcsc2000_net_handle = register_dissector("netcsc2000_net", dissect_netcsc2000_net, proto_netcsc2000_net);
	vgf_register(&netcsc2000_net_profile);
}

void
proto_reg_handoff_netcsc2000_net(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	dissector_add_for_decode_as("tcp.port", netcsc2000_net_handle);
}
