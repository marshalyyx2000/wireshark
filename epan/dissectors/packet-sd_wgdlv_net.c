/* packet-sd_wgdlv_net.c
 *
 * 山东 WGDLV 网络录波器
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/SD_WGDLV_NET .
 * 68 | 长度16LE | 68 | 控制域 | 链路地址（DFR.cpp）
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

void proto_register_sd_wgdlv_net(void);
void proto_reg_handoff_sd_wgdlv_net(void);

static int proto_sd_wgdlv_net;
static dissector_handle_t sd_wgdlv_net_handle;

static const uint8_t sd_wgdlv_net_sig[1] = { 0x68 };

static vgf_profile_t sd_wgdlv_net_profile = {
	0,
	"山东 WGDLV 网络录波器",
	"68 | 长度16LE | 68 | 控制域 | 链路地址（DFR.cpp）",
	VGF_CARRIER_TCP,
	1, { 0x68, 0x00, 0x00, 0x00, 0x00, 0x00 },
		1, 2, false, 4, 6, 2048, 0,
	5, 1, 6,
		VGF_CRC_NONE, 0, 0, false, 0, 0,
	NULL
};

static int
dissect_sd_wgdlv_net(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&sd_wgdlv_net_profile);
}

void
proto_register_sd_wgdlv_net(void)
{
	proto_sd_wgdlv_net = proto_register_protocol(
		"山东 WGDLV 网络录波器",
		"山东WGDLV网络录波器",
		"sd_wgdlv_net");

	sd_wgdlv_net_profile.proto = proto_sd_wgdlv_net;

	sd_wgdlv_net_handle = register_dissector("sd_wgdlv_net", dissect_sd_wgdlv_net, proto_sd_wgdlv_net);
	vgf_register(&sd_wgdlv_net_profile);
}

void
proto_reg_handoff_sd_wgdlv_net(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	dissector_add_for_decode_as("tcp.port", sd_wgdlv_net_handle);
}
