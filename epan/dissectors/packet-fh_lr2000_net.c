/* packet-fh_lr2000_net.c
 *
 * FH LR2000 网络录波器
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/FH_LR2000_NET .
 * 68 | 地址 | 命令 | FF 00 00 | 长度32LE（与南自 NFDFR 同构）
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

void proto_register_fh_lr2000_net(void);
void proto_reg_handoff_fh_lr2000_net(void);

static int proto_fh_lr2000_net;
static dissector_handle_t fh_lr2000_net_handle;

static const uint8_t fh_lr2000_net_sig[1] = { 0x68 };

static vgf_profile_t fh_lr2000_net_profile = {
	0,
	"FH LR2000 网络录波器",
	"68 | 地址 | 命令 | FF 00 00 | 长度32LE（与南自 NFDFR 同构）",
	VGF_CARRIER_TCP,
	1, { 0x68, 0x00, 0x00, 0x00, 0x00, 0x00 },
		6, 4, false, 0, 10, 65535, 0,
	1, 1, 2,
		VGF_CRC_NONE, 0, 0, false, 0, 0,
	NULL
};

static int
dissect_fh_lr2000_net(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&fh_lr2000_net_profile);
}

void
proto_register_fh_lr2000_net(void)
{
	proto_fh_lr2000_net = proto_register_protocol(
		"FH LR2000 网络录波器",
		"FHLR2000网络录波器",
		"fh_lr2000_net");

	fh_lr2000_net_profile.proto = proto_fh_lr2000_net;

	fh_lr2000_net_handle = register_dissector("fh_lr2000_net", dissect_fh_lr2000_net, proto_fh_lr2000_net);
	vgf_register(&fh_lr2000_net_profile);
}

void
proto_reg_handoff_fh_lr2000_net(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	dissector_add_for_decode_as("tcp.port", fh_lr2000_net_handle);
}
