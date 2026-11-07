/* packet-nrcs9785_net.c
 *
 * 南瑞 RCS-9785 网络对时
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/NR_RCS_9785 .
 * UDP 数据报，首字节 0x06，随后 CP56Time2a 风格时标
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

void proto_register_nrcs9785_net(void);
void proto_reg_handoff_nrcs9785_net(void);

static int proto_nrcs9785_net;
static dissector_handle_t nrcs9785_net_handle;

static const uint8_t nrcs9785_net_sig[1] = { 0x06 };

static vgf_profile_t nrcs9785_net_profile = {
	0,
	"南瑞 RCS-9785 网络对时",
	"UDP 数据报，首字节 0x06，随后 CP56Time2a 风格时标",
	VGF_CARRIER_UDP,
	1, { 0x06, 0x00, 0x00, 0x00, 0x00, 0x00 },
		-1, 1, false, 0, 8, 64, 0,
	-1, 1, 1,
		VGF_CRC_NONE, 0, 0, false, 0, 0,
	NULL
};

static int
dissect_nrcs9785_net(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&nrcs9785_net_profile);
}

void
proto_register_nrcs9785_net(void)
{
	proto_nrcs9785_net = proto_register_protocol(
		"南瑞 RCS-9785 网络对时",
		"南瑞RCS9785网络",
		"nrcs9785_net");

	nrcs9785_net_profile.proto = proto_nrcs9785_net;

	nrcs9785_net_handle = register_dissector("nrcs9785_net", dissect_nrcs9785_net, proto_nrcs9785_net);
	vgf_register(&nrcs9785_net_profile);
}

void
proto_reg_handoff_nrcs9785_net(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	dissector_add_for_decode_as("udp.port", nrcs9785_net_handle);
}
