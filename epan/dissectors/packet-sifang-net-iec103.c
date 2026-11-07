/* packet-sifang-net-iec103.c
 *
 * 四方（北京四方 CSC2000）网络 IEC 60870-5-103 over UDP.
 *
 * Per CSC2000 网络规约 V2.0: the device multicasts 103 ASDUs (no FT1.2 header,
 * no APCI) to 236.8.8.8, device TX port 1888, master RX 1888 / TX 1889.
 * See tools/iec103-docs/sifang-net.md.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-vendor-common.h"

void proto_register_sifang_net_iec103(void);
void proto_reg_handoff_sifang_net_iec103(void);

static int proto_sifang_net_iec103;
static dissector_handle_t sifang_net_iec103_handle;

/* Documented CSC2000 ports; used by the menu/simulator, not bound by default. */
#define SIFANG_NET_UDP_DEV_PORT    1888
#define SIFANG_NET_UDP_MASTER_PORT 1889

static iec103_vendor_profile_t sifang_net_profile = {
	0,
	"四方网络103",
	NULL,
	"四方网络103",
	IEC103_POINTS_SIFANG
};

static int
dissect_sifang_net_iec103(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return iec103_vendor_dissect_asdu_datagram(tvb, pinfo, tree, &sifang_net_profile);
}

void
proto_register_sifang_net_iec103(void)
{
	proto_sifang_net_iec103 = proto_register_protocol(
		"四方网络103/UDP",
		"四方网络103",
		"sifang_net_iec103");

	sifang_net_profile.proto = proto_sifang_net_iec103;

	sifang_net_iec103_handle = register_dissector("sifang_net_iec103",
						      dissect_sifang_net_iec103,
						      proto_sifang_net_iec103);

	iec103_vendor_register(&sifang_net_profile);
	iec103_vendor_register_prefs(
		prefs_register_protocol(proto_sifang_net_iec103, NULL), "四方网络103");
}

void
proto_reg_handoff_sifang_net_iec103(void)
{
	/* Neutral capture policy: no port binding, so a UDP 1888/1889 stream is
	 * shown as plain UDP until the user picks it from 网络103 →
	 * 四方网络103规约解析. That menu applies Decode As at runtime. */
	dissector_add_for_decode_as("udp.port", sifang_net_iec103_handle);
	iec103_points_init();
}
