/* packet-sf_udp103_iec103.c
 *
 * 四方网络103(UDP)
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/SF_UDP103 .
 * Framing and ASDU layout reuse packet-iec103-vendor-common.c; this file only
 * supplies the vendor identity, its carrier and its private APCI.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-vendor-common.h"

void proto_register_sf_udp103_iec103(void);
void proto_reg_handoff_sf_udp103_iec103(void);

static int proto_sf_udp103_iec103;
static dissector_handle_t sf_udp103_iec103_handle;

/* 28 字节传输头 (90 EB | 长度32LE | 90 EB | 地址 | 类型 | FF×8) */
static const iec103_apci_desc_t sf_udp103_iec103_apci = {
	"28 字节传输头 (90 EB | 长度32LE | 90 EB | 地址 | 类型 | FF×8)",
	28, 2, 4, 8, false,
	4,
	{ 0, 1, 6, 7 },
	{ 0x90, 0xEB, 0x90, 0xEB }
};

static iec103_vendor_profile_t sf_udp103_iec103_profile = {
	0,                              /* proto, filled in at registration */
	"四方网络103(UDP)",                    /* COL_PROTOCOL */
	NULL,
	"四方网络103(UDP)",                    /* unknown-ASDU expert prefix */
	IEC103_POINTS_SIFANG,
	NULL,                           /* extra_asdu_types */
	NULL,                           /* extra_cot */
	NULL,                           /* dissect_extra_asdu */
	1,
	0,
	1,
	&sf_udp103_iec103_apci
};

static int
dissect_sf_udp103_iec103(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return iec103_vendor_dissect_asdu_datagram(tvb, pinfo, tree, &sf_udp103_iec103_profile);
}

void
proto_register_sf_udp103_iec103(void)
{
	proto_sf_udp103_iec103 = proto_register_protocol(
		"四方网络103(UDP)",
		"四方网络103(UDP)",
		"sf_udp103_iec103");

	sf_udp103_iec103_profile.proto = proto_sf_udp103_iec103;

	sf_udp103_iec103_handle = register_dissector("sf_udp103_iec103", dissect_sf_udp103_iec103, proto_sf_udp103_iec103);

	iec103_vendor_register(&sf_udp103_iec103_profile);
	iec103_vendor_register_prefs(prefs_register_protocol(proto_sf_udp103_iec103, NULL),
		"四方网络103(UDP)");
}

void
proto_reg_handoff_sf_udp103_iec103(void)
{
	/* Neutral capture policy: no port binding. */
	dissector_add_for_decode_as("udp.port", sf_udp103_iec103_handle);
	iec103_points_init();
}
