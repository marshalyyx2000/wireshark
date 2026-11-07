/* packet-nr103_rcs9793_iec103.c
 *
 * 南瑞 RCS-9793 网络103
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/NR103_RCS9793 .
 * Framing and ASDU layout reuse packet-iec103-vendor-common.c; this file only
 * supplies the vendor identity, its carrier and its private APCI.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-vendor-common.h"

void proto_register_nr103_rcs9793_iec103(void);
void proto_reg_handoff_nr103_rcs9793_iec103(void);

static int proto_nr103_rcs9793_iec103;
static dissector_handle_t nr103_rcs9793_iec103_handle;

/* 28 字节传输头 (90 EB | 长度32LE | 90 EB | 地址 | 类型 | FF×8) */
static const iec103_apci_desc_t nr103_rcs9793_iec103_apci = {
	"28 字节传输头 (90 EB | 长度32LE | 90 EB | 地址 | 类型 | FF×8)",
	28, 2, 4, 8, false,
	4,
	{ 0, 1, 6, 7 },
	{ 0x90, 0xEB, 0x90, 0xEB }
};

static iec103_vendor_profile_t nr103_rcs9793_iec103_profile = {
	0,                              /* proto, filled in at registration */
	"南瑞 RCS-9793 网络103",                    /* COL_PROTOCOL */
	NULL,
	"南瑞 RCS-9793 网络103",                    /* unknown-ASDU expert prefix */
	IEC103_POINTS_NARI,
	NULL,                           /* extra_asdu_types */
	NULL,                           /* extra_cot */
	NULL,                           /* dissect_extra_asdu */
	1,
	0,
	1,
	&nr103_rcs9793_iec103_apci
};

static int
dissect_nr103_rcs9793_iec103(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return iec103_vendor_dissect_asdu_stream(tvb, pinfo, tree, &nr103_rcs9793_iec103_profile);
}

void
proto_register_nr103_rcs9793_iec103(void)
{
	proto_nr103_rcs9793_iec103 = proto_register_protocol(
		"南瑞 RCS-9793 网络103",
		"南瑞RCS9793网络103",
		"nr103_rcs9793_iec103");

	nr103_rcs9793_iec103_profile.proto = proto_nr103_rcs9793_iec103;

	nr103_rcs9793_iec103_handle = register_dissector("nr103_rcs9793_iec103", dissect_nr103_rcs9793_iec103, proto_nr103_rcs9793_iec103);

	iec103_vendor_register(&nr103_rcs9793_iec103_profile);
	iec103_vendor_register_prefs(prefs_register_protocol(proto_nr103_rcs9793_iec103, NULL),
		"南瑞 RCS-9793 网络103");
}

void
proto_reg_handoff_nr103_rcs9793_iec103(void)
{
	/* Neutral capture policy: no port binding. The 网络103 menu applies
	 * Decode As for this vendor's documented port. */
	dissector_add_for_decode_as("tcp.port", nr103_rcs9793_iec103_handle);
	iec103_points_init();
}
