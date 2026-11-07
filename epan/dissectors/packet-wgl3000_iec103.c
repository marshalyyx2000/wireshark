/* packet-wgl3000_iec103.c
 *
 * WGL3000 网络103
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/WGL3000 .
 * Framing and ASDU layout reuse packet-iec103-vendor-common.c; this file only
 * supplies the vendor identity, its carrier and its private APCI.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-vendor-common.h"

void proto_register_wgl3000_iec103(void);
void proto_reg_handoff_wgl3000_iec103(void);

static int proto_wgl3000_iec103;
static dissector_handle_t wgl3000_iec103_handle;

/* 6 字节传输头 (68 | 长度16BE | 68 43 地址) */
static const iec103_apci_desc_t wgl3000_iec103_apci = {
	"6 字节传输头 (68 | 长度16BE | 68 43 地址)",
	6, 1, 2, 6, true,
	3,
	{ 0, 3, 4 },
	{ 0x68, 0x68, 0x43 }
};

static iec103_vendor_profile_t wgl3000_iec103_profile = {
	0,                              /* proto, filled in at registration */
	"WGL3000 网络103",                    /* COL_PROTOCOL */
	NULL,
	"WGL3000 网络103",                    /* unknown-ASDU expert prefix */
	IEC103_POINTS_SIFANG,
	NULL,                           /* extra_asdu_types */
	NULL,                           /* extra_cot */
	NULL,                           /* dissect_extra_asdu */
	1,
	0,
	1,
	&wgl3000_iec103_apci
};

static int
dissect_wgl3000_iec103(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return iec103_vendor_dissect_asdu_stream(tvb, pinfo, tree, &wgl3000_iec103_profile);
}

void
proto_register_wgl3000_iec103(void)
{
	proto_wgl3000_iec103 = proto_register_protocol(
		"WGL3000 网络103",
		"WGL3000 网络103",
		"wgl3000_iec103");

	wgl3000_iec103_profile.proto = proto_wgl3000_iec103;

	wgl3000_iec103_handle = register_dissector("wgl3000_iec103", dissect_wgl3000_iec103, proto_wgl3000_iec103);

	iec103_vendor_register(&wgl3000_iec103_profile);
	iec103_vendor_register_prefs(prefs_register_protocol(proto_wgl3000_iec103, NULL),
		"WGL3000 网络103");
}

void
proto_reg_handoff_wgl3000_iec103(void)
{
	/* Neutral capture policy: no port binding. The 网络103 menu applies
	 * Decode As for this vendor's documented port. */
	dissector_add_for_decode_as("tcp.port", wgl3000_iec103_handle);
	iec103_points_init();
}
