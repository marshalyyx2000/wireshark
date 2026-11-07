/* packet-sh2000.c
 *
 * 上海惠安 SH2000 录波器
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/SH2000 .
 * SHTX | 命令 | 长度... （Sh2000_packet.cpp 的 Set_Packet_Head/Tail）
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

void proto_register_sh2000(void);
void proto_reg_handoff_sh2000(void);

static int proto_sh2000;
static dissector_handle_t sh2000_handle;

static const uint8_t sh2000_sig[4] = { 0x53, 0x48, 0x54, 0x58 };

static vgf_profile_t sh2000_profile = {
	0,
	"上海惠安 SH2000 录波器",
	"SHTX | 命令 | 长度... （Sh2000_packet.cpp 的 Set_Packet_Head/Tail）",
	VGF_CARRIER_TCP,
	4, { 0x53, 0x48, 0x54, 0x58, 0x00, 0x00 },
		-1, 2, false, 0, 6, 65535, 0,
	-1, 1, 4,
		VGF_CRC_NONE, 0, 0, false, 0, 0,
	NULL
};

static int
dissect_sh2000(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&sh2000_profile);
}

void
proto_register_sh2000(void)
{
	proto_sh2000 = proto_register_protocol(
		"上海惠安 SH2000 录波器",
		"SH2000录波器",
		"sh2000");

	sh2000_profile.proto = proto_sh2000;

	sh2000_handle = register_dissector("sh2000", dissect_sh2000, proto_sh2000);
	vgf_register(&sh2000_profile);
}

void
proto_reg_handoff_sh2000(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	dissector_add_for_decode_as("tcp.port", sh2000_handle);
}
