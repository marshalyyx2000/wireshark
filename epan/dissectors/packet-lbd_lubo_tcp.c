/* packet-lbd_lubo_tcp.c
 *
 * LBD 录波器网络规约
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/LBD_LuBo_TCP .
 * 文本命令 'f' 起始（distill.cpp / Net103.cpp）
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

void proto_register_lbd_lubo_tcp(void);
void proto_reg_handoff_lbd_lubo_tcp(void);

static int proto_lbd_lubo_tcp;
static dissector_handle_t lbd_lubo_tcp_handle;

static const uint8_t lbd_lubo_tcp_sig[1] = { 0x66 };

static vgf_profile_t lbd_lubo_tcp_profile = {
	0,
	"LBD 录波器网络规约",
	"文本命令 'f' 起始（distill.cpp / Net103.cpp）",
	VGF_CARRIER_TCP,
	1, { 0x66, 0x00, 0x00, 0x00, 0x00, 0x00 },
		-1, 1, false, 0, 8, 8192, 0,
	-1, 1, 1,
		VGF_CRC_NONE, 0, 0, false, 0, 0,
	NULL
};

static int
dissect_lbd_lubo_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&lbd_lubo_tcp_profile);
}

void
proto_register_lbd_lubo_tcp(void)
{
	proto_lbd_lubo_tcp = proto_register_protocol(
		"LBD 录波器网络规约",
		"LBD录波器网络",
		"lbd_lubo_tcp");

	lbd_lubo_tcp_profile.proto = proto_lbd_lubo_tcp;

	lbd_lubo_tcp_handle = register_dissector("lbd_lubo_tcp", dissect_lbd_lubo_tcp, proto_lbd_lubo_tcp);
	vgf_register(&lbd_lubo_tcp_profile);
}

void
proto_reg_handoff_lbd_lubo_tcp(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	dissector_add_for_decode_as("tcp.port", lbd_lubo_tcp_handle);
}
