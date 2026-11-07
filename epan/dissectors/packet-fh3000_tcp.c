/* packet-fh3000_tcp.c
 *
 * FH-3000 网络103
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/FH_3000_TCP .
 * 68 | 长度16LE | 68 | 控制域 | 地址 | ASDU（Packet.cpp）
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

void proto_register_fh3000_tcp(void);
void proto_reg_handoff_fh3000_tcp(void);

static int proto_fh3000_tcp;
static dissector_handle_t fh3000_tcp_handle;

static const uint8_t fh3000_tcp_sig[1] = { 0x68 };

static vgf_profile_t fh3000_tcp_profile = {
	0,
	"FH-3000 网络103",
	"68 | 长度16LE | 68 | 控制域 | 地址 | ASDU（Packet.cpp）",
	VGF_CARRIER_TCP,
	1, { 0x68, 0x00, 0x00, 0x00, 0x00, 0x00 },
		1, 2, false, 4, 6, 2048, 0,
	5, 1, 6,
		VGF_CRC_NONE, 0, 0, false, 0, 0,
	NULL
};

static int
dissect_fh3000_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&fh3000_tcp_profile);
}

void
proto_register_fh3000_tcp(void)
{
	proto_fh3000_tcp = proto_register_protocol(
		"FH-3000 网络103",
		"FH-3000网络103",
		"fh3000_tcp");

	fh3000_tcp_profile.proto = proto_fh3000_tcp;

	fh3000_tcp_handle = register_dissector("fh3000_tcp", dissect_fh3000_tcp, proto_fh3000_tcp);
	vgf_register(&fh3000_tcp_profile);
}

void
proto_reg_handoff_fh3000_tcp(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	dissector_add_for_decode_as("tcp.port", fh3000_tcp_handle);
}
