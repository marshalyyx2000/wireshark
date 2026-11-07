/* packet-wfbl_ftp103.c
 *
 * WFBL 网络103(FTP 承载)
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/WFBL_FTP103 .
 * 90 EB + 长度32LE + 90 EB 传输头（与南自 NZ_NET103 同构）
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

void proto_register_wfbl_ftp103(void);
void proto_reg_handoff_wfbl_ftp103(void);

static int proto_wfbl_ftp103;
static dissector_handle_t wfbl_ftp103_handle;

static const uint8_t wfbl_ftp103_sig[2] = { 0x90, 0xEB };

static vgf_profile_t wfbl_ftp103_profile = {
	0,
	"WFBL 网络103(FTP 承载)",
	"90 EB + 长度32LE + 90 EB 传输头（与南自 NZ_NET103 同构）",
	VGF_CARRIER_TCP,
	2, { 0x90, 0xEB, 0x00, 0x00, 0x00, 0x00 },
		2, 4, false, 8, 28, 65535, 0,
	27, 1, 28,
		VGF_CRC_NONE, 0, 0, false, 0, 0,
	NULL
};

static int
dissect_wfbl_ftp103(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&wfbl_ftp103_profile);
}

void
proto_register_wfbl_ftp103(void)
{
	proto_wfbl_ftp103 = proto_register_protocol(
		"WFBL 网络103(FTP 承载)",
		"WFBL网络103",
		"wfbl_ftp103");

	wfbl_ftp103_profile.proto = proto_wfbl_ftp103;

	wfbl_ftp103_handle = register_dissector("wfbl_ftp103", dissect_wfbl_ftp103, proto_wfbl_ftp103);
	vgf_register(&wfbl_ftp103_profile);
}

void
proto_reg_handoff_wfbl_ftp103(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	dissector_add_for_decode_as("tcp.port", wfbl_ftp103_handle);
}
