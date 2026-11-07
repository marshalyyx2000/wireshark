/* packet-fh_lr12_com.c
 *
 * FH LR12 串口录波器
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/FH_LR12_COM .
 * 68 | 地址 | 命令 | FF 00 00 | 长度32LE
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

void proto_register_fh_lr12_com(void);
void proto_reg_handoff_fh_lr12_com(void);

static int proto_fh_lr12_com;
static dissector_handle_t fh_lr12_com_handle;

static const uint8_t fh_lr12_com_sig[1] = { 0x68 };

static vgf_profile_t fh_lr12_com_profile = {
	0,
	"FH LR12 串口录波器",
	"68 | 地址 | 命令 | FF 00 00 | 长度32LE",
	VGF_CARRIER_SERIAL,
	1, { 0x68, 0x00, 0x00, 0x00, 0x00, 0x00 },
		6, 4, false, 0, 10, 65535, 0,
	1, 1, 2,
		VGF_CRC_NONE, 0, 0, false, 0, 0,
	NULL
};

static int
dissect_fh_lr12_com(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&fh_lr12_com_profile);
}

void
proto_register_fh_lr12_com(void)
{
	proto_fh_lr12_com = proto_register_protocol(
		"FH LR12 串口录波器",
		"FHLR12串口录波器",
		"fh_lr12_com");

	fh_lr12_com_profile.proto = proto_fh_lr12_com;

	fh_lr12_com_handle = register_dissector("fh_lr12_com", dissect_fh_lr12_com, proto_fh_lr12_com);
	vgf_register(&fh_lr12_com_profile);
}

void
proto_reg_handoff_fh_lr12_com(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	/* Registered by name only: the menu forces this dissector onto neutral
	 * serial_raw payloads. */
}
