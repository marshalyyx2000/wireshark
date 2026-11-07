/* packet-nr_lfp_com.c
 *
 * 南瑞 LFP 串口规约
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/NR_LFP_COM .
 * EB 90 EB 90 | 0x02 | 地址 | 命令（Com.cpp）
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

void proto_register_nr_lfp_com(void);
void proto_reg_handoff_nr_lfp_com(void);

static int proto_nr_lfp_com;
static dissector_handle_t nr_lfp_com_handle;

static const uint8_t nr_lfp_com_sig[4] = { 0xEB, 0x90, 0xEB, 0x90 };

static vgf_profile_t nr_lfp_com_profile = {
	0,
	"南瑞 LFP 串口规约",
	"EB 90 EB 90 | 0x02 | 地址 | 命令（Com.cpp）",
	VGF_CARRIER_SERIAL,
	4, { 0xEB, 0x90, 0xEB, 0x90, 0x00, 0x00 },
		-1, 1, false, 0, 8, 4096, 0,
	5, 1, 6,
		VGF_CRC_NONE, 0, 0, false, 0, 0,
	NULL
};

static int
dissect_nr_lfp_com(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&nr_lfp_com_profile);
}

void
proto_register_nr_lfp_com(void)
{
	proto_nr_lfp_com = proto_register_protocol(
		"南瑞 LFP 串口规约",
		"南瑞LFP串口",
		"nr_lfp_com");

	nr_lfp_com_profile.proto = proto_nr_lfp_com;

	nr_lfp_com_handle = register_dissector("nr_lfp_com", dissect_nr_lfp_com, proto_nr_lfp_com);
	vgf_register(&nr_lfp_com_profile);
}

void
proto_reg_handoff_nr_lfp_com(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	/* Registered by name only: the menu forces this dissector onto neutral
	 * serial_raw payloads. */
}
