/* packet-toshbia_com_rsm.c
 *
 * 东芝 COM RSM 规约
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/Toshiba_Com_RSM .
 * 组帧由闭源 GrComm 库完成，帧内无可验证的字段布局；只标识帧边界与原始主体
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

void proto_register_toshbia_com_rsm(void);
void proto_reg_handoff_toshbia_com_rsm(void);

static int proto_toshbia_com_rsm;
static dissector_handle_t toshbia_com_rsm_handle;

static const uint8_t toshbia_com_rsm_sig[1] = { 0x00 };

static vgf_profile_t toshbia_com_rsm_profile = {
	0,
	"东芝 COM RSM 规约",
	"组帧由闭源 GrComm 库完成，帧内无可验证的字段布局；只标识帧边界与原始主体",
	VGF_CARRIER_SERIAL,
	0, { 0x00 },
		-1, 1, false, 0, 8, 4096, 0,
	-1, 1, -1,
		VGF_CRC_NONE, 0, 0, false, 0, 0,
	NULL
};

static int
dissect_toshbia_com_rsm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&toshbia_com_rsm_profile);
}

void
proto_register_toshbia_com_rsm(void)
{
	proto_toshbia_com_rsm = proto_register_protocol(
		"东芝 COM RSM 规约",
		"东芝COMRsm",
		"toshbia_com_rsm");

	toshbia_com_rsm_profile.proto = proto_toshbia_com_rsm;

	toshbia_com_rsm_handle = register_dissector("toshbia_com_rsm", dissect_toshbia_com_rsm, proto_toshbia_com_rsm);
	vgf_register(&toshbia_com_rsm_profile);
}

void
proto_reg_handoff_toshbia_com_rsm(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	/* Registered by name only: the menu forces this dissector onto neutral
	 * serial_raw payloads. */
}
