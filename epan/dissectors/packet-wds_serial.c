/* packet-wds_serial.c
 *
 * WDS 录波器串口规约
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/WDS .
 * '1' 'q' 'p' | 地址(BCD 2 位)（Rtu.cpp 的连接请求帧）
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

void proto_register_wds_serial(void);
void proto_reg_handoff_wds_serial(void);

static int proto_wds_serial;
static dissector_handle_t wds_serial_handle;

static const uint8_t wds_serial_sig[3] = { 0x31, 0x71, 0x70 };

static vgf_profile_t wds_serial_profile = {
	0,
	"WDS 录波器串口规约",
	"'1' 'q' 'p' | 地址(BCD 2 位)（Rtu.cpp 的连接请求帧）",
	VGF_CARRIER_SERIAL,
	3, { 0x31, 0x71, 0x70, 0x00, 0x00, 0x00 },
		-1, 1, false, 0, 5, 4096, 0,
	3, 2, -1,
		VGF_CRC_NONE, 0, 0, false, 0, 0,
	NULL
};

static int
dissect_wds_serial(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&wds_serial_profile);
}

void
proto_register_wds_serial(void)
{
	proto_wds_serial = proto_register_protocol(
		"WDS 录波器串口规约",
		"WDS录波器串口",
		"wds_serial");

	wds_serial_profile.proto = proto_wds_serial;

	wds_serial_handle = register_dissector("wds_serial", dissect_wds_serial, proto_wds_serial);
	vgf_register(&wds_serial_profile);
}

void
proto_reg_handoff_wds_serial(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	/* Registered by name only: the menu forces this dissector onto neutral
	 * serial_raw payloads. */
}
