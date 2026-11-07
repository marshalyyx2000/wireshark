/* packet-wxb11_serial.c
 *
 * WXB11 串口规约
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/WXB11 .
 * 与 WXB 同构（CWxb.cpp / Rtu.cpp）
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

void proto_register_wxb11_serial(void);
void proto_reg_handoff_wxb11_serial(void);

static int proto_wxb11_serial;
static dissector_handle_t wxb11_serial_handle;

static const uint8_t wxb11_serial_sig[1] = { 0x00 };

static vgf_profile_t wxb11_serial_profile = {
	0,
	"WXB11 串口规约",
	"与 WXB 同构（CWxb.cpp / Rtu.cpp）",
	VGF_CARRIER_SERIAL,
	0, { 0x00 },
		-1, 1, false, 0, 6, 4096, 0,
	0, 1, 1,
		VGF_CRC_MODBUS16, 2, 0, false, 0, 0,
	NULL
};

static int
dissect_wxb11_serial(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&wxb11_serial_profile);
}

void
proto_register_wxb11_serial(void)
{
	proto_wxb11_serial = proto_register_protocol(
		"WXB11 串口规约",
		"WXB11串口",
		"wxb11_serial");

	wxb11_serial_profile.proto = proto_wxb11_serial;

	wxb11_serial_handle = register_dissector("wxb11_serial", dissect_wxb11_serial, proto_wxb11_serial);
	vgf_register(&wxb11_serial_profile);
}

void
proto_reg_handoff_wxb11_serial(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	/* Registered by name only: the menu forces this dissector onto neutral
	 * serial_raw payloads. */
}
