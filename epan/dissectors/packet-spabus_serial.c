/* packet-spabus_serial.c
 *
 * SpaBus 串口规约
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/SpaBus .
 * 文本命令，'>' + 地址 + 'R' + 命令（Rtu.cpp 的 FormatAddr/FormatCommand）
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

void proto_register_spabus_serial(void);
void proto_reg_handoff_spabus_serial(void);

static int proto_spabus_serial;
static dissector_handle_t spabus_serial_handle;

static const uint8_t spabus_serial_sig[1] = { 0x3E };

static vgf_profile_t spabus_serial_profile = {
	0,
	"SpaBus 串口规约",
	"文本命令，'>' + 地址 + 'R' + 命令（Rtu.cpp 的 FormatAddr/FormatCommand）",
	VGF_CARRIER_SERIAL,
	1, { 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00 },
		-1, 1, false, 0, 6, 4096, 0,
	1, 1, -1,
		VGF_CRC_NONE, 0, 0, false, 0, 0,
	NULL
};

static int
dissect_spabus_serial(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&spabus_serial_profile);
}

void
proto_register_spabus_serial(void)
{
	proto_spabus_serial = proto_register_protocol(
		"SpaBus 串口规约",
		"SpaBus串口",
		"spabus_serial");

	spabus_serial_profile.proto = proto_spabus_serial;

	spabus_serial_handle = register_dissector("spabus_serial", dissect_spabus_serial, proto_spabus_serial);
	vgf_register(&spabus_serial_profile);
}

void
proto_reg_handoff_spabus_serial(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	/* Registered by name only: the menu forces this dissector onto neutral
	 * serial_raw payloads. */
}
