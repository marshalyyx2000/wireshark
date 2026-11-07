/* packet-ascii_meter_serial.c
 *
 * ASCII 电表规约
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/ASCII .
 * ASCII 文本命令，以 CR 结尾（Rtu.cpp 的 'METER' 等命令字）
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

void proto_register_ascii_meter_serial(void);
void proto_reg_handoff_ascii_meter_serial(void);

static int proto_ascii_meter_serial;
static dissector_handle_t ascii_meter_serial_handle;

static const uint8_t ascii_meter_serial_sig[1] = { 0x00 };

static vgf_profile_t ascii_meter_serial_profile = {
	0,
	"ASCII 电表规约",
	"ASCII 文本命令，以 CR 结尾（Rtu.cpp 的 'METER' 等命令字）",
	VGF_CARRIER_SERIAL,
	0, { 0x00 },
		-1, 1, false, 0, 6, 512, 0,
	-1, 1, -1,
		VGF_CRC_NONE, 0, 0, true, 0, 0,
	NULL
};

static int
dissect_ascii_meter_serial(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return vgf_dissect(tvb, pinfo, tree, (void *)&ascii_meter_serial_profile);
}

void
proto_register_ascii_meter_serial(void)
{
	proto_ascii_meter_serial = proto_register_protocol(
		"ASCII 电表规约",
		"ASCII电表",
		"ascii_meter_serial");

	ascii_meter_serial_profile.proto = proto_ascii_meter_serial;

	ascii_meter_serial_handle = register_dissector("ascii_meter_serial", dissect_ascii_meter_serial, proto_ascii_meter_serial);
	vgf_register(&ascii_meter_serial_profile);
}

void
proto_reg_handoff_ascii_meter_serial(void)
{
	/* Neutral capture policy: no port binding, the vendor menu applies Decode As. */
	/* Registered by name only: the menu forces this dissector onto neutral
	 * serial_raw payloads. */
}
