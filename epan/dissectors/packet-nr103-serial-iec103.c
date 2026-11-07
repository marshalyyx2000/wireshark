/* packet-nr103-serial-iec103.c
 *
 * 南瑞（NR103 / NR103_RCS9691）串口 IEC 60870-5-103 (FT1.2).
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/NR103 与 NR103_RCS9691 的
 * Rtu.cpp：固定帧 10H|C|A|CS|16H，可变帧 68H|L|L|68H|C|A|ASDU|CS|16H，
 * 校验为控制域+地址(+ASDU) 的 8 位累加和；ASDU 头 6 字节。
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-vendor-common.h"

void proto_register_nr103_serial_iec103(void);
void proto_reg_handoff_nr103_serial_iec103(void);

static int proto_nr103_serial_iec103;

static iec103_vendor_profile_t nr103_serial_profile = {
	0,
	"南瑞串口103(NR103)",
	"单字符 E5",
	"南瑞串口103(NR103)",
	IEC103_POINTS_NARI,
	NULL,
	NULL,
	NULL
};

static int
dissect_nr103_serial_iec103(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return iec103_vendor_dissect_ft12(tvb, pinfo, tree, &nr103_serial_profile);
}

void
proto_register_nr103_serial_iec103(void)
{
	proto_nr103_serial_iec103 = proto_register_protocol(
		"南瑞串口103(NR103)",
		"南瑞串口103(NR103)",
		"nr103_serial_iec103");

	nr103_serial_profile.proto = proto_nr103_serial_iec103;

	register_dissector("nr103_serial_iec103", dissect_nr103_serial_iec103,
			   proto_nr103_serial_iec103);

	iec103_vendor_register(&nr103_serial_profile);
	iec103_vendor_register_prefs(
		prefs_register_protocol(proto_nr103_serial_iec103, NULL),
		"南瑞串口103(NR103)");
}

void
proto_reg_handoff_nr103_serial_iec103(void)
{
	iec103_points_init();
}
