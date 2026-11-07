/* packet-keli_103_tcp.c
 *
 * 开利网络103 FT1.2 帧承载于 TCP
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/KELI_103_TCP .
 * Framing and ASDU layout reuse packet-iec103-vendor-common.c; this file only
 * supplies the vendor identity and its extra TYP/COT names.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-vendor-common.h"

void proto_register_keli_103_tcp(void);
void proto_reg_handoff_keli_103_tcp(void);

static int proto_keli_103_tcp;
static dissector_handle_t keli_103_tcp_handle;

static iec103_vendor_profile_t keli_103_tcp_profile = {
	0,
	"开利网络103",
	NULL,
	"开利网络103",
	IEC103_POINTS_SIFANG,
	NULL,
	NULL,
	NULL
};

static int
dissect_keli_103_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return iec103_vendor_dissect_asdu_stream(tvb, pinfo, tree, &keli_103_tcp_profile);
}

void
proto_register_keli_103_tcp(void)
{
	proto_keli_103_tcp = proto_register_protocol(
		"开利网络103",
		"开利网络103",
		"keli_103_tcp");

	keli_103_tcp_profile.proto = proto_keli_103_tcp;

	keli_103_tcp_handle = register_dissector("keli_103_tcp", dissect_keli_103_tcp,
		proto_keli_103_tcp);

	iec103_vendor_register(&keli_103_tcp_profile);
	iec103_vendor_register_prefs(prefs_register_protocol(proto_keli_103_tcp, NULL),
		"开利网络103");
}

void
proto_reg_handoff_keli_103_tcp(void)
{
	/* Neutral capture policy: no port binding. The 网络103 menu applies
	 * Decode As for this vendor's documented port. */
	 dissector_add_for_decode_as("tcp.port", keli_103_tcp_handle);
	iec103_points_init();
}
