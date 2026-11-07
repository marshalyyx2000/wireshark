/* packet-sddffr.c
 *
 * 山东电研院录波器(SDDFR)
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/SDDFR .
 * Frame layout and command table live in packet-iec103-dfr-common.c.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-dfr-common.h"

void proto_register_sddffr(void);
void proto_reg_handoff_sddffr(void);

static int proto_sddffr;
static dissector_handle_t sddffr_handle;

static dfr_vendor_profile_t sddffr_profile = {
	0,
	"山东电研院录波器(SDDFR)",
	"山东电研院录波器",
	NULL,
	NULL,
	false,
	NULL
};

static int
dissect_sddffr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return dfr_dissect_datagram(tvb, pinfo, tree, &sddffr_profile);
}

void
proto_register_sddffr(void)
{
	proto_sddffr = proto_register_protocol(
		"山东电研院录波器(SDDFR)",
		"山东电研院录波器",
		"sddffr");

	sddffr_profile.proto = proto_sddffr;
	sddffr_handle = register_dissector("sddffr", dissect_sddffr,
		proto_sddffr);


	dfr_common_register(&sddffr_profile);
	prefs_register_protocol(proto_sddffr, NULL);
}

void
proto_reg_handoff_sddffr(void)
{
	/* Neutral capture policy: no port binding, the 录波器规约 menu applies
	 * Decode As at runtime. */
	/* Registered by name only: the 录波器规约 serial entry forces this
	 * dissector onto neutral serial_raw payloads. */
}
