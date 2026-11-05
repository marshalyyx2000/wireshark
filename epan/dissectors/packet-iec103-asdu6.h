/* packet-iec103-asdu6.h
 *
 * Shared 6-byte-header IEC 60870-5-103 ASDU dissection (Nari net 103 style).
 * Used by nari_net_iec103 (raw TCP) and xuji_serial_iec103 (FT1.2 + ASDU).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_IEC103_ASDU6_H
#define PACKET_IEC103_ASDU6_H

#include <epan/packet.h>

/* Optional call_data for dissector "iec103_asdu6". */
typedef struct {
	/* Tree protocol for the ASDU root item; 0 = default (nari). */
	int proto;
	/* Root item text; NULL = "南自网络103 ASDU". */
	const char *asdu_title;
} iec103_asdu6_data_t;

#endif /* PACKET_IEC103_ASDU6_H */
