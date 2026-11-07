/* packet-iec103-vendor-common.h
 *
 * Shared IEC 60870-5-103 engine for vendor variants (四方 / 深圳南瑞 / 南瑞 / 南自).
 *
 * One profile description drives three transports:
 *   - FT1.2 serial framing (10H / 68H / E5H), used by *serial* protocols
 *   - raw ASDU stream over TCP (no APCI), used by vendor *net* protocols
 *   - one ASDU per UDP datagram
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_IEC103_VENDOR_COMMON_H
#define PACKET_IEC103_VENDOR_COMMON_H

#include <stdbool.h>
#include <stdint.h>

#include <epan/packet.h>

#include "packet-iec103-points.h"

#define IEC103_FT12_VAR    0x68
#define IEC103_FT12_FIXED  0x10
#define IEC103_FT12_SINGLE 0xE5
#define IEC103_FT12_STOP   0x16
#define IEC103_ASDU_HDR_LEN 6

typedef struct iec103_vendor_profile iec103_vendor_profile_t;

/** One vendor profile. Fill statically, then call register. */
struct iec103_vendor_profile {
	int proto;                          /* populated by the vendor module */
	const char *col_protocol;           /* COL_PROTOCOL text */
	const char *single_char_info;       /* COL_INFO for a bare 0xE5 */
	const char *unknown_asdu_prefix;    /* expert text prefix */
	iec103_points_vendor_t points_vendor;
	/* Optional vendor-specific TYP / COT names, tried after the standard
	 * tables so existing behaviour is unchanged when both are NULL. */
	const struct _value_string *extra_asdu_types;
	const struct _value_string *extra_cot;
	/* Optional body decoder for vendor-specific TYP values. Return true when
	 * the body was consumed; *offset is advanced past the decoded bytes. */
	bool (*dissect_extra_asdu)(tvbuff_t *tvb, int *offset, int end,
				   packet_info *pinfo, proto_tree *tree,
				   const iec103_vendor_profile_t *profile);
};

/**
 * Dissect one ASDU occupying [offset, offset+len) of @p tvb.
 *
 * Exported for vendors that implement their own APCI (Jinzhi 2-byte length /
 * 12-13 byte control field, Jicheng 4-byte control field). The caller is
 * responsible for having validated that the range holds one ASDU.
 */
void iec103_vendor_dissect_one_asdu(tvbuff_t *tvb, int offset, int len,
				    packet_info *pinfo, proto_tree *tree,
				    const iec103_vendor_profile_t *profile);

/** Register every field/subtree/expert for one vendor profile. */
void iec103_vendor_register(const iec103_vendor_profile_t *profile);

/** FT1.2 record dissection (serial). Returns bytes consumed, 0 if not FT1.2. */
int iec103_vendor_dissect_ft12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
			       const iec103_vendor_profile_t *profile);

/**
 * Raw ASDU TCP stream dissection: splits the stream into ASDU PDUs using the
 * ASDU header/length rules and dissects each one.
 */
int iec103_vendor_dissect_asdu_stream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
				      const iec103_vendor_profile_t *profile);

/** One ASDU per UDP datagram. Returns bytes consumed, 0 if not an ASDU. */
int iec103_vendor_dissect_asdu_datagram(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
					const iec103_vendor_profile_t *profile);

/** True when the payload plausibly starts with a known ASDU type. */
bool iec103_vendor_looks_like_asdu(tvbuff_t *tvb, int offset, int remaining);

/** Same as above, also accepting the profile's vendor-specific TYP list. */
bool iec103_vendor_looks_like_asdu_ext(tvbuff_t *tvb, int offset, int remaining,
				       const iec103_vendor_profile_t *profile);

/** Register the shared "show point names" preference on a vendor module. */
void iec103_vendor_register_prefs(module_t *module, const char *title);

/** Number of loaded point-table rows for a vendor (diagnostics). */
unsigned iec103_vendor_point_rows(iec103_points_vendor_t vendor);

#endif /* PACKET_IEC103_VENDOR_COMMON_H */
