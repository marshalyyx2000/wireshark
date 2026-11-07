/* packet-iec103-points.h
 *
 * IEC 60870-5-103 vendor point-table lookup (FUN/INF -> point name).
 *
 * Point tables live in <datafile>/iec103/points/<vendor>.csv and are shared by
 * the dissectors and the Python simulators. All rows are optional: if a table
 * is missing the dissector simply shows numeric FUN/INF.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_IEC103_POINTS_H
#define PACKET_IEC103_POINTS_H

#include <stdbool.h>

#include <epan/prefs.h>

typedef enum {
	IEC103_POINTS_SIFANG = 0,
	IEC103_POINTS_SZNARI,
	IEC103_POINTS_NRELECTRIC,
	IEC103_POINTS_NARI,
	IEC103_POINTS_JINZHI,
	IEC103_POINTS_JICHENG,
	IEC103_POINTS_COUNT
} iec103_points_vendor_t;

#define IEC103_POINTS_MAX_NAME 96

/** Load all known point tables. Called from each vendor handoff. */
void iec103_points_init(void);

/**
 * Look up a point name.
 * @param vendor point table to consult
 * @param fun    function type
 * @param inf    information number
 * @return interned name (never freed) or NULL when unknown
 */
const char *iec103_points_lookup(iec103_points_vendor_t vendor, uint8_t fun, uint8_t inf);

/** Number of loaded rows, for diagnostics. */
unsigned iec103_points_rows(iec103_points_vendor_t vendor);

/** Global "show point names" preference (default true). */
extern bool iec103_points_show_names;

void iec103_points_register_prefs(module_t *module, const char *title);

#endif /* PACKET_IEC103_POINTS_H */
