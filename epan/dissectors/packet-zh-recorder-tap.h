/* packet-zh-recorder-tap.h
 *
 * Tap payload for 武汉中元华电 ZH 系列录波器 file transfer (multi-packet
 * reassembly in the GUI exporter).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_ZH_RECORDER_TAP_H
#define PACKET_ZH_RECORDER_TAP_H

#include <stdbool.h>
#include <stdint.h>

#define ZH_RECORDER_TAP_NAME  "zh-recorder"
#define ZH_RECORDER_NAME_LEN  256

typedef enum {
	/* PTYPE_FILE_INFO / PTYPE_FILE_PUT: starts (or describes) one file. */
	ZH_RECORDER_TAP_FILE_BEGIN = 0,
	/* PTYPE_FILE_DATA: one chunk of the file started above. */
	ZH_RECORDER_TAP_FILE_DATA  = 1,
} zh_recorder_tap_kind_t;

typedef struct zh_recorder_tap_data {
	zh_recorder_tap_kind_t kind;
	uint32_t framenum;
	char     name[ZH_RECORDER_NAME_LEN];  /* NUL-terminated, basename kept as sent */
	uint32_t total_size;                  /* FILE_INFO.size, 0 when unknown */
	uint32_t offset;                      /* FILE_INFO.offset (chunk start) */
	uint32_t length;                      /* bytes carried by this record */
	const uint8_t *data;                  /* chunk bytes; UI must copy */
} zh_recorder_tap_data_t;

#endif /* PACKET_ZH_RECORDER_TAP_H */
