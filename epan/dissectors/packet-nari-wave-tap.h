/* packet-nari-wave-tap.h
 *
 * Tap payload for NARI network IEC 103 disturbance (录波) export.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_NARI_WAVE_TAP_H
#define PACKET_NARI_WAVE_TAP_H

#include <stdint.h>

#define NARI_WAVE_TAP_NAME       "nari-wave"
#define NARI_WAVE_MAX_SDV        512
#define NARI_WAVE_MAX_TAGS       256

typedef enum {
	NARI_WAVE_TAP_ASDU23 = 23,
	NARI_WAVE_TAP_ASDU26 = 26,
	NARI_WAVE_TAP_ASDU27 = 27,
	NARI_WAVE_TAP_ASDU29 = 29,
	NARI_WAVE_TAP_ASDU30 = 30,
} nari_wave_tap_kind_t;

typedef struct {
	uint16_t tap;
	uint8_t  fun;
	uint8_t  inf;
	uint8_t  dpi;
} nari_wave_tag_t;

typedef struct nari_wave_tap_data {
	nari_wave_tap_kind_t kind;
	uint8_t              asdu_addr;
	uint16_t             fan;
	/* ASDU23 */
	uint8_t              sof;
	uint8_t              cp56time[7];
	/* ASDU26 */
	uint16_t             nof;
	uint8_t              noc;
	uint8_t              ch_info;
	uint8_t              noe;
	uint16_t             int_us;
	/* ASDU27 / ASDU30 */
	uint8_t              acc;
	float                rpv;
	float                rdv;
	float                rfa;
	/* ASDU29 */
	uint8_t              not_count;
	uint16_t             tag_count;
	nari_wave_tag_t      tags[NARI_WAVE_MAX_TAGS];
	/* ASDU30 */
	uint16_t             ndv;
	uint16_t             nfe;
	uint16_t             sdv_count;
	int16_t              sdv[NARI_WAVE_MAX_SDV];
} nari_wave_tap_data_t;

#endif /* PACKET_NARI_WAVE_TAP_H */
