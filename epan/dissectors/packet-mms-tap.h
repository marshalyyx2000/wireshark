/* packet-mms-tap.h
 *
 * Tap payload for IEC 61850 MMS reports.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_MMS_TAP_H
#define PACKET_MMS_TAP_H

#include <stdbool.h>
#include <stdint.h>

#define MMS_RPT_TAP_STR_LEN 256

typedef struct mms_rpt_tap_data {
    char rptid[MMS_RPT_TAP_STR_LEN];
    char datset[MMS_RPT_TAP_STR_LEN];
    uint8_t reason;
    bool has_reason;
} mms_rpt_tap_data;

#endif /* PACKET_MMS_TAP_H */
