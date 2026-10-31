/* packet-mms-tap.h
 *
 * Tap payload for IEC 61850 MMS station-layer process analysis
 * (reports, confirmed read/write request and response).
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

#include <wsutil/nstime.h>

#define MMS_RPT_TAP_STR_LEN 256
#define MMS_PROCESS_VALUES_LEN 512
#define MMS_PROCESS_ARROW_LABEL_LEN 96
#define MMS_PROCESS_RESULT_ZH_LEN 32

typedef enum {
    MMS_PROCESS_KIND_REPORT_PDU = 0,
    /* Deprecated: was misused for GetRCB/SetRCB requests; kept for ABI stability. */
    MMS_PROCESS_KIND_REPORT_SERVICE = 1,
    MMS_PROCESS_KIND_REQUEST = 2,
    MMS_PROCESS_KIND_RESPONSE = 3
} mms_process_kind_t;

typedef struct mms_process_tap_data {
    uint32_t framenum;
    nstime_t rel_ts;
    char src[46];
    char dst[46];
    mms_process_kind_t kind;
    char arrow_label[MMS_PROCESS_ARROW_LABEL_LEN];
    /* Report: RCB / dataset ref. Request: object reference (last path). */
    char rcb_ref[MMS_RPT_TAP_STR_LEN];
    char reason_zh[64];
    /* Comma-separated leaf values for spontaneous (data-change) reports. */
    char values[MMS_PROCESS_VALUES_LEN];
    uint32_t invoke_id;
    bool has_invoke_id;
    char object_ref[MMS_RPT_TAP_STR_LEN];
    char result_zh[MMS_PROCESS_RESULT_ZH_LEN];
} mms_process_tap_data;

typedef struct mms_rpt_tap_data {
    char rptid[MMS_RPT_TAP_STR_LEN];
    char datset[MMS_RPT_TAP_STR_LEN];
    uint8_t reason;
    bool has_reason;
} mms_rpt_tap_data;

#endif /* PACKET_MMS_TAP_H */
