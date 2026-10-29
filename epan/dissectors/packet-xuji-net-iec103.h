/* packet-xuji-net-iec103.h
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_XUJI_NET_IEC103_H
#define PACKET_XUJI_NET_IEC103_H

#include <stdbool.h>
#include <epan/tvbuff.h>

#include "packet-iec103-net-apci2404-common.h"

#define XUJI_NET_IEC103_PORT IEC103_NET_APCI2404_PORT
#define XUJI_ASDU_HDR_LEN    IEC103_NET_ASDU_HDR_LEN

bool xuji_net_iec103_asdu_prefers_xuji(tvbuff_t *tvb, int asdu_offset, int asdu_len);

#endif
