/* packet-sznari-net-iec103.h
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_SZNARI_NET_IEC103_H
#define PACKET_SZNARI_NET_IEC103_H

#define SZNARI_NET_IEC103_PORT 2404

void proto_register_sznari_net_iec103(void);
void proto_reg_handoff_sznari_net_iec103(void);

#endif
