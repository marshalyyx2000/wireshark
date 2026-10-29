/* packet-iec103-net-apci2404-common.h
 *
 * IEC 60870-5-103 over TCP port 2404 (104-style APCI + 8-byte ASDU header).
 * Shared by 许继 / 深圳南瑞 network variants.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_IEC103_NET_APCI2404_COMMON_H
#define PACKET_IEC103_NET_APCI2404_COMMON_H

#include <stdbool.h>
#include <epan/packet.h>
#include <epan/prefs.h>

#define IEC103_NET_APCI2404_PORT 2404
#define IEC103_NET_ASDU_HDR_LEN  8

typedef enum {
	IEC103_APCI2404_VENDOR_XUJI = 0,
	IEC103_APCI2404_VENDOR_SZNARI = 1,
} iec103_apci2404_vendor_t;

typedef struct {
	int      proto;
	const char *col_protocol;
	const char *tree_root_label;
	const char *apdu_invalid_info;

	int *ett_root;
	int ett_apci;
	int ett_apci_ctrl;
	int ett_asdu;
	int ett_cp56;
	int ett_sof;
	int ett_gen;
	int ett_gen_entry;

	int hf_start;
	int hf_apdulen;
	int hf_apci_ctrl;
	int hf_apci_type;
	int hf_apci_tx;
	int hf_apci_rx;
	int hf_u_type;
	int hf_typeid;
	int hf_vsq;
	int hf_vsq_sq;
	int hf_vsq_num;
	int hf_cot;
	int hf_cot_hi;
	int hf_comaddr_unit;
	int hf_comaddr_dev;
	int hf_fun;
	int hf_inf;
	int hf_dpi;
	int hf_spi;
	int hf_sof;
	int hf_sof_tp;
	int hf_sof_tm;
	int hf_sof_test;
	int hf_sof_otev;
	int hf_fan;
	int hf_too;
	int hf_tov;
	int hf_acc;
	int hf_ndv;
	int hf_nfe;
	int hf_rpv;
	int hf_rdv;
	int hf_rfa;
	int hf_gen_group;
	int hf_gen_entry;
	int hf_gen_kod;
	int hf_rii;
	int hf_ngd;
	int hf_ngd_cont;
	int hf_ngd_count;
	int hf_nog;
	int hf_gen_datatype;
	int hf_gen_datasize;
	int hf_gen_datanumber;
	int hf_gen_gid;
	int hf_run;
	int hf_scn;
	int hf_raw;
	int hf_cp56time;
	int hf_cp56time_ms;
	int hf_cp56time_min;
	int hf_cp56time_iv;
	int hf_cp56time_hour;
	int hf_cp56time_su;
	int hf_cp56time_day;
	int hf_cp56time_dow;
	int hf_cp56time_month;
	int hf_cp56time_year;
} iec103_apci2404_regs_t;

bool iec103_net_apci2404_asdu_prefers_vendor(tvbuff_t *tvb, int asdu_offset, int asdu_len);

void iec103_net_apci2404_register_vendor(iec103_apci2404_vendor_t vendor,
	const iec103_apci2404_regs_t *regs);

extern int iec103_apci2404_pref_vendor;

iec103_apci2404_vendor_t iec103_net_apci2404_get_display_vendor(void);

void iec103_net_apci2404_register_prefs(module_t *mod);

void proto_register_iec103_net_apci2404_common(void);
void proto_reg_handoff_iec103_net_apci2404_common(void);

#endif
