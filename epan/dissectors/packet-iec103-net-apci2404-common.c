/* packet-iec103-net-apci2404-common.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>
#include <time.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/tfs.h>
#include <epan/wmem_scopes.h>
#include <wsutil/array.h>

#include "packet-tcp.h"
#include "packet-iec103-net-apci2404-common.h"

#define APCI_START     0x68
#define APCI_HDR_LEN   3
#define APCI_CTRL_LEN  4
#define APDU_MIN_LEN   4
#define APDU_MAX_BODY  2048

#define I_TYPE 0
#define S_TYPE 1
#define U_TYPE 3

#define KOD_VALUE  0x01
#define GDD_UI     3
#define GDD_R32    7
#define GDD_DPI    9

static const iec103_apci2404_regs_t *vendor_regs[2];
int iec103_apci2404_pref_vendor = 1;

static dissector_handle_t apci2404_tcp_handle;
static expert_field ei_apdu_bad_len;

static const enum_val_t vendor_pref_vals[] = {
	{ "xuji",   "许继", 0 },
	{ "sznari", "深圳南瑞", 1 },
	{ NULL, NULL, 0 }
};

bool
iec103_net_apci2404_asdu_prefers_vendor(tvbuff_t *tvb, int asdu_offset, int asdu_len)
{
	uint8_t cot_hi, fun6;

	if (asdu_len < IEC103_NET_ASDU_HDR_LEN)
		return false;
	cot_hi = tvb_get_uint8(tvb, asdu_offset + 3);
	if (cot_hi != 0)
		return false;
	fun6 = tvb_get_uint8(tvb, asdu_offset + 6);
	return (fun6 == 254 || fun6 == 255);
}

void
iec103_net_apci2404_register_vendor(iec103_apci2404_vendor_t vendor,
	const iec103_apci2404_regs_t *regs)
{
	if (vendor >= 0 && vendor < 2)
		vendor_regs[vendor] = regs;
}

void
iec103_net_apci2404_register_prefs(module_t *mod)
{
	prefs_register_enum_preference(mod, "apci2404_vendor",
		"2404 APCI vendor display",
		"Which protocol name and filter fields to use for TCP port 2404 APCI 103 frames",
		&iec103_apci2404_pref_vendor, vendor_pref_vals, false);
}

iec103_apci2404_vendor_t
iec103_net_apci2404_get_display_vendor(void)
{
	if (iec103_apci2404_pref_vendor == 0)
		return IEC103_APCI2404_VENDOR_XUJI;
	return IEC103_APCI2404_VENDOR_SZNARI;
}

static const iec103_apci2404_regs_t *
active_regs(void)
{
	const iec103_apci2404_regs_t *r = vendor_regs[iec103_net_apci2404_get_display_vendor()];
	if (r)
		return r;
	return vendor_regs[IEC103_APCI2404_VENDOR_XUJI];
}

static bool
is_plausible_asdu_type(uint8_t typ)
{
	if (typ >= 1 && typ <= 44)
		return true;
	if (typ >= 50 && typ <= 88)
		return true;
	return false;
}

static bool
try_apdu_at(tvbuff_t *tvb, int base, unsigned off, unsigned remaining,
	unsigned *out_body, unsigned *out_total)
{
	uint8_t ctrl0;
	unsigned body;

	if (off + APCI_HDR_LEN > remaining)
		return false;
	if (tvb_get_uint8(tvb, base + (int)off) != APCI_START)
		return false;
	if (off + 2 >= remaining)
		return false;

	body = tvb_get_letohs(tvb, base + (int)off + 1);
	if (body < APDU_MIN_LEN || body > APDU_MAX_BODY)
		return false;

	if (off + APCI_HDR_LEN + APCI_CTRL_LEN <= remaining) {
		ctrl0 = tvb_get_uint8(tvb, base + (int)off + APCI_HDR_LEN);
		if ((ctrl0 & 0x01) == 0 && body > APCI_CTRL_LEN) {
			unsigned asdu_off = base + off + APCI_HDR_LEN + APCI_CTRL_LEN;
			if (asdu_off < (unsigned)tvb_reported_length(tvb)) {
				uint8_t typ = tvb_get_uint8(tvb, asdu_off);
				if (!is_plausible_asdu_type(typ))
					return false;
				if (!iec103_net_apci2404_asdu_prefers_vendor(tvb, (int)asdu_off,
						(int)tvb_reported_length(tvb) - (int)asdu_off))
					return false;
			}
		}
	}

	*out_body = body;
	*out_total = off + APCI_HDR_LEN + body;
	return true;
}

static const value_string u_type_vals[] = {
	{ 0x07, "STARTDT act" },
	{ 0x0B, "STARTDT con" },
	{ 0x13, "STOPDT act" },
	{ 0x23, "STOPDT con" },
	{ 0x43, "TESTFR act" },
	{ 0x83, "TESTFR con" },
	{ 0, NULL }
};

static const value_string too_vals[] = {
	{ 1,  "选择故障" },
	{ 2,  "请求扰动数据" },
	{ 3,  "终止扰动数据" },
	{ 8,  "认可扰动数据" },
	{ 9,  "请求通道数据" },
	{ 16, "请求状态量" },
	{ 17, "终止状态量" },
	{ 24, "请求扰动表" },
	{ 0, NULL }
};

static const value_string dpi_vals[] = {
	{ 0, "不确定" },
	{ 1, "分" },
	{ 2, "合" },
	{ 3, "无效" },
	{ 0, NULL }
};

static void
dissect_cp56time(tvbuff_t *tvb, int *offset, proto_tree *tree,
	const iec103_apci2404_regs_t *R)
{
	proto_item *ti;
	proto_tree *tm_tree;
	nstime_t datetime;
	struct tm tm;
	uint16_t ms;
	uint8_t min, hour, day_dow, month, year;

	if (tvb_reported_length_remaining(tvb, *offset) < 7)
		return;

	ms = tvb_get_letohs(tvb, *offset);
	min = tvb_get_uint8(tvb, *offset + 2) & 0x3f;
	hour = tvb_get_uint8(tvb, *offset + 3) & 0x1f;
	day_dow = tvb_get_uint8(tvb, *offset + 4);
	month = tvb_get_uint8(tvb, *offset + 5) & 0x0f;
	year = tvb_get_uint8(tvb, *offset + 6) & 0x7f;

	memset(&tm, 0, sizeof(tm));
	tm.tm_sec = ms / 1000;
	tm.tm_min = min;
	tm.tm_hour = hour;
	tm.tm_mday = day_dow & 0x1f;
	tm.tm_mon = month - 1;
	tm.tm_year = year + 100;
	datetime.secs = mktime(&tm);
	datetime.nsecs = (ms % 1000) * 1000000;

	ti = proto_tree_add_time(tree, R->hf_cp56time, tvb, *offset, 7, &datetime);
	tm_tree = proto_item_add_subtree(ti, R->ett_cp56);
	proto_tree_add_uint(tm_tree, R->hf_cp56time_ms, tvb, *offset, 2, ms);
	proto_tree_add_uint(tm_tree, R->hf_cp56time_min, tvb, *offset + 2, 1, min);
	proto_tree_add_item(tm_tree, R->hf_cp56time_iv, tvb, *offset + 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_uint(tm_tree, R->hf_cp56time_hour, tvb, *offset + 3, 1, hour);
	proto_tree_add_item(tm_tree, R->hf_cp56time_su, tvb, *offset + 3, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_uint(tm_tree, R->hf_cp56time_day, tvb, *offset + 4, 1, day_dow & 0x1f);
	proto_tree_add_uint(tm_tree, R->hf_cp56time_dow, tvb, *offset + 4, 1, (day_dow >> 5) & 0x07);
	proto_tree_add_uint(tm_tree, R->hf_cp56time_month, tvb, *offset + 5, 1, month);
	proto_tree_add_uint(tm_tree, R->hf_cp56time_year, tvb, *offset + 6, 1, year);
	*offset += 7;
}

static void
dissect_sof(proto_tree *tree, tvbuff_t *tvb, int offset, const iec103_apci2404_regs_t *R)
{
	proto_item *pi = proto_tree_add_item(tree, R->hf_sof, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree *st = proto_item_add_subtree(pi, R->ett_sof);
	proto_tree_add_item(st, R->hf_sof_tp, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(st, R->hf_sof_tm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(st, R->hf_sof_test, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(st, R->hf_sof_otev, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

static void
dissect_gdd_gid(proto_tree *tree, tvbuff_t *tvb, int *offset, int end,
	const iec103_apci2404_regs_t *R)
{
	uint8_t datatype, datasize, datanumber;
	int gid_len;

	if (*offset + 3 > end)
		return;
	datatype = tvb_get_uint8(tvb, *offset);
	datasize = tvb_get_uint8(tvb, *offset + 1);
	datanumber = tvb_get_uint8(tvb, *offset + 2);
	proto_tree_add_item(tree, R->hf_gen_datatype, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
	proto_tree_add_item(tree, R->hf_gen_datasize, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
	proto_tree_add_item(tree, R->hf_gen_datanumber, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;

	gid_len = (int)datasize * (int)datanumber;
	if (gid_len <= 0 || *offset + gid_len > end) {
		gid_len = end - *offset;
		if (gid_len <= 0)
			return;
	}

	if (datatype == GDD_UI && gid_len >= 1) {
		proto_tree_add_item(tree, R->hf_gen_gid, tvb, *offset, gid_len, ENC_LITTLE_ENDIAN);
	} else if (datatype == GDD_R32 && gid_len >= 4) {
		proto_tree_add_item(tree, R->hf_gen_gid, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
		if (gid_len > 4)
			proto_tree_add_item(tree, R->hf_raw, tvb, *offset + 4, gid_len - 4, ENC_NA);
	} else if (datatype == GDD_DPI && gid_len >= 1) {
		proto_tree_add_item(tree, R->hf_dpi, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		if (gid_len > 1)
			proto_tree_add_item(tree, R->hf_raw, tvb, *offset + 1, gid_len - 1, ENC_NA);
	} else {
		proto_tree_add_item(tree, R->hf_gen_gid, tvb, *offset, gid_len, ENC_NA);
	}
	*offset += gid_len;
}

static void
dissect_generic_elements(tvbuff_t *tvb, proto_tree *tree, int *offset, int end,
	bool is_command, const iec103_apci2404_regs_t *R)
{
	unsigned nds, i;

	if (*offset >= end)
		return;

	proto_tree_add_item(tree, R->hf_rii, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
	if (*offset >= end)
		return;

	if (is_command) {
		nds = tvb_get_uint8(tvb, *offset);
		proto_tree_add_item(tree, R->hf_nog, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
		for (i = 0; i < nds && *offset + 3 <= end; i++) {
			proto_item *gi;
			proto_tree *gt;

			gi = proto_tree_add_item(tree, R->hf_gen_entry, tvb, *offset, 3, ENC_NA);
			gt = proto_item_add_subtree(gi, R->ett_gen_entry);
			proto_tree_add_item(gt, R->hf_gen_group, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
			(*offset)++;
			proto_tree_add_item(gt, R->hf_gen_entry, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
			(*offset)++;
			proto_tree_add_item(gt, R->hf_gen_kod, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
			(*offset)++;
		}
		return;
	}

	nds = tvb_get_uint8(tvb, *offset) & 0x3f;
	proto_tree_add_item(tree, R->hf_ngd, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, R->hf_ngd_cont, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, R->hf_ngd_count, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;

	for (i = 0; i < nds && *offset + 3 <= end; i++) {
		proto_item *gi;
		proto_tree *gt;
		int start = *offset;

		gi = proto_tree_add_none_format(tree, R->hf_gen_entry, tvb, *offset, -1,
			"通用分类数据元素 %u", i + 1);
		gt = proto_item_add_subtree(gi, R->ett_gen_entry);
		proto_tree_add_item(gt, R->hf_gen_group, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
		proto_tree_add_item(gt, R->hf_gen_entry, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
		proto_tree_add_item(gt, R->hf_gen_kod, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
		dissect_gdd_gid(gt, tvb, offset, end, R);
		proto_item_set_len(gi, *offset - start);
	}
}

static void
dissect_asdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	const iec103_apci2404_regs_t *R)
{
	proto_item *asdu_item;
	proto_tree *asdu_tree;
	int offset = 0;
	int end = (int)tvb_reported_length(tvb);
	uint8_t typ, vsq, fun;
	uint16_t cot;

	if (end < IEC103_NET_ASDU_HDR_LEN)
		return;

	asdu_item = proto_tree_add_item(tree, R->proto, tvb, 0, end, ENC_NA);
	proto_item_set_text(asdu_item, "ASDU");
	asdu_tree = proto_item_add_subtree(asdu_item, R->ett_asdu);

	typ = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(asdu_tree, R->hf_typeid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "ASDU%u", typ);
	offset++;

	proto_tree_add_item(asdu_tree, R->hf_vsq, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(asdu_tree, R->hf_vsq_sq, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(asdu_tree, R->hf_vsq_num, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	vsq = tvb_get_uint8(tvb, offset);
	offset++;

	cot = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(asdu_tree, R->hf_cot, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(asdu_tree, R->hf_cot_hi, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
	col_append_fstr(pinfo->cinfo, COL_INFO, " COT=%u", cot);
	offset += 2;

	proto_tree_add_item(asdu_tree, R->hf_comaddr_unit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;
	proto_tree_add_item(asdu_tree, R->hf_comaddr_dev, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;

	fun = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(asdu_tree, R->hf_fun, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;
	proto_tree_add_item(asdu_tree, R->hf_inf, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;

	switch (typ) {
	case 5:
		if (offset < end)
			proto_tree_add_item(asdu_tree, R->hf_run, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset++;
		if (end - offset >= 7)
			dissect_cp56time(tvb, &offset, asdu_tree, R);
		break;
	case 6:
		if (offset < end)
			proto_tree_add_item(asdu_tree, R->hf_run, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		break;
	case 7:
		if (offset < end)
			proto_tree_add_item(asdu_tree, R->hf_scn, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		break;
	case 1:
		if (offset < end) {
			proto_tree_add_item(asdu_tree, R->hf_dpi, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (end - offset >= 7)
			dissect_cp56time(tvb, &offset, asdu_tree, R);
		break;
	case 40:
		if (offset < end)
			proto_tree_add_item(asdu_tree, R->hf_spi, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		break;
	case 42:
		if (offset < end)
			proto_tree_add_item(asdu_tree, R->hf_dpi, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		break;
	case 23:
		while (offset + 10 <= end) {
			proto_tree_add_item(asdu_tree, R->hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
			dissect_sof(asdu_tree, tvb, offset, R);
			offset++;
			if (end - offset >= 7)
				dissect_cp56time(tvb, &offset, asdu_tree, R);
		}
		break;
	case 24:
	case 25:
	case 31:
		if (offset + 5 <= end) {
			proto_tree_add_item(asdu_tree, R->hf_too, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(asdu_tree, R->hf_tov, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(asdu_tree, R->hf_fan, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(asdu_tree, R->hf_acc, tvb, offset + 4, 1, ENC_LITTLE_ENDIAN);
			offset += 5;
		}
		break;
	case 26:
		if (offset + 16 <= end) {
			offset += 2;
			proto_tree_add_item(asdu_tree, R->hf_tov, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
			proto_tree_add_item(asdu_tree, R->hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
			proto_tree_add_item(asdu_tree, R->hf_acc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
			proto_tree_add_item(asdu_tree, R->hf_ndv, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 10;
		}
		break;
	case 27:
		if (offset + 18 <= end) {
			offset += 3;
			proto_tree_add_item(asdu_tree, R->hf_acc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
			proto_tree_add_item(asdu_tree, R->hf_rpv, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(asdu_tree, R->hf_rdv, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(asdu_tree, R->hf_rfa, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
		}
		break;
	case 28:
		if (offset + 2 <= end) {
			proto_tree_add_item(asdu_tree, R->hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		break;
	case 29:
		if (offset + 3 <= end) {
			proto_tree_add_item(asdu_tree, R->hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 3;
			while (offset + 5 <= end) {
				offset += 2;
				proto_tree_add_item(asdu_tree, R->hf_fun, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset++;
				proto_tree_add_item(asdu_tree, R->hf_inf, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset++;
				proto_tree_add_item(asdu_tree, R->hf_dpi, tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset++;
			}
		}
		break;
	case 30: {
		uint8_t ndv;
		unsigned i;

		if (offset + 10 > end)
			break;
		offset += 3;
		proto_tree_add_item(asdu_tree, R->hf_acc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset++;
		ndv = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(asdu_tree, R->hf_ndv, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset++;
		proto_tree_add_item(asdu_tree, R->hf_nfe, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		for (i = 0; i < ndv && offset + 2 <= end; i++) {
			proto_tree_add_none_format(asdu_tree, R->hf_raw, tvb, offset, 2,
				"SDV %u: %d", i + 1, (int)tvb_get_letohs(tvb, offset));
			offset += 2;
		}
		break;
	}
	case 10:
		dissect_generic_elements(tvb, asdu_tree, &offset, end, false, R);
		break;
	case 21:
		dissect_generic_elements(tvb, asdu_tree, &offset, end, true, R);
		break;
	default:
		break;
	}

	if (offset < end)
		proto_tree_add_item(asdu_tree, R->hf_raw, tvb, offset, end - offset, ENC_NA);

	(void)vsq;
	(void)fun;
}

static void
dissect_apci_ctrl(tvbuff_t *tvb, int offset, proto_tree *apci_tree,
	const iec103_apci2404_regs_t *R)
{
	uint8_t b0, b1, b2, b3;
	proto_item *ci;
	proto_tree *ct;

	b0 = tvb_get_uint8(tvb, offset);
	b1 = tvb_get_uint8(tvb, offset + 1);
	b2 = tvb_get_uint8(tvb, offset + 2);
	b3 = tvb_get_uint8(tvb, offset + 3);

	ci = proto_tree_add_item(apci_tree, R->hf_apci_ctrl, tvb, offset, 4, ENC_NA);
	ct = proto_item_add_subtree(ci, R->ett_apci_ctrl);

	if ((b0 & 0x03) == U_TYPE) {
		uint8_t ut = b0 & 0xfc;
		proto_tree_add_uint(ct, R->hf_u_type, tvb, offset, 1, ut);
	} else if ((b0 & 0x01) == 0) {
		uint16_t tx = (uint16_t)((b0 >> 1) | (b1 << 7));
		uint16_t rx = (uint16_t)((b2 >> 1) | (b3 << 7));
		proto_tree_add_uint(ct, R->hf_apci_tx, tvb, offset, 2, tx);
		proto_tree_add_uint(ct, R->hf_apci_rx, tvb, offset + 2, 2, rx);
	} else {
		uint16_t rx = (uint16_t)((b0 >> 1) | (b1 << 7));
		proto_tree_add_uint(ct, R->hf_apci_rx, tvb, offset, 2, rx);
	}
}

static int
dissect_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	const iec103_apci2404_regs_t *R = active_regs();
	proto_item *ti;
	proto_tree *apci_tree;
	unsigned off, body, total;
	bool found = false;
	int tcp_len = (int)tvb_reported_length(tvb);
	uint8_t ctrl0;
	int offset;

	if (!R)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, R->col_protocol);
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, R->proto, tvb, 0, -1, ENC_NA);
	proto_item_set_text(ti, R->tree_root_label);
	apci_tree = proto_item_add_subtree(ti, R->ett_apci);

	for (off = 0; (int)off + 2 < tcp_len; off++) {
		if (try_apdu_at(tvb, 0, off, (unsigned)tcp_len, &body, &total)) {
			found = true;
			break;
		}
	}
	if (!found) {
		proto_tree_add_item(apci_tree, R->hf_raw, tvb, 0, tcp_len, ENC_NA);
		col_set_str(pinfo->cinfo, COL_INFO, R->apdu_invalid_info);
		return tvb_captured_length(tvb);
	}

	offset = (int)off;
	proto_tree_add_uint_format_value(apci_tree, R->hf_start, tvb, offset, 1, APCI_START, "0x68");
	offset++;
	proto_tree_add_item(apci_tree, R->hf_apdulen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	ctrl0 = tvb_get_uint8(tvb, offset);
	dissect_apci_ctrl(tvb, offset, apci_tree, R);
	offset += 4;

	if ((ctrl0 & 0x01) == 0 && body > APCI_CTRL_LEN) {
		int asdu_len = (int)body - APCI_CTRL_LEN;
		if (offset + asdu_len <= tcp_len) {
			tvbuff_t *asdu_tvb = tvb_new_subset_length(tvb, offset, asdu_len);
			dissect_asdu(asdu_tvb, pinfo, tree, R);
		}
	}

	proto_item_set_len(ti, (int)total);
	return (int)total;
}

static unsigned
get_apdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	unsigned remaining = tvb_reported_length_remaining(tvb, offset);
	unsigned off, body, total;

	for (off = 0; off + APCI_HDR_LEN < remaining; off++) {
		if (try_apdu_at(tvb, offset, off, remaining, &body, &total))
			return total;
	}
	return remaining;
}

static int
dissect_apci2404_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	unsigned remaining = tvb_reported_length(tvb);

	if (remaining < APCI_HDR_LEN)
		return 0;

	tcp_dissect_pdus(tvb, pinfo, tree, true, APCI_HDR_LEN + APCI_CTRL_LEN,
		get_apdu_len, dissect_apdu, data);
	return tvb_captured_length(tvb);
}

void
proto_register_iec103_net_apci2404_common(void)
{
}

void
proto_reg_handoff_iec103_net_apci2404_common(void)
{
	static bool handoff_done;
	const iec103_apci2404_regs_t *R;

	if (handoff_done)
		return;
	R = active_regs();
	if (!R)
		return;

	apci2404_tcp_handle = create_dissector_handle(dissect_apci2404_tcp, R->proto);
	dissector_add_uint_with_preference("tcp.port", IEC103_NET_APCI2404_PORT, apci2404_tcp_handle);
	handoff_done = true;
}
