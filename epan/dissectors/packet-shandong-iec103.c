/* packet-shandong-iec103.c
 *
 * Shandong / SGCC master-slave IEC 60870-5-103 over TCP.
 * APCI: IEC 104-style (68H + length + 4-byte control), APDU body <= 2048.
 * ASDU: IEC 103 + SGCC extensions (2-byte addr, CP56Time2a, file ASDUs,
 * generic services with KOD<103> attribute structure).
 * Strings: GB18030/GBK preferred for Chinese display.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <time.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/wmem_scopes.h>
#include <wsutil/array.h>
#include <wsutil/str_util.h>

#include "packet-tcp.h"

void proto_register_shandong_iec103(void);
void proto_reg_handoff_shandong_iec103(void);

#define SHANDONG_IEC103_PORT 2404
#define APCI_START           0x68
#define APCI_CTRL_LEN        4
#define APDU_MIN_LEN         4
#define APDU_MAX_BODY        2048
#define FILENAME_LEN         100
/* Disturbance file list (ASDU16) per-entry stride observed on SGCC links */
#define DIST_FILE_ENTRY_LEN  129

#define I_TYPE 0
#define S_TYPE 1
#define U_TYPE 3

#define KOD_VALUE  0x01
#define KOD_DESC   0x0A
#define KOD_ATTR   0x67  /* KOD<103> attribute structure */

#define GDD_OS8ASCII  1
#define GDD_UI        3
#define GDD_R32       7
#define GDD_DPI       9
#define GDD_STRUCT    23

static int proto_shandong_iec103;
static dissector_handle_t shandong_iec103_handle;

static int ett_shandong_iec103;
static int ett_shandong_apci;
static int ett_shandong_asdu;
static int ett_shandong_cp56time;
static int ett_shandong_gen;
static int ett_shandong_gen_entry;
static int ett_shandong_attr;
static int ett_shandong_file;

static int hf_start;
static int hf_apdulen;
static int hf_apdulen_ext;
static int hf_apcitype_i;
static int hf_apcitype_su;
static int hf_apcitx;
static int hf_apcirx;
static int hf_apciutype;
static int hf_junk;
static int hf_typeid;
static int hf_vsq;
static int hf_vsq_sq;
static int hf_vsq_num;
static int hf_cot;
static int hf_asdu_addr;
static int hf_fun;
static int hf_inf;
static int hf_dpi;
static int hf_sin;
static int hf_scn;
static int hf_rii;
static int hf_ngd;
static int hf_ngd_cont;
static int hf_ngd_count;
static int hf_nog;
static int hf_raw;
static int hf_cp56time;
static int hf_cp56time_ms;
static int hf_cp56time_min;
static int hf_cp56time_iv;
static int hf_cp56time_hour;
static int hf_cp56time_su;
static int hf_cp56time_day;
static int hf_cp56time_dow;
static int hf_cp56time_month;
static int hf_cp56time_year;
static int hf_gen_gin_group;
static int hf_gen_gin_entry;
static int hf_gen_kod;
static int hf_gen_datatype;
static int hf_gen_datasize;
static int hf_gen_datanumber;
static int hf_gen_gid;
static int hf_gen_desc;
static int hf_gen_gid_ui;
static int hf_gen_gid_float;
static int hf_endflag;
static int hf_file_num;
static int hf_filename;
static int hf_file_entry;
static int hf_file_offset;
static int hf_file_size;
static int hf_file_data;
static int hf_event_type;
static int hf_fpt;
static int hf_jpt;
static int hf_scl;
static int hf_ret;
static int hf_fan;
static int hf_reclose_dpi;
static int hf_attr_layout;
static int hf_attr_bytes;

static expert_field ei_apdu_min_len;
static expert_field ei_apdu_bad_len;
static expert_field ei_asdu_truncated;

static const value_string apci_types[] = {
	{ I_TYPE, "I" },
	{ S_TYPE, "S" },
	{ U_TYPE, "U" },
	{ 0, NULL }
};

static const value_string u_types[] = {
	{ 0x01, "STARTDT act" },
	{ 0x02, "STARTDT con" },
	{ 0x04, "STOPDT act" },
	{ 0x08, "STOPDT con" },
	{ 0x10, "TESTFR act" },
	{ 0x20, "TESTFR con" },
	{ 0, NULL }
};

static const value_string asdu_type_vals[] = {
	{ 1,   "ASDU1 Time-tagged message" },
	{ 2,   "ASDU2 Time-tagged message with relative time" },
	{ 3,   "ASDU3 Measurands I" },
	{ 4,   "ASDU4 Time-tagged measurands with relative time" },
	{ 5,   "ASDU5 Identification" },
	{ 6,   "ASDU6 Time synchronization" },
	{ 7,   "ASDU7 General interrogation" },
	{ 8,   "ASDU8 Termination of general interrogation" },
	{ 9,   "ASDU9 Measurands II" },
	{ 10,  "ASDU10 Generic data" },
	{ 11,  "ASDU11 Generic identification" },
	{ 12,  "ASDU12 Brief disturbance report (SGCC)" },
	{ 13,  "ASDU13 Call disturbance file (SGCC)" },
	{ 14,  "ASDU14 Disturbance file content (SGCC)" },
	{ 15,  "ASDU15 Call disturbance file list (SGCC)" },
	{ 16,  "ASDU16 Disturbance file list / history call (SGCC)" },
	{ 17,  "ASDU17 Call fault history (SGCC)" },
	{ 18,  "ASDU18 Fault history data (SGCC)" },
	{ 20,  "ASDU20 General command" },
	{ 21,  "ASDU21 Generic command" },
	{ 42,  "ASDU42 DPI status interrogation (SGCC)" },
	{ 101, "ASDU101 Call general file list (SGCC)" },
	{ 102, "ASDU102 General file list (SGCC)" },
	{ 103, "ASDU103 Call general file content (SGCC)" },
	{ 104, "ASDU104 General file content (SGCC)" },
	{ 105, "ASDU105 Fault archive report (SGCC)" },
	{ 0, NULL }
};

static const value_string kod_vals[] = {
	{ 0x01, "Actual value" },
	{ 0x0A, "Description" },
	{ 0x67, "Attribute structure (KOD<103>)" },
	{ 0, NULL }
};

static const value_string endflag_vals[] = {
	{ 0, "Last frame" },
	{ 1, "More frames follow" },
	{ 0, NULL }
};

static const value_string gdd_type_vals[] = {
	{ 1,  "OS8ASCII" },
	{ 2,  "BS1" },
	{ 3,  "UI" },
	{ 4,  "I" },
	{ 5,  "UF" },
	{ 6,  "F" },
	{ 7,  "R32.23" },
	{ 9,  "DPI" },
	{ 10, "SPI" },
	{ 12, "TED" },
	{ 22, "GSE" },
	{ 23, "Data structure" },
	{ 0, NULL }
};

/* APCI: 0x68 + uint16 LE body length + 4-byte control (+ ASDU). */
#define APCI_HDR_LEN 3

/* ---- Chinese / padded string helpers ---- */

static int
trim_nul_len(tvbuff_t *tvb, int offset, int len)
{
	while (len > 0 && tvb_get_uint8(tvb, offset + len - 1) == 0)
		len--;
	return len;
}

static bool
bytes_are_valid_utf8(tvbuff_t *tvb, int offset, int len)
{
	int i = 0;

	while (i < len) {
		uint8_t c = tvb_get_uint8(tvb, offset + i);
		int need, j;

		if (c <= 0x7f) {
			i++;
			continue;
		}
		if ((c & 0xe0) == 0xc0)
			need = 1;
		else if ((c & 0xf0) == 0xe0)
			need = 2;
		else if ((c & 0xf8) == 0xf0)
			need = 3;
		else
			return false;
		if (i + need >= len)
			return false;
		if (c == 0xc0 || c == 0xc1 || c >= 0xf5)
			return false;
		for (j = 1; j <= need; j++) {
			if ((tvb_get_uint8(tvb, offset + i + j) & 0xc0) != 0x80)
				return false;
		}
		i += 1 + need;
	}
	return true;
}

static void
proto_tree_add_zh_string(proto_tree *tree, int hfindex, tvbuff_t *tvb,
	int offset, int len)
{
	int slim = trim_nul_len(tvb, offset, len);
	unsigned encoding = ENC_GB18030;

	if (slim <= 0) {
		proto_tree_add_string(tree, hfindex, tvb, offset, len, "");
		return;
	}
	/*
	 * Field IEDs typically emit GBK/GB18030 for OS8ASCII names.
	 * Modern file payloads may already be UTF-8 — detect and prefer that.
	 */
	if (bytes_are_valid_utf8(tvb, offset, slim))
		encoding = ENC_UTF_8;
	proto_tree_add_item(tree, hfindex, tvb, offset, slim, encoding);
}

static bool
is_plausible_asdu_type(uint8_t typ)
{
	if (typ >= 1 && typ <= 31)
		return true;
	if (typ == 42)
		return true;
	if (typ >= 101 && typ <= 105)
		return true;
	return false;
}

/*
 * Validate APCI at base+off. Shandong/SGCC uses 2-byte little-endian length
 * (unlike stock IEC 104's single length byte). Body length must be 4..2048.
 */
static bool
try_apdu_at(tvbuff_t *tvb, int base, unsigned off, unsigned remaining,
	unsigned *out_body, unsigned *out_total)
{
	uint8_t ctrl0;
	unsigned body;

	if (off + 2 >= remaining && remaining - off < APCI_HDR_LEN)
		return false;
	if (tvb_get_uint8(tvb, base + (int)off) != APCI_START)
		return false;
	if (off + 2 >= remaining) {
		/* Have start but not full length yet — ask for more only if
		 * this is the start of the buffer (reassembly). */
		if (off != 0)
			return false;
		*out_body = APDU_MIN_LEN;
		*out_total = APCI_HDR_LEN + APDU_MIN_LEN;
		return true;
	}

	body = tvb_get_letohs(tvb, base + (int)off + 1);
	if (body < APDU_MIN_LEN || body > APDU_MAX_BODY)
		return false;

	if (off + APCI_HDR_LEN >= remaining) {
		*out_body = body;
		*out_total = off + APCI_HDR_LEN + body;
		return true;
	}

	ctrl0 = tvb_get_uint8(tvb, base + (int)off + APCI_HDR_LEN);
	if ((ctrl0 & 0x01) == 0) {
		/* I-format: require plausible ASDU type when present */
		if (body > APCI_CTRL_LEN
				&& off + APCI_HDR_LEN + APCI_CTRL_LEN < remaining) {
			uint8_t typ = tvb_get_uint8(tvb,
				base + (int)off + APCI_HDR_LEN + APCI_CTRL_LEN);
			if (!is_plausible_asdu_type(typ))
				return false;
		} else if (body == APCI_CTRL_LEN) {
			/* I-format with no ASDU is unusual — reject mid-stream noise */
			return false;
		}
	} else {
		uint8_t t = ctrl0 & 0x03;
		if (t != S_TYPE && t != U_TYPE)
			return false;
		if (body != APCI_CTRL_LEN)
			return false;
	}

	*out_body = body;
	*out_total = off + APCI_HDR_LEN + body;
	return true;
}

static void
dissect_cp56time(tvbuff_t *tvb, int *offset, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *tm_tree;
	nstime_t datetime;
	struct tm tm;
	uint16_t ms;
	uint8_t min, hour, day_dow, month, year;
	int su;

	if (tvb_reported_length_remaining(tvb, *offset) < 7)
		return;

	ms = tvb_get_letohs(tvb, *offset);
	min = tvb_get_uint8(tvb, *offset + 2) & 0x3f;
	hour = tvb_get_uint8(tvb, *offset + 3) & 0x1f;
	su = (tvb_get_uint8(tvb, *offset + 3) & 0x80) ? 1 : 0;
	day_dow = tvb_get_uint8(tvb, *offset + 4);
	month = tvb_get_uint8(tvb, *offset + 5) & 0x0f;
	year = tvb_get_uint8(tvb, *offset + 6) & 0x7f;

	memset(&tm, 0, sizeof(tm));
	tm.tm_sec = ms / 1000;
	tm.tm_min = min;
	tm.tm_hour = hour;
	tm.tm_mday = day_dow & 0x1f;
	tm.tm_mon = month > 0 ? month - 1 : 0;
	tm.tm_year = year;
	if (tm.tm_year < 70)
		tm.tm_year += 100;
	tm.tm_isdst = su ? 1 : -1;

	datetime.secs = mktime(&tm);
	datetime.nsecs = (ms % 1000) * 1000000;

	ti = proto_tree_add_time(tree, hf_cp56time, tvb, *offset, 7, &datetime);
	tm_tree = proto_item_add_subtree(ti, ett_shandong_cp56time);

	proto_tree_add_item(tm_tree, hf_cp56time_ms, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
	*offset += 2;
	proto_tree_add_item(tm_tree, hf_cp56time_min, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tm_tree, hf_cp56time_iv, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
	proto_tree_add_item(tm_tree, hf_cp56time_hour, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tm_tree, hf_cp56time_su, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
	proto_tree_add_item(tm_tree, hf_cp56time_day, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tm_tree, hf_cp56time_dow, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
	proto_tree_add_item(tm_tree, hf_cp56time_month, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
	proto_tree_add_item(tm_tree, hf_cp56time_year, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
}

static void
dissect_filename_field(proto_tree *tree, tvbuff_t *tvb, int *offset, int end, int flen)
{
	int avail = end - *offset;
	int len = flen;

	if (avail <= 0)
		return;
	if (len > avail)
		len = avail;
	proto_tree_add_zh_string(tree, hf_filename, tvb, *offset, len);
	*offset += len;
}

static void
dissect_file_payload(proto_tree *tree, tvbuff_t *tvb, int *offset, int end)
{
	proto_tree *ft;
	proto_item *fi;
	int rem;

	if (*offset >= end)
		return;
	fi = proto_tree_add_item(tree, hf_file_data, tvb, *offset, end - *offset, ENC_NA);
	ft = proto_item_add_subtree(fi, ett_shandong_file);
	if (*offset < end) {
		proto_tree_add_item(ft, hf_rii, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
	}
	if (*offset < end) {
		proto_tree_add_item(ft, hf_endflag, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
	}
	if (end - *offset >= 4) {
		proto_tree_add_item(ft, hf_file_offset, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
		*offset += 4;
	}
	rem = end - *offset;
	if (rem > 0) {
		proto_tree_add_item(ft, hf_file_data, tvb, *offset, rem, ENC_NA);
		*offset = end;
	}
}

/* SGCC A63/A65 group-title feature substrings (UTF-8) → layout label. */
static const char * const attr_feature_labels[][2] = {
	{ "装置", "装置配置" },
	{ "线路", "线路配置" },
	{ "母线", "母线配置" },
	{ "开关", "开关配置" },
	{ "变压器", "变压器配置" },
	{ "主变", "变压器配置" },
	{ "发电机", "发电机配置" },
	{ "电抗器", "电抗器配置" },
	{ "电容器", "电容器配置" },
	{ "刀闸", "刀闸配置" },
	{ "模拟量", "模拟量配置" },
	{ "定值区", "定值区号配置" },
	{ "定值", "定值配置" },
	{ "压板", "状态量/压板配置" },
	{ "状态量", "状态量配置" },
	{ NULL, NULL }
};

static const char *
match_attr_layout_label(packet_info *pinfo, tvbuff_t *tvb, int offset, int len)
{
	char *utf8;
	unsigned encoding;
	int i;
	const char *best = NULL;
	size_t best_flen = 0;

	if (len <= 0 || pinfo == NULL)
		return "未匹配属性结构模板";
	encoding = bytes_are_valid_utf8(tvb, offset, len) ? ENC_UTF_8 : ENC_GB18030;
	utf8 = (char *)tvb_get_string_enc(pinfo->pool, tvb, offset, len, encoding);
	if (!utf8 || !utf8[0])
		return "未匹配属性结构模板";
	for (i = 0; attr_feature_labels[i][0] != NULL; i++) {
		const char *feat = attr_feature_labels[i][0];
		size_t flen = strlen(feat);
		if (flen > best_flen && strstr(utf8, feat) != NULL) {
			best = attr_feature_labels[i][1];
			best_flen = flen;
		}
	}
	return best ? best : "未匹配属性结构模板（按 GDD 流式展开）";
}

/* Attribute structure: feature-string layout label + GDD/GID field walk. */
static void
dissect_kod103_attr(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
	int *offset, int gid_len)
{
	proto_item *ai;
	proto_tree *at;
	int start = *offset;
	int end = *offset + gid_len;
	int pos;
	const char *layout;

	ai = proto_tree_add_bytes_format(tree, hf_attr_bytes, tvb, start, gid_len,
		NULL, "Attribute structure (KOD<103>), %d bytes", gid_len);
	at = proto_item_add_subtree(ai, ett_shandong_attr);

	/* Longest-match feature string against any OS8ASCII runs in the block. */
	layout = match_attr_layout_label(pinfo, tvb, start, gid_len);
	proto_tree_add_string(at, hf_attr_layout, tvb, start, 0, layout);

	pos = start;
	while (pos + 3 <= end) {
		uint8_t maybe_dt = tvb_get_uint8(tvb, pos);
		uint8_t maybe_sz, maybe_n;
		int chunk;

		if (maybe_dt == GDD_UI || maybe_dt == GDD_OS8ASCII
				|| maybe_dt == GDD_R32 || maybe_dt == GDD_DPI
				|| maybe_dt == GDD_STRUCT) {
			maybe_sz = tvb_get_uint8(tvb, pos + 1);
			maybe_n = tvb_get_uint8(tvb, pos + 2);
			chunk = (int)maybe_sz * (int)maybe_n;
			if (chunk > 0 && pos + 3 + chunk <= end && chunk < 512) {
				proto_tree_add_item(at, hf_gen_datatype, tvb, pos, 1, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(at, hf_gen_datasize, tvb, pos + 1, 1, ENC_LITTLE_ENDIAN);
				proto_tree_add_item(at, hf_gen_datanumber, tvb, pos + 2, 1, ENC_LITTLE_ENDIAN);
				pos += 3;
				if (maybe_dt == GDD_OS8ASCII) {
					proto_tree_add_zh_string(at, hf_gen_desc, tvb, pos, chunk);
				} else if (maybe_dt == GDD_UI && maybe_sz <= 4 && maybe_n == 1) {
					proto_tree_add_item(at, hf_gen_gid_ui, tvb, pos, maybe_sz, ENC_LITTLE_ENDIAN);
				} else if (maybe_dt == GDD_R32 && maybe_sz == 4 && maybe_n == 1) {
					proto_tree_add_item(at, hf_gen_gid_float, tvb, pos, 4, ENC_LITTLE_ENDIAN);
				} else {
					proto_tree_add_item(at, hf_gen_gid, tvb, pos, chunk, ENC_NA);
				}
				pos += chunk;
				continue;
			}
		}
		proto_tree_add_item(at, hf_attr_bytes, tvb, pos, end - pos, ENC_NA);
		pos = end;
	}
	*offset = end;
}

static void
dissect_gdd_gid(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
	int *offset, int end, uint8_t kod)
{
	uint8_t datatype, datasize, datanumber;
	int gid_len;

	if (*offset + 3 > end) {
		expert_add_info(pinfo, tree, &ei_asdu_truncated);
		*offset = end;
		return;
	}
	datatype = tvb_get_uint8(tvb, *offset);
	proto_tree_add_item(tree, hf_gen_datatype, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
	datasize = tvb_get_uint8(tvb, *offset);
	proto_tree_add_item(tree, hf_gen_datasize, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
	datanumber = tvb_get_uint8(tvb, *offset);
	proto_tree_add_item(tree, hf_gen_datanumber, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;

	gid_len = (int)datasize * (int)datanumber;
	if (gid_len < 0 || *offset + gid_len > end) {
		expert_add_info(pinfo, tree, &ei_asdu_truncated);
		*offset = end;
		return;
	}
	if (gid_len == 0)
		return;

	if (kod == KOD_ATTR || datatype == GDD_STRUCT) {
		dissect_kod103_attr(tree, pinfo, tvb, offset, gid_len);
		return;
	}
	if (kod == KOD_DESC || datatype == GDD_OS8ASCII) {
		proto_tree_add_zh_string(tree, hf_gen_desc, tvb, *offset, gid_len);
		*offset += gid_len;
		return;
	}
	if (datatype == GDD_UI && datasize == 2 && datanumber == 1) {
		proto_tree_add_item(tree, hf_gen_gid_ui, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
		*offset += 2;
		return;
	}
	if (datatype == GDD_UI && datasize == 1 && datanumber == 1) {
		proto_tree_add_item(tree, hf_gen_gid_ui, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
		return;
	}
	if (datatype == GDD_R32 && datasize == 4 && datanumber == 1) {
		proto_tree_add_item(tree, hf_gen_gid_float, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
		*offset += 4;
		return;
	}
	proto_tree_add_item(tree, hf_gen_gid, tvb, *offset, gid_len, ENC_NA);
	*offset += gid_len;
}

static void
dissect_generic_elements(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	int *offset, int end, bool is_command)
{
	unsigned nds;
	unsigned i;
	uint8_t ngd;

	if (*offset >= end)
		return;

	proto_tree_add_item(tree, hf_rii, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
	if (*offset >= end)
		return;

	if (is_command) {
		/* ASDU21: NOG then GIN+KOD repeats */
		nds = tvb_get_uint8(tvb, *offset);
		proto_tree_add_item(tree, hf_nog, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
		for (i = 0; i < nds && *offset + 3 <= end; i++) {
			proto_item *gi;
			proto_tree *gt;
			uint8_t kod;

			gi = proto_tree_add_none_format(tree, hf_raw, tvb, *offset, 3,
				"Generic command element %u", i + 1);
			gt = proto_item_add_subtree(gi, ett_shandong_gen_entry);
			proto_tree_add_item(gt, hf_gen_gin_group, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
			(*offset)++;
			proto_tree_add_item(gt, hf_gen_gin_entry, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
			(*offset)++;
			kod = tvb_get_uint8(tvb, *offset);
			proto_tree_add_item(gt, hf_gen_kod, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
			(*offset)++;
			proto_item_set_end(gi, tvb, *offset);
			(void)kod;
		}
		return;
	}

	ngd = tvb_get_uint8(tvb, *offset);
	nds = ngd & 0x3f;
	proto_tree_add_item(tree, hf_ngd, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ngd_cont, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_ngd_count, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;

	for (i = 0; i < nds && *offset + 3 <= end; i++) {
		proto_item *gi;
		proto_tree *gt;
		uint8_t kod;
		int start = *offset;

		gi = proto_tree_add_none_format(tree, hf_raw, tvb, *offset, -1,
			"Generic data set %u", i + 1);
		gt = proto_item_add_subtree(gi, ett_shandong_gen_entry);

		proto_tree_add_item(gt, hf_gen_gin_group, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
		proto_tree_add_item(gt, hf_gen_gin_entry, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
		kod = tvb_get_uint8(tvb, *offset);
		proto_tree_add_item(gt, hf_gen_kod, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;

		dissect_gdd_gid(gt, pinfo, tvb, offset, end, kod);
		proto_item_set_len(gi, *offset - start);
	}
}

static void
dissect_asdu12(proto_tree *tree, tvbuff_t *tvb, int *offset, int end)
{
	if (*offset < end) {
		proto_tree_add_item(tree, hf_fpt, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
	}
	if (*offset < end) {
		proto_tree_add_item(tree, hf_jpt, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
	}
	if (end - *offset >= 4) {
		proto_tree_add_item(tree, hf_scl, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
		*offset += 4;
	}
	if (*offset < end) {
		proto_tree_add_item(tree, hf_reclose_dpi, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
	}
	if (end - *offset >= 2) {
		proto_tree_add_item(tree, hf_raw, tvb, *offset, 2, ENC_NA); /* reclose ms */
		*offset += 2;
	}
	if (end - *offset >= 7)
		dissect_cp56time(tvb, offset, tree);
	if (*offset < end)
		dissect_filename_field(tree, tvb, offset, end, end - *offset);
}

static void
dissect_asdu_file_list(proto_tree *tree, tvbuff_t *tvb, int *offset, int end,
	bool disturbance_list)
{
	unsigned nfiles, i;
	uint16_t n_le;
	int entry_len;

	if (*offset >= end)
		return;
	proto_tree_add_item(tree, hf_rii, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
	if (*offset >= end)
		return;
	proto_tree_add_item(tree, hf_endflag, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
	if (end - *offset < 2)
		return;
	n_le = tvb_get_letohs(tvb, *offset);
	proto_tree_add_item(tree, hf_file_num, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
	*offset += 2;
	nfiles = n_le;
	/* ASDU16 echoes query time window before entries */
	if (disturbance_list) {
		if (end - *offset >= 7)
			dissect_cp56time(tvb, offset, tree);
		if (end - *offset >= 7)
			dissect_cp56time(tvb, offset, tree);
		entry_len = DIST_FILE_ENTRY_LEN;
	} else {
		entry_len = FILENAME_LEN + 7 + 4; /* name + CP56 + size */
	}
	for (i = 0; i < nfiles && *offset < end; i++) {
		proto_item *fi;
		proto_tree *ft;
		int start = *offset;
		int avail = end - *offset;
		int name_len;

		fi = proto_tree_add_none_format(tree, hf_file_entry, tvb, *offset, -1,
			"File entry %u", i + 1);
		ft = proto_item_add_subtree(fi, ett_shandong_file);
		if (disturbance_list) {
			name_len = (avail >= entry_len) ? entry_len : avail;
			dissect_filename_field(ft, tvb, offset, end, name_len);
		} else {
			dissect_filename_field(ft, tvb, offset, end, FILENAME_LEN);
			if (end - *offset >= 7)
				dissect_cp56time(tvb, offset, ft);
			if (end - *offset >= 4) {
				proto_tree_add_item(ft, hf_file_size, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
				*offset += 4;
			}
		}
		proto_item_set_len(fi, *offset - start);
	}
}

static void
dissect_asdu_call_file_list(proto_tree *tree, tvbuff_t *tvb, int *offset, int end)
{
	if (*offset >= end)
		return;
	proto_tree_add_item(tree, hf_rii, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
	if (end - *offset >= 7)
		dissect_cp56time(tvb, offset, tree);
	if (end - *offset >= 7)
		dissect_cp56time(tvb, offset, tree);
	if (*offset < end)
		dissect_filename_field(tree, tvb, offset, end, FILENAME_LEN);
}

static void
dissect_asdu_call_file_content(proto_tree *tree, tvbuff_t *tvb, int *offset, int end)
{
	if (*offset >= end)
		return;
	proto_tree_add_item(tree, hf_rii, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
	dissect_filename_field(tree, tvb, offset, end, FILENAME_LEN);
	if (end - *offset >= 4) {
		proto_tree_add_item(tree, hf_file_offset, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
		*offset += 4;
	}
}

static void
dissect_asdu105(proto_tree *tree, tvbuff_t *tvb, int *offset, int end)
{
	uint8_t nfiles, i;

	if (*offset >= end)
		return;
	nfiles = tvb_get_uint8(tvb, *offset);
	proto_tree_add_item(tree, hf_file_num, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
	for (i = 0; i < nfiles && *offset < end; i++)
		dissect_filename_field(tree, tvb, offset, end, FILENAME_LEN);
	if (end - *offset >= 7)
		dissect_cp56time(tvb, offset, tree);
}

static void
dissect_asdu17(proto_tree *tree, tvbuff_t *tvb, int *offset, int end)
{
	if (*offset < end) {
		proto_tree_add_item(tree, hf_event_type, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
	}
	if (end - *offset >= 7)
		dissect_cp56time(tvb, offset, tree);
	if (end - *offset >= 7)
		dissect_cp56time(tvb, offset, tree);
}

static void
dissect_asdu18(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int *offset, int end)
{
	if (*offset < end) {
		proto_tree_add_item(tree, hf_endflag, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
	}
	if (end - *offset >= 7)
		dissect_cp56time(tvb, offset, tree);
	if (end - *offset >= 7)
		dissect_cp56time(tvb, offset, tree);
	/* Remaining history blocks: treat as generic GDD/GID stream */
	while (*offset + 6 <= end) {
		int before = *offset;
		dissect_gdd_gid(tree, pinfo, tvb, offset, end, KOD_VALUE);
		if (*offset <= before)
			break;
	}
}

static void
dissect_asdu42(proto_tree *tree, tvbuff_t *tvb, int *offset, int end, uint8_t num)
{
	unsigned i;
	unsigned n = num ? num : (unsigned)(end - *offset);

	for (i = 0; i < n && *offset < end; i++) {
		proto_tree_add_item(tree, hf_dpi, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
	}
}

static void
dissect_asdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *asdu_item;
	proto_tree *asdu_tree;
	int offset = 0;
	int end = (int)tvb_reported_length(tvb);
	uint8_t typ, cot, fun, inf, vsq_num;

	if (end < 8) {
		if (end > 0)
			proto_tree_add_item(tree, hf_raw, tvb, 0, end, ENC_NA);
		return;
	}

	asdu_item = proto_tree_add_item(tree, proto_shandong_iec103, tvb, 0, end, ENC_NA);
	proto_item_set_text(asdu_item, "山东主子站103 ASDU");
	asdu_tree = proto_item_add_subtree(asdu_item, ett_shandong_asdu);

	typ = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(asdu_tree, hf_typeid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s",
		val_to_str_const(typ, asdu_type_vals, "ASDU%u"));
	offset++;

	vsq_num = tvb_get_uint8(tvb, offset) & 0x7f;
	proto_tree_add_item(asdu_tree, hf_vsq, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(asdu_tree, hf_vsq_sq, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(asdu_tree, hf_vsq_num, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;

	cot = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(asdu_tree, hf_cot, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	col_append_fstr(pinfo->cinfo, COL_INFO, " COT=%u", cot);
	offset++;

	proto_tree_add_item(asdu_tree, hf_asdu_addr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	fun = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(asdu_tree, hf_fun, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;
	inf = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(asdu_tree, hf_inf, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;

	switch (typ) {
	case 1:
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_dpi, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (end - offset >= 7)
			dissect_cp56time(tvb, &offset, asdu_tree);
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_sin, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		break;
	case 2:
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_dpi, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_ret, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (end - offset >= 7)
			dissect_cp56time(tvb, &offset, asdu_tree);
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_sin, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		break;
	case 4:
		if (end - offset >= 4) {
			proto_tree_add_item(asdu_tree, hf_scl, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_ret, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (end - offset >= 7)
			dissect_cp56time(tvb, &offset, asdu_tree);
		break;
	case 6:
		if (end - offset >= 7)
			dissect_cp56time(tvb, &offset, asdu_tree);
		break;
	case 7:
	case 8:
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_scn, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		break;
	case 10:
	case 11:
		dissect_generic_elements(tvb, pinfo, asdu_tree, &offset, end, false);
		break;
	case 12:
		dissect_asdu12(asdu_tree, tvb, &offset, end);
		break;
	case 13:
		/* Call disturbance file: filename (INF selects local/simplified/device) */
		if (offset < end)
			dissect_filename_field(asdu_tree, tvb, &offset, end, end - offset);
		break;
	case 14:
		dissect_file_payload(asdu_tree, tvb, &offset, end);
		break;
	case 15:
		dissect_asdu_call_file_list(asdu_tree, tvb, &offset, end);
		break;
	case 16:
		/* COT 0x14 => history call (ASDU17 TYP overlap in some excerpts) */
		if ((cot & 0x3f) == 0x14) {
			dissect_asdu17(asdu_tree, tvb, &offset, end);
		} else {
			dissect_asdu_file_list(asdu_tree, tvb, &offset, end, true);
		}
		break;
	case 17:
		dissect_asdu17(asdu_tree, tvb, &offset, end);
		break;
	case 18:
		dissect_asdu18(asdu_tree, pinfo, tvb, &offset, end);
		break;
	case 21:
		dissect_generic_elements(tvb, pinfo, asdu_tree, &offset, end, true);
		break;
	case 42:
		dissect_asdu42(asdu_tree, tvb, &offset, end, vsq_num);
		break;
	case 101:
		dissect_asdu_call_file_list(asdu_tree, tvb, &offset, end);
		break;
	case 102:
		dissect_asdu_file_list(asdu_tree, tvb, &offset, end, false);
		break;
	case 103:
		dissect_asdu_call_file_content(asdu_tree, tvb, &offset, end);
		break;
	case 104:
		dissect_file_payload(asdu_tree, tvb, &offset, end);
		break;
	case 105:
		dissect_asdu105(asdu_tree, tvb, &offset, end);
		break;
	default:
		break;
	}

	if (offset < end)
		proto_tree_add_item(asdu_tree, hf_raw, tvb, offset, end - offset, ENC_NA);

	(void)inf;
}

static unsigned
get_shandong_apdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	unsigned remaining = tvb_reported_length_remaining(tvb, offset);
	unsigned off, body, total;

	if (remaining < APCI_HDR_LEN)
		return remaining;

	for (off = 0; off + 2 < remaining; off++) {
		if (tvb_get_uint8(tvb, offset + (int)off) != APCI_START)
			continue;
		if (try_apdu_at(tvb, offset, off, remaining, &body, &total))
			return total;
		/* Reject bogus mid-payload 0x68; keep scanning. */
	}
	return remaining;
}

static int
dissect_shandong_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *ti;
	proto_tree *apci_tree;
	int tcp_len = (int)tvb_reported_length(tvb);
	unsigned off, body = 0, total = 0;
	bool found = false;
	uint8_t type, temp8;
	uint32_t txid, rxid, utype;
	wmem_strbuf_t *res;
	int offset;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "山东主子站103");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_shandong_iec103, tvb, 0, -1, ENC_NA);
	apci_tree = proto_item_add_subtree(ti, ett_shandong_apci);

	for (off = 0; (int)off + 2 < tcp_len; off++) {
		if (try_apdu_at(tvb, 0, off, (unsigned)tcp_len, &body, &total)) {
			found = true;
			break;
		}
	}
	if (!found) {
		proto_tree_add_item(apci_tree, hf_raw, tvb, 0, tcp_len, ENC_NA);
		col_set_str(pinfo->cinfo, COL_INFO, "TCP continuation / no valid APCI");
		return tvb_captured_length(tvb);
	}

	if (off > 0)
		proto_tree_add_item(apci_tree, hf_junk, tvb, 0, (int)off, ENC_NA);

	offset = (int)off;
	proto_tree_add_uint_format(apci_tree, hf_start, tvb, offset, 1, APCI_START, "START");
	offset++;
	proto_tree_add_item(apci_tree, hf_apdulen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	if (body < APDU_MIN_LEN || body > APDU_MAX_BODY) {
		expert_add_info_format(pinfo, ti, &ei_apdu_bad_len,
			"Invalid APDU body length %u (allowed %d..%d)",
			body, APDU_MIN_LEN, APDU_MAX_BODY);
		return tvb_captured_length(tvb);
	}

	proto_item_set_len(ti, (int)total);

	temp8 = tvb_get_uint8(tvb, offset);
	if ((temp8 & 0x01) == 0)
		type = I_TYPE;
	else
		type = temp8 & 0x03;

	res = wmem_strbuf_create(pinfo->pool);
	wmem_strbuf_append_printf(res, "%s %s ",
		(pinfo->srcport == pinfo->match_uint ? "->" : "<-"),
		val_to_str_const(type, apci_types, "?"));

	if (type == I_TYPE)
		proto_tree_add_item(apci_tree, hf_apcitype_i, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	else
		proto_tree_add_item(apci_tree, hf_apcitype_su, tvb, offset, 4, ENC_LITTLE_ENDIAN);

	switch (type) {
	case I_TYPE:
		proto_tree_add_item_ret_uint(apci_tree, hf_apcitx, tvb, offset, 4, ENC_LITTLE_ENDIAN, &txid);
		proto_tree_add_item_ret_uint(apci_tree, hf_apcirx, tvb, offset, 4, ENC_LITTLE_ENDIAN, &rxid);
		wmem_strbuf_append_printf(res, "(%u,%u)", txid, rxid);
		break;
	case S_TYPE:
		proto_tree_add_item_ret_uint(apci_tree, hf_apcirx, tvb, offset, 4, ENC_LITTLE_ENDIAN, &rxid);
		wmem_strbuf_append_printf(res, "(%u)", rxid);
		break;
	case U_TYPE:
		proto_tree_add_item_ret_uint(apci_tree, hf_apciutype, tvb, offset, 4, ENC_LITTLE_ENDIAN, &utype);
		wmem_strbuf_append_printf(res, "(%s)", val_to_str_const(utype, u_types, "?"));
		break;
	}

	col_append_str(pinfo->cinfo, COL_INFO, wmem_strbuf_get_str(res));
	proto_item_append_text(ti, ": %s", wmem_strbuf_get_str(res));
	offset += APCI_CTRL_LEN;

	if (type == I_TYPE && body > APCI_CTRL_LEN) {
		int asdu_len = (int)body - APCI_CTRL_LEN;
		if (offset + asdu_len <= tcp_len) {
			tvbuff_t *asdu_tvb = tvb_new_subset_length(tvb, offset, asdu_len);
			dissect_asdu(asdu_tvb, pinfo, tree);
		}
	}

	return tvb_captured_length(tvb);
}

static int
dissect_shandong_iec103_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	unsigned remaining = tvb_reported_length(tvb);
	unsigned off, body, total;
	bool found = false;

	if (remaining < APCI_HDR_LEN)
		return 0;

	for (off = 0; off + 2 < remaining; off++) {
		if (try_apdu_at(tvb, 0, off, remaining, &body, &total)) {
			found = true;
			break;
		}
	}
	if (!found)
		return 0;

	tcp_dissect_pdus(tvb, pinfo, tree, true, APCI_HDR_LEN + APCI_CTRL_LEN,
		get_shandong_apdu_len, dissect_shandong_apdu, data);
	return tvb_captured_length(tvb);
}

void
proto_register_shandong_iec103(void)
{
	static hf_register_info hf[] = {
		{ &hf_start,
		  { "Start", "shandong_iec103.start", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_apdulen,
		  { "ApduLen", "shandong_iec103.apdulen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_apdulen_ext,
		  { "ApduLen (legacy alias)", "shandong_iec103.apdulen_ext", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_file_entry,
		  { "File entry", "shandong_iec103.file_entry", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_apcitype_i,
		  { "Type", "shandong_iec103.type", FT_UINT32, BASE_HEX, VALS(apci_types), 0x00000001, NULL, HFILL }},
		{ &hf_apcitype_su,
		  { "Type", "shandong_iec103.type", FT_UINT32, BASE_HEX, VALS(apci_types), 0x00000003, NULL, HFILL }},
		{ &hf_apcitx,
		  { "Tx", "shandong_iec103.tx", FT_UINT32, BASE_DEC, NULL, 0x0000FFFE, NULL, HFILL }},
		{ &hf_apcirx,
		  { "Rx", "shandong_iec103.rx", FT_UINT32, BASE_DEC, NULL, 0xFFFE0000, NULL, HFILL }},
		{ &hf_apciutype,
		  { "UType", "shandong_iec103.utype", FT_UINT32, BASE_HEX, VALS(u_types), 0x000000FC, NULL, HFILL }},
		{ &hf_junk,
		  { "Leading junk", "shandong_iec103.junk", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_typeid,
		  { "Type ID", "shandong_iec103.typeid", FT_UINT8, BASE_DEC, VALS(asdu_type_vals), 0x0, NULL, HFILL }},
		{ &hf_vsq,
		  { "VSQ", "shandong_iec103.vsq", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_vsq_sq,
		  { "SQ", "shandong_iec103.vsq.sq", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
		{ &hf_vsq_num,
		  { "Number of objects", "shandong_iec103.vsq.num", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }},
		{ &hf_cot,
		  { "Cause of transmission", "shandong_iec103.cot", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_asdu_addr,
		  { "ASDU address", "shandong_iec103.asdu_addr", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_fun,
		  { "Function type", "shandong_iec103.fun", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_inf,
		  { "Information number", "shandong_iec103.inf", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_dpi,
		  { "DPI", "shandong_iec103.dpi", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sin,
		  { "SIN", "shandong_iec103.sin", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_scn,
		  { "Scan number", "shandong_iec103.scn", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_rii,
		  { "RII", "shandong_iec103.rii", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_ngd,
		  { "NGD", "shandong_iec103.ngd", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_ngd_cont,
		  { "NGD CONT", "shandong_iec103.ngd.cont", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
		{ &hf_ngd_count,
		  { "NGD count", "shandong_iec103.ngd.count", FT_UINT8, BASE_DEC, NULL, 0x3F, NULL, HFILL }},
		{ &hf_nog,
		  { "NOG", "shandong_iec103.nog", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_raw,
		  { "Data", "shandong_iec103.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_cp56time,
		  { "CP56Time2a", "shandong_iec103.cp56time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }},
		{ &hf_cp56time_ms,
		  { "Milliseconds", "shandong_iec103.cp56time.ms", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_cp56time_min,
		  { "Minutes", "shandong_iec103.cp56time.min", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL }},
		{ &hf_cp56time_iv,
		  { "Invalid", "shandong_iec103.cp56time.iv", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
		{ &hf_cp56time_hour,
		  { "Hours", "shandong_iec103.cp56time.hour", FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL }},
		{ &hf_cp56time_su,
		  { "Summer time", "shandong_iec103.cp56time.su", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
		{ &hf_cp56time_day,
		  { "Day", "shandong_iec103.cp56time.day", FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL }},
		{ &hf_cp56time_dow,
		  { "Day of week", "shandong_iec103.cp56time.dow", FT_UINT8, BASE_DEC, NULL, 0xe0, NULL, HFILL }},
		{ &hf_cp56time_month,
		  { "Month", "shandong_iec103.cp56time.month", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_cp56time_year,
		  { "Year", "shandong_iec103.cp56time.year", FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL }},
		{ &hf_gen_gin_group,
		  { "GIN group", "shandong_iec103.gen.group", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_gin_entry,
		  { "GIN entry", "shandong_iec103.gen.entry", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_kod,
		  { "KOD", "shandong_iec103.gen.kod", FT_UINT8, BASE_HEX, VALS(kod_vals), 0x0, NULL, HFILL }},
		{ &hf_gen_datatype,
		  { "Data type", "shandong_iec103.gen.datatype", FT_UINT8, BASE_DEC, VALS(gdd_type_vals), 0x0, NULL, HFILL }},
		{ &hf_gen_datasize,
		  { "Data size", "shandong_iec103.gen.datasize", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_datanumber,
		  { "Data number", "shandong_iec103.gen.datanumber", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_gid,
		  { "GID", "shandong_iec103.gen.gid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_desc,
		  { "Description", "shandong_iec103.gen.desc", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_gid_ui,
		  { "GID UI", "shandong_iec103.gen.gid_ui", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_gid_float,
		  { "GID R32.23", "shandong_iec103.gen.gid_float", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_endflag,
		  { "ENDFLAG", "shandong_iec103.endflag", FT_UINT8, BASE_DEC, VALS(endflag_vals), 0x0, NULL, HFILL }},
		{ &hf_file_num,
		  { "File count", "shandong_iec103.file_num", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_filename,
		  { "File name", "shandong_iec103.filename", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_file_offset,
		  { "Transfer offset", "shandong_iec103.file_offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_file_size,
		  { "File size", "shandong_iec103.file_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_file_data,
		  { "File data", "shandong_iec103.file_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_event_type,
		  { "Event type", "shandong_iec103.event_type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_fpt,
		  { "Fault phase/type (FPT)", "shandong_iec103.fpt", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_jpt,
		  { "Trip phase (JPT)", "shandong_iec103.jpt", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_scl,
		  { "Fault distance (SCL)", "shandong_iec103.scl", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_ret,
		  { "Relative time (RET)", "shandong_iec103.ret", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_fan,
		  { "Fault number (FAN)", "shandong_iec103.fan", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_reclose_dpi,
		  { "Reclose DPI", "shandong_iec103.reclose_dpi", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_attr_layout,
		  { "Attribute layout", "shandong_iec103.attr.layout", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_attr_bytes,
		  { "Attribute bytes", "shandong_iec103.attr.bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	};

	static int *ett[] = {
		&ett_shandong_iec103,
		&ett_shandong_apci,
		&ett_shandong_asdu,
		&ett_shandong_cp56time,
		&ett_shandong_gen,
		&ett_shandong_gen_entry,
		&ett_shandong_attr,
		&ett_shandong_file,
	};

	static ei_register_info ei[] = {
		{ &ei_apdu_min_len,
		  { "shandong_iec103.apdu_min_len", PI_MALFORMED, PI_ERROR,
		    "APDU too short", EXPFILL }},
		{ &ei_apdu_bad_len,
		  { "shandong_iec103.apdu_bad_len", PI_MALFORMED, PI_ERROR,
		    "APDU length out of range", EXPFILL }},
		{ &ei_asdu_truncated,
		  { "shandong_iec103.asdu_truncated", PI_MALFORMED, PI_WARN,
		    "ASDU truncated", EXPFILL }},
	};

	expert_module_t *expert_mod;

	proto_shandong_iec103 = proto_register_protocol(
		"山东主子站103规约",
		"山东主子站103",
		"shandong_iec103");

	proto_register_field_array(proto_shandong_iec103, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_mod = expert_register_protocol(proto_shandong_iec103);
	expert_register_field_array(expert_mod, ei, array_length(ei));

	prefs_register_protocol(proto_shandong_iec103, NULL);

	shandong_iec103_handle = register_dissector("shandong_iec103",
		dissect_shandong_iec103_tcp, proto_shandong_iec103);
}

void
proto_reg_handoff_shandong_iec103(void)
{
	dissector_add_uint_with_preference("tcp.port", SHANDONG_IEC103_PORT, shandong_iec103_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=true:
 */
