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
#include <epan/tfs.h>
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
static int ett_shandong_apci_len;
static int ett_shandong_apci_ctrl;
static int ett_shandong_apci_ctrl_b1;
static int ett_shandong_apci_ctrl_b2;
static int ett_shandong_apci_ctrl_b3;
static int ett_shandong_apci_ctrl_b4;
static int ett_shandong_asdu;
static int ett_shandong_cp56time;
static int ett_shandong_gen;
static int ett_shandong_gen_entry;
static int ett_shandong_attr;
static int ett_shandong_file;
static int ett_shandong_file_text;

static int hf_start;
static int hf_apdulen;
static int hf_apdulen_ext;
static int hf_apdulen_lo;
static int hf_apdulen_hi;
static int hf_apdulen_calc;
static int hf_apci_ctrl;
static int hf_apci_ctrl_b1;
static int hf_apci_ctrl_b2;
static int hf_apci_ctrl_b3;
static int hf_apci_ctrl_b4;
static int hf_apci_fmt_i;
static int hf_apci_fmt_su;
static int hf_apci_ns_lo;
static int hf_apci_ns_hi;
static int hf_apci_ns;
static int hf_apci_nr_lo;
static int hf_apci_nr_hi;
static int hf_apci_nr;
static int hf_apci_s_resv;
static int hf_apci_u_startdt_act;
static int hf_apci_u_startdt_con;
static int hf_apci_u_stopdt_act;
static int hf_apci_u_stopdt_con;
static int hf_apci_u_testfr_act;
static int hf_apci_u_testfr_con;
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
static int hf_gen_entry;
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
static int hf_file_chunk;
static int hf_file_offset;
static int hf_file_size;
static int hf_file_data;
static int hf_file_data_text;
static int hf_file_data_line;
static int hf_file_text;

static dissector_handle_t xml_handle;
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
	{ I_TYPE, "信息帧(I)" },
	{ S_TYPE, "监视帧(S)" },
	{ U_TYPE, "控制帧(U)" },
	{ 0, NULL }
};

/* U 功能摘要（第1字节 bit2-7，不含格式位） */
static const value_string u_func_vals[] = {
	{ 0x04, "启动数据传输激活" },
	{ 0x08, "启动数据传输确认" },
	{ 0x10, "停止数据传输激活" },
	{ 0x20, "停止数据传输确认" },
	{ 0x40, "测试帧激活" },
	{ 0x80, "测试帧确认" },
	{ 0, NULL }
};

static const true_false_string tfs_apci_set = { "置位", "未置位" };
/* bit0=0 → 信息帧(I)；bit0=1 → 非I */
static const true_false_string tfs_apci_bit0_i = { "非信息帧", "信息帧(I)" };

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

/* Drop leading orphan UTF-8 continuation bytes (10xxxxxx) from prior APDU. */
static int
skip_orphan_utf8_head(tvbuff_t *tvb, int offset, int len)
{
	int i = 0;

	while (i < len && (tvb_get_uint8(tvb, offset + i) & 0xc0) == 0x80)
		i++;
	return i;
}

/* Drop a trailing incomplete UTF-8 sequence (common in ASDU file fragments). */
static int
trim_incomplete_utf8_tail(tvbuff_t *tvb, int offset, int len)
{
	int i;

	if (len <= 0)
		return 0;
	i = len - 1;
	/* Continuation bytes 10xxxxxx — walk back to lead byte. */
	while (i > 0 && (tvb_get_uint8(tvb, offset + i) & 0xc0) == 0x80)
		i--;
	if (i < len - 1 || (tvb_get_uint8(tvb, offset + i) & 0x80) != 0) {
		uint8_t c = tvb_get_uint8(tvb, offset + i);
		int need = 0;

		if ((c & 0xe0) == 0xc0)
			need = 2;
		else if ((c & 0xf0) == 0xe0)
			need = 3;
		else if ((c & 0xf8) == 0xf0)
			need = 4;
		else if ((c & 0x80) != 0)
			return i; /* orphan continuation — drop it */
		if (need > 0 && i + need > len)
			return i; /* incomplete char at end */
	}
	return len;
}

/*
 * Normalize a possibly-fragmented text chunk for display.
 * Returns adjusted offset/len and chosen encoding (UTF-8 preferred for XML).
 */
static void
normalize_file_text_chunk(tvbuff_t *tvb, int *offset, int *len, unsigned *encoding)
{
	int off = *offset;
	int slim = trim_nul_len(tvb, off, *len);
	int head, cut;

	*encoding = ENC_UTF_8;
	if (slim <= 0) {
		*len = 0;
		return;
	}
	head = skip_orphan_utf8_head(tvb, off, slim);
	off += head;
	slim -= head;
	if (slim <= 0) {
		*offset = off;
		*len = 0;
		return;
	}
	cut = trim_incomplete_utf8_tail(tvb, off, slim);
	if (cut > 0)
		slim = cut;
	if (bytes_are_valid_utf8(tvb, off, slim)) {
		*encoding = ENC_UTF_8;
	} else {
		/* True GBK/GB18030 body (no UTF-8 structure). */
		*encoding = ENC_GB18030;
	}
	*offset = off;
	*len = slim;
}

/*
 * Field IEDs typically emit GBK/GB18030 for OS8ASCII names.
 * File payloads (XML etc.) are often UTF-8 and may be fragmented —
 * trim an incomplete tail then prefer UTF-8 when the body is valid.
 * Returns the byte length to decode (0 if empty).
 */
static int
zh_string_span(tvbuff_t *tvb, int offset, int len, unsigned *encoding)
{
	int slim = trim_nul_len(tvb, offset, len);

	*encoding = ENC_GB18030;
	if (slim <= 0)
		return 0;
	if (bytes_are_valid_utf8(tvb, offset, slim)) {
		*encoding = ENC_UTF_8;
	} else {
		int cut = trim_incomplete_utf8_tail(tvb, offset, slim);

		if (cut > 0 && cut < slim && bytes_are_valid_utf8(tvb, offset, cut)) {
			slim = cut;
			*encoding = ENC_UTF_8;
		}
	}
	return slim;
}

static char *
decode_zh_string(wmem_allocator_t *scope, tvbuff_t *tvb, int offset, int len)
{
	unsigned encoding;
	int slim = zh_string_span(tvb, offset, len, &encoding);

	if (slim <= 0)
		return wmem_strdup(scope, "");
	return (char *)tvb_get_string_enc(scope, tvb, offset, slim, encoding);
}

static void
proto_tree_add_zh_string(proto_tree *tree, int hfindex, tvbuff_t *tvb,
	int offset, int len)
{
	unsigned encoding;
	int slim = zh_string_span(tvb, offset, len, &encoding);

	if (slim <= 0) {
		proto_tree_add_string(tree, hfindex, tvb, offset, len, "");
		return;
	}
	proto_tree_add_item(tree, hfindex, tvb, offset, slim, encoding);
}

/*
 * Show file body as one tree node per physical line so the UI renders
 * real line breaks instead of escaped "\n" in a single FT_STRING.
 * Fragments may start/end mid-UTF-8 char — normalize before decode.
 */
static void
proto_tree_add_file_text(proto_tree *tree, int hfindex _U_, tvbuff_t *tvb,
	int offset, int len)
{
	proto_item *pi;
	proto_tree *pt;
	int orig_off = offset;
	int orig_len = len;
	int pos, end;
	unsigned encoding = ENC_UTF_8;

	normalize_file_text_chunk(tvb, &offset, &len, &encoding);
	if (len <= 0) {
		proto_tree_add_none_format(tree, hf_file_data_text, tvb, orig_off, orig_len,
			"文件数据文本 (File data text)");
		return;
	}

	pi = proto_tree_add_none_format(tree, hf_file_data_text, tvb, offset, len,
		"文件数据文本 (File data text)");
	pt = proto_item_add_subtree(pi, ett_shandong_file_text);

	pos = offset;
	end = offset + len;
	while (pos < end) {
		int line_end = pos;
		int next;
		int line_off, line_len;
		unsigned line_enc = encoding;

		while (line_end < end) {
			uint8_t c = tvb_get_uint8(tvb, line_end);
			if (c == '\n' || c == '\r')
				break;
			line_end++;
		}
		line_off = pos;
		line_len = line_end - pos;
		/* Per-line normalize in case a cut sits mid-line at fragment edge. */
		normalize_file_text_chunk(tvb, &line_off, &line_len, &line_enc);
		if (line_len > 0)
			proto_tree_add_item(pt, hf_file_data_line, tvb, line_off, line_len, line_enc);
		else
			proto_tree_add_string(pt, hf_file_data_line, tvb, pos, line_end - pos, "");
		next = line_end;
		if (next < end && tvb_get_uint8(tvb, next) == '\r')
			next++;
		if (next < end && tvb_get_uint8(tvb, next) == '\n')
			next++;
		if (next <= line_end)
			break;
		pos = next;
	}
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

/* True when chunk is mostly printable text (XML/cfg/ASCII/UTF-8). */
static bool
file_chunk_looks_text(tvbuff_t *tvb, int offset, int len)
{
	int i, printable = 0;
	int head;
	int off = offset;
	int slim = len;

	if (len <= 0)
		return false;
	head = skip_orphan_utf8_head(tvb, off, slim);
	off += head;
	slim -= head;
	if (slim > 0) {
		int cut = trim_incomplete_utf8_tail(tvb, off, slim);
		if (cut > 0)
			slim = cut;
		if (bytes_are_valid_utf8(tvb, off, slim))
			return true;
	}
	for (i = 0; i < len; i++) {
		uint8_t c = tvb_get_uint8(tvb, offset + i);
		if (c == 0)
			break;
		if (c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c < 0x7f))
			printable++;
		else if (c >= 0x80)
			printable++; /* allow high bytes; GBK/GB18030 text */
		else
			return false;
	}
	return printable * 10 >= len * 8; /* >= 80% printable */
}

static void
dissect_file_payload(proto_tree *tree, tvbuff_t *tvb, int *offset, int end)
{
	proto_tree *ft;
	proto_item *fi;
	int rem;
	int start = *offset;

	if (*offset >= end)
		return;
	fi = proto_tree_add_none_format(tree, hf_file_entry, tvb, *offset, end - *offset,
		"文件内容 (File content)");
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
		if (file_chunk_looks_text(tvb, *offset, rem)) {
			proto_tree_add_file_text(ft, hf_file_data_text, tvb, *offset, rem);
		} else {
			proto_tree_add_item(ft, hf_file_data, tvb, *offset, rem, ENC_NA);
		}
		*offset = end;
	}
	proto_item_set_len(fi, end - start);
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

/* Compact GID value for parent-item summary (ASDU10 tree title). */
static void
format_gid_value_summary(wmem_allocator_t *scope, tvbuff_t *tvb, int gid_off,
	int gid_len, uint8_t datatype, uint8_t datasize, uint8_t datanumber,
	uint8_t kod, char *buf, size_t buf_len)
{
	if (buf_len == 0)
		return;
	buf[0] = '\0';
	if (gid_len <= 0) {
		(void)snprintf(buf, buf_len, "-");
		return;
	}
	if (kod == KOD_ATTR || datatype == GDD_STRUCT) {
		(void)snprintf(buf, buf_len, "属性结构(%d字节)", gid_len);
		return;
	}
	if (kod == KOD_DESC || datatype == GDD_OS8ASCII) {
		int slim = trim_nul_len(tvb, gid_off, gid_len);
		unsigned encoding = ENC_GB18030;
		char *s;

		if (slim <= 0) {
			(void)snprintf(buf, buf_len, "\"\"");
			return;
		}
		if (bytes_are_valid_utf8(tvb, gid_off, slim))
			encoding = ENC_UTF_8;
		s = (char *)tvb_get_string_enc(scope, tvb, gid_off, slim, encoding);
		(void)snprintf(buf, buf_len, "\"%s\"", s ? s : "");
		return;
	}
	if (datatype == GDD_UI && datasize == 2 && datanumber == 1 && gid_len >= 2) {
		(void)snprintf(buf, buf_len, "%u", tvb_get_letohs(tvb, gid_off));
		return;
	}
	if (datatype == GDD_UI && datasize == 1 && datanumber == 1 && gid_len >= 1) {
		(void)snprintf(buf, buf_len, "%u", tvb_get_uint8(tvb, gid_off));
		return;
	}
	if (datatype == GDD_R32 && datasize == 4 && datanumber == 1 && gid_len >= 4) {
		(void)snprintf(buf, buf_len, "%g", (double)tvb_get_letohieee_float(tvb, gid_off));
		return;
	}
	if (datatype == GDD_DPI && gid_len >= 1) {
		(void)snprintf(buf, buf_len, "0x%02x", tvb_get_uint8(tvb, gid_off));
		return;
	}
	(void)snprintf(buf, buf_len, "%d字节", gid_len);
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
			uint8_t group, entry, kod;

			group = tvb_get_uint8(tvb, *offset);
			entry = tvb_get_uint8(tvb, *offset + 1);
			kod = tvb_get_uint8(tvb, *offset + 2);
			gi = proto_tree_add_none_format(tree, hf_gen_entry, tvb, *offset, 3,
				"通用分类命令元素 %u: 组号=%u 条目号=%u KOD=%s",
				i + 1, group, entry,
				val_to_str_const(kod, kod_vals, "未知"));
			gt = proto_item_add_subtree(gi, ett_shandong_gen_entry);
			proto_tree_add_item(gt, hf_gen_gin_group, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
			(*offset)++;
			proto_tree_add_item(gt, hf_gen_gin_entry, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
			(*offset)++;
			proto_tree_add_item(gt, hf_gen_kod, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
			(*offset)++;
			proto_item_set_end(gi, tvb, *offset);
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
		uint8_t group, entry, kod;
		uint8_t datatype = 0, datasize = 0, datanumber = 0;
		int start = *offset;
		int gid_off;
		int gid_len = 0;
		char value_buf[96];

		group = tvb_get_uint8(tvb, *offset);
		entry = tvb_get_uint8(tvb, *offset + 1);
		kod = tvb_get_uint8(tvb, *offset + 2);

		gi = proto_tree_add_none_format(tree, hf_gen_entry, tvb, *offset, -1,
			"通用分类数据元素 %u", i + 1);
		gt = proto_item_add_subtree(gi, ett_shandong_gen_entry);

		proto_tree_add_item(gt, hf_gen_gin_group, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
		proto_tree_add_item(gt, hf_gen_gin_entry, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
		proto_tree_add_item(gt, hf_gen_kod, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;

		if (*offset + 3 <= end) {
			datatype = tvb_get_uint8(tvb, *offset);
			datasize = tvb_get_uint8(tvb, *offset + 1);
			datanumber = tvb_get_uint8(tvb, *offset + 2);
			gid_len = (int)datasize * (int)datanumber;
			gid_off = *offset + 3;
			if (gid_len < 0 || gid_off + gid_len > end)
				gid_len = 0;
			format_gid_value_summary(pinfo->pool, tvb, gid_off, gid_len,
				datatype, datasize, datanumber, kod,
				value_buf, sizeof value_buf);
			proto_item_set_text(gi,
				"通用分类数据元素 %u: 组号=%u 条目号=%u 数据类型=%s 实际值=%s",
				i + 1, group, entry,
				val_to_str_const(datatype, gdd_type_vals, "未知"),
				value_buf);
		} else {
			proto_item_set_text(gi,
				"通用分类数据元素 %u: 组号=%u 条目号=%u",
				i + 1, group, entry);
		}

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
dissect_asdu_file_list(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
	int *offset, int end, bool disturbance_list)
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
		const char *name;

		fi = proto_tree_add_none_format(tree, hf_file_entry, tvb, *offset, -1,
			"文件条目 (File entry) %u", i + 1);
		ft = proto_item_add_subtree(fi, ett_shandong_file);
		if (disturbance_list) {
			name_len = (avail >= entry_len) ? entry_len : avail;
		} else {
			name_len = FILENAME_LEN;
			if (name_len > avail)
				name_len = avail;
		}
		name = decode_zh_string(pinfo->pool, tvb, *offset, name_len);
		if (name && name[0] != '\0') {
			proto_item_set_text(fi, "文件条目 (File entry) %u: %s",
				i + 1, name);
		}
		if (disturbance_list) {
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
			dissect_asdu_file_list(asdu_tree, pinfo, tvb, &offset, end, true);
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
		dissect_asdu_file_list(asdu_tree, pinfo, tvb, &offset, end, false);
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

/* 控制域四字节逐位中文解剖；返回帧类型，并通过 out_info 写 Info 摘要片段。 */
static uint8_t
dissect_apci_control(proto_tree *apci_tree, tvbuff_t *tvb, int offset,
	wmem_strbuf_t *out_info)
{
	proto_item *ctrl_ti, *b_ti;
	proto_tree *ctrl_tree, *b_tree;
	uint8_t b1, b2, b3, b4, type;
	uint16_t ns, nr;

	b1 = tvb_get_uint8(tvb, offset);
	b2 = tvb_get_uint8(tvb, offset + 1);
	b3 = tvb_get_uint8(tvb, offset + 2);
	b4 = tvb_get_uint8(tvb, offset + 3);

	if ((b1 & 0x01) == 0)
		type = I_TYPE;
	else
		type = b1 & 0x03;

	ctrl_ti = proto_tree_add_item(apci_tree, hf_apci_ctrl, tvb, offset, 4, ENC_NA);
	proto_item_append_text(ctrl_ti, ": %s", val_to_str_const(type, apci_types, "未知"));
	ctrl_tree = proto_item_add_subtree(ctrl_ti, ett_shandong_apci_ctrl);

	/* ---- 第1字节 ---- */
	b_ti = proto_tree_add_uint_format_value(ctrl_tree, hf_apci_ctrl_b1, tvb, offset, 1, b1,
		"0x%02x", b1);
	b_tree = proto_item_add_subtree(b_ti, ett_shandong_apci_ctrl_b1);

	if (type == I_TYPE) {
		ns = (uint16_t)((b1 >> 1) | ((uint16_t)b2 << 7));
		nr = (uint16_t)((b3 >> 1) | ((uint16_t)b4 << 7));

		proto_tree_add_item(b_tree, hf_apci_fmt_i, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(b_tree, hf_apci_ns_lo, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_item_append_text(b_ti, " [信息帧(I), N(S)低7位]");

		b_ti = proto_tree_add_uint_format_value(ctrl_tree, hf_apci_ctrl_b2, tvb,
			offset + 1, 1, b2, "0x%02x", b2);
		b_tree = proto_item_add_subtree(b_ti, ett_shandong_apci_ctrl_b2);
		proto_tree_add_item(b_tree, hf_apci_ns_hi, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
		proto_item_append_text(b_ti, " [N(S)高8位]");

		proto_tree_add_uint(ctrl_tree, hf_apci_ns, tvb, offset, 2, ns);
		proto_tree_add_uint(apci_tree, hf_apcitx, tvb, offset, 4, ns);

		b_ti = proto_tree_add_uint_format_value(ctrl_tree, hf_apci_ctrl_b3, tvb,
			offset + 2, 1, b3, "0x%02x", b3);
		b_tree = proto_item_add_subtree(b_ti, ett_shandong_apci_ctrl_b3);
		proto_tree_add_item(b_tree, hf_apci_fmt_i, tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(b_tree, hf_apci_nr_lo, tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
		proto_item_append_text(b_ti, " [N(R)低7位]");

		b_ti = proto_tree_add_uint_format_value(ctrl_tree, hf_apci_ctrl_b4, tvb,
			offset + 3, 1, b4, "0x%02x", b4);
		b_tree = proto_item_add_subtree(b_ti, ett_shandong_apci_ctrl_b4);
		proto_tree_add_item(b_tree, hf_apci_nr_hi, tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
		proto_item_append_text(b_ti, " [N(R)高8位]");

		proto_tree_add_uint(ctrl_tree, hf_apci_nr, tvb, offset + 2, 2, nr);
		proto_tree_add_uint(apci_tree, hf_apcirx, tvb, offset, 4, nr);

		wmem_strbuf_append_printf(out_info, "信息帧(I) N(S)=%u N(R)=%u", ns, nr);
	} else if (type == S_TYPE) {
		nr = (uint16_t)((b3 >> 1) | ((uint16_t)b4 << 7));

		proto_tree_add_item(b_tree, hf_apci_fmt_su, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(b_tree, hf_apci_s_resv, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_item_append_text(b_ti, " [监视帧(S)]");

		b_ti = proto_tree_add_uint_format_value(ctrl_tree, hf_apci_ctrl_b2, tvb,
			offset + 1, 1, b2, "0x%02x", b2);
		proto_item_append_text(b_ti, " [保留, 应为0]");

		b_ti = proto_tree_add_uint_format_value(ctrl_tree, hf_apci_ctrl_b3, tvb,
			offset + 2, 1, b3, "0x%02x", b3);
		b_tree = proto_item_add_subtree(b_ti, ett_shandong_apci_ctrl_b3);
		proto_tree_add_item(b_tree, hf_apci_fmt_i, tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(b_tree, hf_apci_nr_lo, tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
		proto_item_append_text(b_ti, " [N(R)低7位]");

		b_ti = proto_tree_add_uint_format_value(ctrl_tree, hf_apci_ctrl_b4, tvb,
			offset + 3, 1, b4, "0x%02x", b4);
		b_tree = proto_item_add_subtree(b_ti, ett_shandong_apci_ctrl_b4);
		proto_tree_add_item(b_tree, hf_apci_nr_hi, tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
		proto_item_append_text(b_ti, " [N(R)高8位]");

		proto_tree_add_uint(ctrl_tree, hf_apci_nr, tvb, offset + 2, 2, nr);
		proto_tree_add_uint(apci_tree, hf_apcirx, tvb, offset, 4, nr);

		wmem_strbuf_append_printf(out_info, "监视帧(S) N(R)=%u", nr);
	} else {
		/* U 格式 */
		proto_tree_add_item(b_tree, hf_apci_fmt_su, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(b_tree, hf_apci_u_startdt_act, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(b_tree, hf_apci_u_startdt_con, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(b_tree, hf_apci_u_stopdt_act, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(b_tree, hf_apci_u_stopdt_con, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(b_tree, hf_apci_u_testfr_act, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(b_tree, hf_apci_u_testfr_con, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_item_append_text(b_ti, " [控制帧(U) %s]",
			val_to_str_const(b1 & 0xfc, u_func_vals, "未知功能"));

		b_ti = proto_tree_add_uint_format_value(ctrl_tree, hf_apci_ctrl_b2, tvb,
			offset + 1, 1, b2, "0x%02x", b2);
		proto_item_append_text(b_ti, " [保留, 应为0]");
		b_ti = proto_tree_add_uint_format_value(ctrl_tree, hf_apci_ctrl_b3, tvb,
			offset + 2, 1, b3, "0x%02x", b3);
		proto_item_append_text(b_ti, " [保留, 应为0]");
		b_ti = proto_tree_add_uint_format_value(ctrl_tree, hf_apci_ctrl_b4, tvb,
			offset + 3, 1, b4, "0x%02x", b4);
		proto_item_append_text(b_ti, " [保留, 应为0]");

		proto_tree_add_uint(apci_tree, hf_apciutype, tvb, offset, 1, b1 & 0xfc);

		wmem_strbuf_append_printf(out_info, "控制帧(U) %s",
			val_to_str_const(b1 & 0xfc, u_func_vals, "未知功能"));
	}

	return type;
}

static int
dissect_shandong_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *ti, *len_ti;
	proto_tree *apci_tree, *len_tree;
	int tcp_len = (int)tvb_reported_length(tvb);
	unsigned off, body = 0, total = 0;
	bool found = false;
	uint8_t type;
	uint8_t len_lo, len_hi;
	wmem_strbuf_t *res;
	int offset;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "山东主子站103");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_shandong_iec103, tvb, 0, -1, ENC_NA);
	proto_item_set_text(ti, "山东主子站103规约");
	apci_tree = proto_item_add_subtree(ti, ett_shandong_apci);

	for (off = 0; (int)off + 2 < tcp_len; off++) {
		if (try_apdu_at(tvb, 0, off, (unsigned)tcp_len, &body, &total)) {
			found = true;
			break;
		}
	}
	if (!found) {
		proto_tree_add_item(apci_tree, hf_raw, tvb, 0, tcp_len, ENC_NA);
		col_set_str(pinfo->cinfo, COL_INFO, "TCP续传/无有效APCI");
		return tvb_captured_length(tvb);
	}

	if (off > 0)
		proto_tree_add_item(apci_tree, hf_junk, tvb, 0, (int)off, ENC_NA);

	offset = (int)off;

	/* 1. 启动字符 */
	proto_tree_add_uint_format_value(apci_tree, hf_start, tvb, offset, 1, APCI_START,
		"0x%02x", APCI_START);
	offset++;

	/* 2. APDU长度：低字节 + 高字节 + 合成 */
	len_lo = tvb_get_uint8(tvb, offset);
	len_hi = tvb_get_uint8(tvb, offset + 1);
	len_ti = proto_tree_add_uint_format_value(apci_tree, hf_apdulen_calc, tvb, offset, 2, body,
		"%u (= 低字节%u + 高字节%u×256, 含控制域+ASDU)",
		body, len_lo, len_hi);
	len_tree = proto_item_add_subtree(len_ti, ett_shandong_apci_len);
	proto_tree_add_uint(len_tree, hf_apdulen_lo, tvb, offset, 1, len_lo);
	proto_tree_add_uint(len_tree, hf_apdulen_hi, tvb, offset + 1, 1, len_hi);
	proto_tree_add_uint(len_tree, hf_apdulen, tvb, offset, 2, body);
	offset += 2;

	if (body < APDU_MIN_LEN || body > APDU_MAX_BODY) {
		expert_add_info_format(pinfo, ti, &ei_apdu_bad_len,
			"APDU长度非法 %u (允许 %d..%d)",
			body, APDU_MIN_LEN, APDU_MAX_BODY);
		return tvb_captured_length(tvb);
	}

	proto_item_set_len(ti, (int)total);

	res = wmem_strbuf_create(pinfo->pool);
	wmem_strbuf_append_printf(res, "%s ",
		(pinfo->srcport == pinfo->match_uint ? "->" : "<-"));

	/* 3. 控制域逐字节逐位 */
	type = dissect_apci_control(apci_tree, tvb, offset, res);

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
		  { "启动字符", "shandong_iec103.start", FT_UINT8, BASE_HEX, NULL, 0x0,
		    "APCI启动字符, 固定为68H", HFILL }},
		{ &hf_apdulen,
		  { "APDU长度", "shandong_iec103.apdulen", FT_UINT16, BASE_DEC, NULL, 0x0,
		    "控制域+ASDU字节数(小端)", HFILL }},
		{ &hf_apdulen_ext,
		  { "APDU长度(别名)", "shandong_iec103.apdulen_ext", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_apdulen_lo,
		  { "长度低字节", "shandong_iec103.apdulen.lo", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_apdulen_hi,
		  { "长度高字节", "shandong_iec103.apdulen.hi", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_apdulen_calc,
		  { "APDU长度", "shandong_iec103.apdulen.calc", FT_UINT16, BASE_DEC, NULL, 0x0,
		    "长度=低字节+高字节×256, 表示控制域与ASDU总长度", HFILL }},
		{ &hf_apci_ctrl,
		  { "控制域", "shandong_iec103.apci.ctrl", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_apci_ctrl_b1,
		  { "控制域第1字节", "shandong_iec103.apci.ctrl.b1", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_apci_ctrl_b2,
		  { "控制域第2字节", "shandong_iec103.apci.ctrl.b2", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_apci_ctrl_b3,
		  { "控制域第3字节", "shandong_iec103.apci.ctrl.b3", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_apci_ctrl_b4,
		  { "控制域第4字节", "shandong_iec103.apci.ctrl.b4", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_apci_fmt_i,
		  { "格式位(bit0)", "shandong_iec103.apci.fmt_bit0", FT_BOOLEAN, 8, TFS(&tfs_apci_bit0_i), 0x01,
		    "I格式要求为0", HFILL }},
		{ &hf_apci_fmt_su,
		  { "帧格式(bit1-0)", "shandong_iec103.apci.fmt", FT_UINT8, BASE_HEX, VALS(apci_types), 0x03,
		    "01=监视帧(S), 11=控制帧(U)", HFILL }},
		{ &hf_apci_ns_lo,
		  { "发送序号N(S)低7位(bit7-1)", "shandong_iec103.apci.ns_lo", FT_UINT8, BASE_DEC, NULL, 0xfe, NULL, HFILL }},
		{ &hf_apci_ns_hi,
		  { "发送序号N(S)高8位", "shandong_iec103.apci.ns_hi", FT_UINT8, BASE_DEC, NULL, 0xff, NULL, HFILL }},
		{ &hf_apci_ns,
		  { "发送序号N(S)", "shandong_iec103.apci.ns", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_apci_nr_lo,
		  { "接收序号N(R)低7位(bit7-1)", "shandong_iec103.apci.nr_lo", FT_UINT8, BASE_DEC, NULL, 0xfe, NULL, HFILL }},
		{ &hf_apci_nr_hi,
		  { "接收序号N(R)高8位", "shandong_iec103.apci.nr_hi", FT_UINT8, BASE_DEC, NULL, 0xff, NULL, HFILL }},
		{ &hf_apci_nr,
		  { "接收序号N(R)", "shandong_iec103.apci.nr", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_apci_s_resv,
		  { "S格式保留位(bit7-2)", "shandong_iec103.apci.s_resv", FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL }},
		{ &hf_apci_u_startdt_act,
		  { "启动数据传输激活(bit2)", "shandong_iec103.apci.u.startdt_act", FT_BOOLEAN, 8, TFS(&tfs_apci_set), 0x04, NULL, HFILL }},
		{ &hf_apci_u_startdt_con,
		  { "启动数据传输确认(bit3)", "shandong_iec103.apci.u.startdt_con", FT_BOOLEAN, 8, TFS(&tfs_apci_set), 0x08, NULL, HFILL }},
		{ &hf_apci_u_stopdt_act,
		  { "停止数据传输激活(bit4)", "shandong_iec103.apci.u.stopdt_act", FT_BOOLEAN, 8, TFS(&tfs_apci_set), 0x10, NULL, HFILL }},
		{ &hf_apci_u_stopdt_con,
		  { "停止数据传输确认(bit5)", "shandong_iec103.apci.u.stopdt_con", FT_BOOLEAN, 8, TFS(&tfs_apci_set), 0x20, NULL, HFILL }},
		{ &hf_apci_u_testfr_act,
		  { "测试帧激活(bit6)", "shandong_iec103.apci.u.testfr_act", FT_BOOLEAN, 8, TFS(&tfs_apci_set), 0x40, NULL, HFILL }},
		{ &hf_apci_u_testfr_con,
		  { "测试帧确认(bit7)", "shandong_iec103.apci.u.testfr_con", FT_BOOLEAN, 8, TFS(&tfs_apci_set), 0x80, NULL, HFILL }},
		{ &hf_file_entry,
		  { "文件条目 (File entry)", "shandong_iec103.file_entry", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_apcitype_i,
		  { "帧类型", "shandong_iec103.type", FT_UINT32, BASE_HEX, VALS(apci_types), 0x00000001, NULL, HFILL }},
		{ &hf_apcitype_su,
		  { "帧类型", "shandong_iec103.type", FT_UINT32, BASE_HEX, VALS(apci_types), 0x00000003, NULL, HFILL }},
		{ &hf_apcitx,
		  { "发送序号N(S)", "shandong_iec103.tx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_apcirx,
		  { "接收序号N(R)", "shandong_iec103.rx", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_apciutype,
		  { "U功能", "shandong_iec103.utype", FT_UINT8, BASE_HEX, VALS(u_func_vals), 0x0, NULL, HFILL }},
		{ &hf_junk,
		  { "前导无效数据", "shandong_iec103.junk", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_typeid,
		  { "类型标识 (Type ID)", "shandong_iec103.typeid", FT_UINT8, BASE_DEC, VALS(asdu_type_vals), 0x0, NULL, HFILL }},
		{ &hf_vsq,
		  { "可变结构限定词 (VSQ)", "shandong_iec103.vsq", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_vsq_sq,
		  { "顺序位 (SQ)", "shandong_iec103.vsq.sq", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
		{ &hf_vsq_num,
		  { "信息体数目 (Number of objects)", "shandong_iec103.vsq.num", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }},
		{ &hf_cot,
		  { "传送原因 (COT)", "shandong_iec103.cot", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_asdu_addr,
		  { "ASDU地址 (ASDU address)", "shandong_iec103.asdu_addr", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_fun,
		  { "功能类型 (FUN)", "shandong_iec103.fun", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_inf,
		  { "信息序号 (INF)", "shandong_iec103.inf", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_dpi,
		  { "双点信息 (DPI)", "shandong_iec103.dpi", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sin,
		  { "附加信息 (SIN)", "shandong_iec103.sin", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_scn,
		  { "扫描序号 (SCN)", "shandong_iec103.scn", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_rii,
		  { "返回信息标识符 (RII)", "shandong_iec103.rii", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_ngd,
		  { "通用数据集数目 (NGD)", "shandong_iec103.ngd", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_ngd_cont,
		  { "后续标志 (NGD CONT)", "shandong_iec103.ngd.cont", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
		{ &hf_ngd_count,
		  { "数据集个数 (NGD count)", "shandong_iec103.ngd.count", FT_UINT8, BASE_DEC, NULL, 0x3F, NULL, HFILL }},
		{ &hf_nog,
		  { "通用对象数目 (NOG)", "shandong_iec103.nog", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_raw,
		  { "原始数据 (Data)", "shandong_iec103.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_entry,
		  { "通用分类元素 (Generic entry)", "shandong_iec103.gen.entry_item", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_cp56time,
		  { "时标 (CP56Time2a)", "shandong_iec103.cp56time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }},
		{ &hf_cp56time_ms,
		  { "毫秒 (Milliseconds)", "shandong_iec103.cp56time.ms", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_cp56time_min,
		  { "分钟 (Minutes)", "shandong_iec103.cp56time.min", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL }},
		{ &hf_cp56time_iv,
		  { "无效标志 (IV)", "shandong_iec103.cp56time.iv", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
		{ &hf_cp56time_hour,
		  { "小时 (Hours)", "shandong_iec103.cp56time.hour", FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL }},
		{ &hf_cp56time_su,
		  { "夏令时 (SU)", "shandong_iec103.cp56time.su", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
		{ &hf_cp56time_day,
		  { "日 (Day)", "shandong_iec103.cp56time.day", FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL }},
		{ &hf_cp56time_dow,
		  { "星期 (Day of week)", "shandong_iec103.cp56time.dow", FT_UINT8, BASE_DEC, NULL, 0xe0, NULL, HFILL }},
		{ &hf_cp56time_month,
		  { "月 (Month)", "shandong_iec103.cp56time.month", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_cp56time_year,
		  { "年 (Year)", "shandong_iec103.cp56time.year", FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL }},
		{ &hf_gen_gin_group,
		  { "组号 (GIN group)", "shandong_iec103.gen.group", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_gin_entry,
		  { "条目号 (GIN entry)", "shandong_iec103.gen.entry", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_kod,
		  { "描述类别 (KOD)", "shandong_iec103.gen.kod", FT_UINT8, BASE_HEX, VALS(kod_vals), 0x0, NULL, HFILL }},
		{ &hf_gen_datatype,
		  { "数据类型 (Data type)", "shandong_iec103.gen.datatype", FT_UINT8, BASE_DEC, VALS(gdd_type_vals), 0x0, NULL, HFILL }},
		{ &hf_gen_datasize,
		  { "数据宽度 (Data size)", "shandong_iec103.gen.datasize", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_datanumber,
		  { "数据数目 (Data number)", "shandong_iec103.gen.datanumber", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_gid,
		  { "通用标识数据 (GID)", "shandong_iec103.gen.gid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_desc,
		  { "描述 (Description)", "shandong_iec103.gen.desc", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_gid_ui,
		  { "无符号整数 (GID UI)", "shandong_iec103.gen.gid_ui", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_gid_float,
		  { "浮点数 (GID R32.23)", "shandong_iec103.gen.gid_float", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_endflag,
		  { "结束标志 (ENDFLAG)", "shandong_iec103.endflag", FT_UINT8, BASE_DEC, VALS(endflag_vals), 0x0, NULL, HFILL }},
		{ &hf_file_num,
		  { "文件个数 (File count)", "shandong_iec103.file_num", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_filename,
		  { "文件名 (File name)", "shandong_iec103.filename", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_file_offset,
		  { "传输偏移 (Transfer offset)", "shandong_iec103.file_offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_file_size,
		  { "文件长度 (File size)", "shandong_iec103.file_size", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_file_data,
		  { "文件数据 (File data)", "shandong_iec103.file_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_file_data_text,
		  { "文件数据文本 (File data text)", "shandong_iec103.file_data_text", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_file_data_line,
		  { "行 (Line)", "shandong_iec103.file_data_line", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_event_type,
		  { "事件类型 (Event type)", "shandong_iec103.event_type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_fpt,
		  { "故障相别 (FPT)", "shandong_iec103.fpt", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_jpt,
		  { "跳闸相别 (JPT)", "shandong_iec103.jpt", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_scl,
		  { "故障测距 (SCL)", "shandong_iec103.scl", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_ret,
		  { "相对时间 (RET)", "shandong_iec103.ret", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_fan,
		  { "故障序号 (FAN)", "shandong_iec103.fan", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_reclose_dpi,
		  { "重合闸 (Reclose DPI)", "shandong_iec103.reclose_dpi", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_attr_layout,
		  { "属性结构布局 (Attribute layout)", "shandong_iec103.attr.layout", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_attr_bytes,
		  { "属性结构字节 (Attribute bytes)", "shandong_iec103.attr.bytes", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	};

	static int *ett[] = {
		&ett_shandong_iec103,
		&ett_shandong_apci,
		&ett_shandong_apci_len,
		&ett_shandong_apci_ctrl,
		&ett_shandong_apci_ctrl_b1,
		&ett_shandong_apci_ctrl_b2,
		&ett_shandong_apci_ctrl_b3,
		&ett_shandong_apci_ctrl_b4,
		&ett_shandong_asdu,
		&ett_shandong_cp56time,
		&ett_shandong_gen,
		&ett_shandong_gen_entry,
		&ett_shandong_attr,
		&ett_shandong_file,
		&ett_shandong_file_text,
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
