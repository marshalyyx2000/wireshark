/* packet-nari-net-iec103.c
 *
 * NARI (国电南京自动化) IEC 60870-5-103 over Ethernet.
 * TCP port 1048: raw ASDU stream (no APCI/68H framing).
 * UDP port 1032: 41-byte master on-line broadcast (byte0 = 0xFF).
 * ASDU address: 1 byte; minimum header 6 bytes (TYP, VSQ, COT, ADDR, FUN, INF).
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

void proto_register_nari_net_iec103(void);
void proto_reg_handoff_nari_net_iec103(void);

#define NARI_NET_IEC103_TCP_PORT 1048
#define NARI_NET_IEC103_UDP_PORT 1032
#define NARI_UDP_BCAST_LEN       41
#define NARI_UDP_BCAST_MARK      0xFF
#define NARI_ASDU_HDR_LEN        6
#define NARI_ASDU5_BODY_LEN      25
#define NARI_ASDU6_BODY_LEN      7
#define NARI_ASDU7_BODY_LEN      1
#define NARI_ASDU20_BODY_LEN     1
#define NARI_ASDU24_BODY_LEN     5
#define NARI_ASDU25_BODY_LEN     5
#define NARI_ASDU26_BODY_LEN     14
#define NARI_ASDU27_BODY_LEN     17
#define NARI_ASDU28_BODY_LEN     4
#define NARI_ASDU29_BODY_MIN     3
#define NARI_ASDU31_BODY_LEN     5
#define NARI_ASDU23_SQ1_ENTRY    8
#define NARI_ASDU23_SQ0_ENTRY    9
#define NARI_NAME_FIELD_LEN      16

#define KOD_VALUE  0x01
#define KOD_DESC   0x0A

#define GDD_OS8ASCII  1
#define GDD_UI        3
#define GDD_R32       7
#define GDD_DPI       9
#define GDD_STRUCT    23

static int proto_nari_net_iec103;
static dissector_handle_t nari_net_iec103_tcp_handle;
static dissector_handle_t nari_net_iec103_udp_handle;

static int ett_nari_net_iec103;
static int ett_nari_asdu;
static int ett_nari_cp56time;
static int ett_nari_gen;
static int ett_nari_gen_entry;
static int ett_nari_dist;
static int ett_nari_dist_entry;
static int ett_nari_udp;

static int hf_typeid;
static int hf_vsq;
static int hf_vsq_sq;
static int hf_vsq_num;
static int hf_cot;
static int hf_asdu_addr;
static int hf_fun;
static int hf_inf;
static int hf_dpi;
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
static int hf_col;
static int hf_dco;
static int hf_tov;
static int hf_fan;
static int hf_acc;
static int hf_ndv;
static int hf_nfe;
static int hf_sdv;
static int hf_nof;
static int hf_noc;
static int hf_noe;
static int hf_too;
static int hf_rpv;
static int hf_rdv;
static int hf_rfa;
static int hf_ret;
static int hf_dist_entry;
static int hf_tag;
static int hf_udp_mark;
static int hf_udp_time_flag;
static int hf_udp_name;
static int hf_udp_padding;

static expert_field ei_asdu_truncated;
static expert_field ei_asdu_unknown;

static const value_string asdu_type_vals[] = {
	{ 5,  "ASDU5  标识 (Identification)" },
	{ 6,  "ASDU6  时间同步 (Time synchronization)" },
	{ 7,  "ASDU7  总查询 (General interrogation)" },
	{ 8,  "ASDU8  总查询终止 (Termination of general interrogation)" },
	{ 10, "ASDU10 通用分类数据 (Generic data)" },
	{ 20, "ASDU20 一般命令 (General command)" },
	{ 21, "ASDU21 通用分类命令 (Generic command)" },
	{ 23, "ASDU23 被记录的扰动表 (List of recorded disturbances)" },
	{ 24, "ASDU24 扰动数据传输准备就绪 (Disturbance data ready)" },
	{ 25, "ASDU25 扰动数据传输准备就绪并传送通道 (Disturbance data ready for transmission)" },
	{ 26, "ASDU26 传送扰动值准备就绪 (Ready for transmission of disturbance values)" },
	{ 27, "ASDU27 被记录的通道传送准备就绪 (Ready for transmission of recorded channels)" },
	{ 28, "ASDU28 带标志的状态变位传输准备就绪 (Ready for transmission of tags)" },
	{ 29, "ASDU29 带标志的状态变位传输终止 (End of transmission of tags)" },
	{ 30, "ASDU30 传送扰动值 (Transmission of disturbance values)" },
	{ 31, "ASDU31 传送结束 (End of transmission)" },
	{ 0, NULL }
};

static const value_string kod_vals[] = {
	{ 0x01, "实际值 (Actual value)" },
	{ 0x0A, "描述 (Description)" },
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

static const true_false_string tfs_time_flag_set = { "含时标", "无时标" };

/* ---- Chinese / padded string helpers (from packet-shandong-iec103.c) ---- */

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

static int
trim_incomplete_utf8_tail(tvbuff_t *tvb, int offset, int len)
{
	int i;

	if (len <= 0)
		return 0;
	i = len - 1;
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
			return i;
		if (need > 0 && i + need > len)
			return i;
	}
	return len;
}

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
	tm_tree = proto_item_add_subtree(ti, ett_nari_cp56time);

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
			gt = proto_item_add_subtree(gi, ett_nari_gen_entry);
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
		gt = proto_item_add_subtree(gi, ett_nari_gen_entry);

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

static bool
is_plausible_nari_asdu_type(uint8_t typ)
{
	switch (typ) {
	case 5:
	case 6:
	case 7:
	case 8:
	case 10:
	case 20:
	case 21:
	case 23:
	case 24:
	case 25:
	case 26:
	case 27:
	case 28:
	case 29:
	case 30:
	case 31:
		return true;
	default:
		return false;
	}
}

static unsigned
walk_generic_body_len(tvbuff_t *tvb, unsigned offset, unsigned remaining,
	bool is_command)
{
	unsigned pos = offset + NARI_ASDU_HDR_LEN;
	unsigned end = offset + remaining;
	unsigned nds, i;

	if (pos >= end)
		return NARI_ASDU_HDR_LEN;
	pos++; /* RII */
	if (pos >= end)
		return pos - offset;

	if (is_command) {
		nds = tvb_get_uint8(tvb, (int)pos);
		pos++;
		for (i = 0; i < nds && pos + 3 <= end; i++)
			pos += 3;
		return pos - offset;
	}

	nds = tvb_get_uint8(tvb, (int)pos) & 0x3f;
	pos++;
	for (i = 0; i < nds && pos + 3 <= end; i++) {
		uint8_t datasize, datanumber;
		int gid_len;

		pos += 3; /* GIN + KOD */
		if (pos + 3 > end)
			break;
		datasize = tvb_get_uint8(tvb, (int)pos + 1);
		datanumber = tvb_get_uint8(tvb, (int)pos + 2);
		gid_len = (int)datasize * (int)datanumber;
		pos += 3;
		if (gid_len < 0 || pos + (unsigned)gid_len > end)
			break;
		pos += (unsigned)gid_len;
	}
	return pos - offset;
}

static unsigned
walk_asdu23_body_len(tvbuff_t *tvb, unsigned offset, unsigned remaining)
{
	uint8_t vsq;
	unsigned num;
	unsigned entry_len;
	unsigned pos;

	if (remaining < NARI_ASDU_HDR_LEN)
		return remaining;

	vsq = tvb_get_uint8(tvb, (int)offset + 1);
	num = vsq & 0x7f;
	entry_len = (vsq & 0x80) ? NARI_ASDU23_SQ1_ENTRY : NARI_ASDU23_SQ0_ENTRY;
	pos = offset + NARI_ASDU_HDR_LEN + num * entry_len;
	if (pos > offset + remaining)
		return offset + remaining - offset;
	return pos - offset;
}

static unsigned
walk_asdu29_body_len(tvbuff_t *tvb, unsigned offset, unsigned remaining)
{
	unsigned pos = offset + NARI_ASDU_HDR_LEN;
	unsigned end = offset + remaining;

	if (pos + NARI_ASDU29_BODY_MIN > end)
		return end - offset;

	pos += NARI_ASDU29_BODY_MIN;
	while (pos + 5 <= end && tvb_get_uint8(tvb, (int)pos) == 0xFF)
		pos += 5;

	return pos - offset;
}

static unsigned
heuristic_nari_asdu_len(tvbuff_t *tvb, unsigned offset, unsigned remaining)
{
	unsigned scan;

	if (remaining < NARI_ASDU_HDR_LEN)
		return remaining;

	for (scan = NARI_ASDU_HDR_LEN; scan < remaining; scan++) {
		uint8_t typ = tvb_get_uint8(tvb, (int)offset + (int)scan);

		if (!is_plausible_nari_asdu_type(typ))
			continue;
		if (scan == NARI_ASDU_HDR_LEN)
			break;
		return scan;
	}
	return remaining;
}

static unsigned
compute_nari_asdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	unsigned remaining = tvb_reported_length_remaining(tvb, offset);
	uint8_t typ;
	uint16_t ndv;
	unsigned body_len;

	if (remaining < NARI_ASDU_HDR_LEN)
		return remaining;

	typ = tvb_get_uint8(tvb, offset);
	if (!is_plausible_nari_asdu_type(typ))
		return heuristic_nari_asdu_len(tvb, offset, remaining);

	switch (typ) {
	case 5:
		body_len = NARI_ASDU5_BODY_LEN;
		break;
	case 6:
		body_len = NARI_ASDU6_BODY_LEN;
		break;
	case 7:
	case 8:
		body_len = NARI_ASDU7_BODY_LEN;
		break;
	case 10:
		return walk_generic_body_len(tvb, offset, remaining, false);
	case 20:
		body_len = NARI_ASDU20_BODY_LEN;
		break;
	case 21:
		return walk_generic_body_len(tvb, offset, remaining, true);
	case 23:
		return walk_asdu23_body_len(tvb, offset, remaining);
	case 24:
		body_len = NARI_ASDU24_BODY_LEN;
		break;
	case 25:
		body_len = NARI_ASDU25_BODY_LEN;
		break;
	case 26:
		body_len = NARI_ASDU26_BODY_LEN;
		break;
	case 27:
		body_len = NARI_ASDU27_BODY_LEN;
		break;
	case 28:
		body_len = NARI_ASDU28_BODY_LEN;
		break;
	case 29:
		return walk_asdu29_body_len(tvb, offset, remaining);
	case 30:
		if (remaining < 16)
			return remaining;
		ndv = tvb_get_letohs(tvb, offset + 12);
		body_len = 10 + (unsigned)ndv * 2;
		break;
	case 31:
		body_len = NARI_ASDU31_BODY_LEN;
		break;
	default:
		return heuristic_nari_asdu_len(tvb, offset, remaining);
	}

	if (NARI_ASDU_HDR_LEN + body_len > remaining)
		return remaining;
	return NARI_ASDU_HDR_LEN + body_len;
}

static void
dissect_asdu23(proto_tree *tree, tvbuff_t *tvb, int *offset, int end, uint8_t vsq)
{
	unsigned num = vsq & 0x7f;
	unsigned i;
	bool sq = (vsq & 0x80) != 0;

	for (i = 0; i < num && *offset < end; i++) {
		proto_item *pi;
		proto_tree *pt;
		int start = *offset;

		pi = proto_tree_add_none_format(tree, hf_dist_entry, tvb, *offset, -1,
			"扰动表条目 %u", i + 1);
		pt = proto_item_add_subtree(pi, ett_nari_dist_entry);

		if (!sq) {
			proto_tree_add_item(pt, hf_fun, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
			(*offset)++;
			proto_tree_add_item(pt, hf_inf, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
			(*offset)++;
		}
		proto_tree_add_item(pt, hf_tov, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
		proto_tree_add_item(pt, hf_fan, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
		*offset += 2;
		if (sq) {
			proto_tree_add_item(pt, hf_acc, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
			(*offset)++;
		}
		if (end - *offset >= 4) {
			proto_tree_add_item(pt, hf_ret, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
			*offset += 4;
		}
		proto_item_set_len(pi, *offset - start);
	}
}

static void
dissect_asdu30(proto_tree *tree, tvbuff_t *tvb, int *offset, int end)
{
	uint16_t ndv;
	int sdv_len;
	proto_item *pi;
	proto_tree *pt;
	int start = *offset;

	if (end - *offset < 10)
		return;

	pi = proto_tree_add_none_format(tree, hf_dist_entry, tvb, *offset, end - *offset,
		"扰动值 (Disturbance values)");
	pt = proto_item_add_subtree(pi, ett_nari_dist);

	proto_tree_add_item(pt, hf_raw, tvb, *offset, 2, ENC_NA); /* reserved */
	*offset += 2;
	proto_tree_add_item(pt, hf_tov, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
	proto_tree_add_item(pt, hf_fan, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
	*offset += 2;
	proto_tree_add_item(pt, hf_acc, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
	proto_tree_add_item(pt, hf_ndv, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
	ndv = tvb_get_letohs(tvb, *offset);
	*offset += 2;
	proto_tree_add_item(pt, hf_nfe, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
	*offset += 2;

	sdv_len = (int)ndv * 2;
	if (sdv_len > 0 && *offset + sdv_len <= end) {
		proto_tree_add_item(pt, hf_sdv, tvb, *offset, sdv_len, ENC_NA);
		*offset += sdv_len;
	}
	proto_item_set_len(pi, *offset - start);
}

static void
dissect_asdu29_tags(proto_tree *tree, tvbuff_t *tvb, int *offset, int end)
{
	while (*offset + 5 <= end && tvb_get_uint8(tvb, *offset) == 0xFF) {
		proto_item *pi;
		proto_tree *pt;
		int start = *offset;

		pi = proto_tree_add_none_format(tree, hf_tag, tvb, *offset, 5,
			"状态变位标志");
		pt = proto_item_add_subtree(pi, ett_nari_dist_entry);
		proto_tree_add_item(pt, hf_tag, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
		proto_tree_add_item(pt, hf_acc, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
		proto_tree_add_item(pt, hf_dpi, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		(*offset)++;
		proto_tree_add_item(pt, hf_raw, tvb, *offset, 2, ENC_NA);
		*offset += 2;
		proto_item_set_len(pi, *offset - start);
	}
}

static void
dissect_asdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *asdu_item;
	proto_tree *asdu_tree;
	int offset = 0;
	int end = (int)tvb_reported_length(tvb);
	uint8_t typ, vsq, cot;

	if (end < NARI_ASDU_HDR_LEN) {
		if (end > 0)
			proto_tree_add_item(tree, hf_raw, tvb, 0, end, ENC_NA);
		return;
	}

	asdu_item = proto_tree_add_item(tree, proto_nari_net_iec103, tvb, 0, end, ENC_NA);
	proto_item_set_text(asdu_item, "南自网络103 ASDU");
	asdu_tree = proto_item_add_subtree(asdu_item, ett_nari_asdu);

	typ = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(asdu_tree, hf_typeid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s",
		val_to_str_const(typ, asdu_type_vals, "ASDU%u"));
	offset++;

	vsq = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(asdu_tree, hf_vsq, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(asdu_tree, hf_vsq_sq, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(asdu_tree, hf_vsq_num, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;

	cot = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(asdu_tree, hf_cot, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	col_append_fstr(pinfo->cinfo, COL_INFO, " COT=%u", cot);
	offset++;

	proto_tree_add_item(asdu_tree, hf_asdu_addr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;

	proto_tree_add_item(asdu_tree, hf_fun, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;
	proto_tree_add_item(asdu_tree, hf_inf, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;

	switch (typ) {
	case 5:
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_col, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (end - offset >= 8) {
			proto_tree_add_zh_string(asdu_tree, hf_gen_desc, tvb, offset, 8);
			offset += 8;
		}
		if (end - offset >= 8) {
			proto_tree_add_zh_string(asdu_tree, hf_gen_desc, tvb, offset, 8);
			offset += 8;
		}
		if (end - offset >= 8) {
			proto_tree_add_zh_string(asdu_tree, hf_gen_desc, tvb, offset, 8);
			offset += 8;
		}
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
		dissect_generic_elements(tvb, pinfo, asdu_tree, &offset, end, false);
		break;
	case 20:
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_dco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		break;
	case 21:
		dissect_generic_elements(tvb, pinfo, asdu_tree, &offset, end, true);
		break;
	case 23:
		dissect_asdu23(asdu_tree, tvb, &offset, end, vsq);
		break;
	case 24:
	case 25:
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_tov, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_raw, tvb, offset, 2, ENC_NA);
			offset += 2;
		}
		break;
	case 26:
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_tov, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_acc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_rpv, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_rdv, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_rfa, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (end - offset >= 4) {
			proto_tree_add_item(asdu_tree, hf_raw, tvb, offset, 4, ENC_NA);
			offset += 4;
		}
		break;
	case 27:
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_tov, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_acc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (end - offset >= 4) {
			proto_tree_add_item(asdu_tree, hf_rpv, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
			proto_tree_add_item(asdu_tree, hf_rdv, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 4;
		}
		if (end - offset >= 8) {
			proto_tree_add_item(asdu_tree, hf_gen_gid_float, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
			proto_tree_add_item(asdu_tree, hf_gen_gid_float, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
		}
		break;
	case 28:
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_tov, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_acc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		break;
	case 29:
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_tov, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_acc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		dissect_asdu29_tags(asdu_tree, tvb, &offset, end);
		break;
	case 30:
		dissect_asdu30(asdu_tree, tvb, &offset, end);
		break;
	case 31:
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_tov, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_acc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_too, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_scn, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		break;
	default:
		expert_add_info(pinfo, asdu_item, &ei_asdu_unknown);
		break;
	}

	if (offset < end)
		proto_tree_add_item(asdu_tree, hf_raw, tvb, offset, end - offset, ENC_NA);
}

static int
dissect_nari_asdu_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *ti;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "南自网络103");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_nari_net_iec103, tvb, 0, -1, ENC_NA);
	proto_item_set_text(ti, "南自网络103规约");
	dissect_asdu(tvb, pinfo, tree);
	return tvb_captured_length(tvb);
}

static bool
nari_tcp_stream_looks_valid(tvbuff_t *tvb)
{
	unsigned remaining = tvb_reported_length(tvb);

	if (remaining < NARI_ASDU_HDR_LEN)
		return false;
	return is_plausible_nari_asdu_type(tvb_get_uint8(tvb, 0));
}

static int
dissect_nari_net_iec103_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	if (!nari_tcp_stream_looks_valid(tvb))
		return 0;

	tcp_dissect_pdus(tvb, pinfo, tree, true, NARI_ASDU_HDR_LEN,
		compute_nari_asdu_len, dissect_nari_asdu_pdu, data);
	return tvb_captured_length(tvb);
}

static int
dissect_nari_net_iec103_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *ti;
	proto_tree *udp_tree;
	int offset = 0;
	uint8_t time_flag;
	int end = (int)tvb_reported_length(tvb);

	if (end != NARI_UDP_BCAST_LEN)
		return 0;
	if (tvb_get_uint8(tvb, 0) != NARI_UDP_BCAST_MARK)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "南自网络103");
	col_set_str(pinfo->cinfo, COL_INFO, "主站在线广播");

	ti = proto_tree_add_item(tree, proto_nari_net_iec103, tvb, 0, end, ENC_NA);
	proto_item_set_text(ti, "南自网络103规约");
	udp_tree = proto_item_add_subtree(ti, ett_nari_udp);

	proto_tree_add_item(udp_tree, hf_udp_mark, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;
	time_flag = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(udp_tree, hf_udp_time_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;

	if (time_flag != 0) {
		if (end - offset >= 7)
			dissect_cp56time(tvb, &offset, udp_tree);
	} else if (end - offset >= 7) {
		proto_tree_add_item(udp_tree, hf_raw, tvb, offset, 7, ENC_NA);
		offset += 7;
	}

	if (end - offset >= NARI_NAME_FIELD_LEN) {
		proto_tree_add_item(udp_tree, hf_udp_name, tvb, offset,
			NARI_NAME_FIELD_LEN, ENC_ASCII);
		offset += NARI_NAME_FIELD_LEN;
	}

	if (offset < end)
		proto_tree_add_item(udp_tree, hf_udp_padding, tvb, offset, end - offset, ENC_NA);

	return end;
}

void
proto_register_nari_net_iec103(void)
{
	static hf_register_info hf[] = {
		{ &hf_typeid,
		  { "类型标识 (Type ID)", "nari_net_iec103.typeid", FT_UINT8, BASE_DEC,
		    VALS(asdu_type_vals), 0x0, NULL, HFILL }},
		{ &hf_vsq,
		  { "可变结构限定词 (VSQ)", "nari_net_iec103.vsq", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_vsq_sq,
		  { "顺序位 (SQ)", "nari_net_iec103.vsq.sq", FT_UINT8, BASE_DEC,
		    NULL, 0x80, NULL, HFILL }},
		{ &hf_vsq_num,
		  { "信息体数目 (Number of objects)", "nari_net_iec103.vsq.num", FT_UINT8, BASE_DEC,
		    NULL, 0x7F, NULL, HFILL }},
		{ &hf_cot,
		  { "传送原因 (COT)", "nari_net_iec103.cot", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_asdu_addr,
		  { "ASDU地址 (ASDU address)", "nari_net_iec103.asdu_addr", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_fun,
		  { "功能类型 (FUN)", "nari_net_iec103.fun", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_inf,
		  { "信息序号 (INF)", "nari_net_iec103.inf", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_dpi,
		  { "双点信息 (DPI)", "nari_net_iec103.dpi", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_scn,
		  { "扫描序号 (SCN)", "nari_net_iec103.scn", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_rii,
		  { "返回信息标识符 (RII)", "nari_net_iec103.rii", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_ngd,
		  { "通用数据集数目 (NGD)", "nari_net_iec103.ngd", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_ngd_cont,
		  { "后续标志 (NGD CONT)", "nari_net_iec103.ngd.cont", FT_UINT8, BASE_DEC,
		    NULL, 0x80, NULL, HFILL }},
		{ &hf_ngd_count,
		  { "数据集个数 (NGD count)", "nari_net_iec103.ngd.count", FT_UINT8, BASE_DEC,
		    NULL, 0x3F, NULL, HFILL }},
		{ &hf_nog,
		  { "通用对象数目 (NOG)", "nari_net_iec103.nog", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_raw,
		  { "原始数据 (Data)", "nari_net_iec103.data", FT_BYTES, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_entry,
		  { "通用分类元素 (Generic entry)", "nari_net_iec103.gen.entry_item", FT_NONE, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_cp56time,
		  { "时标 (CP56Time2a)", "nari_net_iec103.cp56time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_cp56time_ms,
		  { "毫秒 (Milliseconds)", "nari_net_iec103.cp56time.ms", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_cp56time_min,
		  { "分钟 (Minutes)", "nari_net_iec103.cp56time.min", FT_UINT8, BASE_DEC,
		    NULL, 0x3f, NULL, HFILL }},
		{ &hf_cp56time_iv,
		  { "无效标志 (IV)", "nari_net_iec103.cp56time.iv", FT_UINT8, BASE_DEC,
		    NULL, 0x80, NULL, HFILL }},
		{ &hf_cp56time_hour,
		  { "小时 (Hours)", "nari_net_iec103.cp56time.hour", FT_UINT8, BASE_DEC,
		    NULL, 0x1f, NULL, HFILL }},
		{ &hf_cp56time_su,
		  { "夏令时 (SU)", "nari_net_iec103.cp56time.su", FT_UINT8, BASE_DEC,
		    NULL, 0x80, NULL, HFILL }},
		{ &hf_cp56time_day,
		  { "日 (Day)", "nari_net_iec103.cp56time.day", FT_UINT8, BASE_DEC,
		    NULL, 0x1f, NULL, HFILL }},
		{ &hf_cp56time_dow,
		  { "星期 (Day of week)", "nari_net_iec103.cp56time.dow", FT_UINT8, BASE_DEC,
		    NULL, 0xe0, NULL, HFILL }},
		{ &hf_cp56time_month,
		  { "月 (Month)", "nari_net_iec103.cp56time.month", FT_UINT8, BASE_DEC,
		    NULL, 0x0f, NULL, HFILL }},
		{ &hf_cp56time_year,
		  { "年 (Year)", "nari_net_iec103.cp56time.year", FT_UINT8, BASE_DEC,
		    NULL, 0x7f, NULL, HFILL }},
		{ &hf_gen_gin_group,
		  { "组号 (GIN group)", "nari_net_iec103.gen.group", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_gin_entry,
		  { "条目号 (GIN entry)", "nari_net_iec103.gen.entry", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_kod,
		  { "描述类别 (KOD)", "nari_net_iec103.gen.kod", FT_UINT8, BASE_HEX,
		    VALS(kod_vals), 0x0, NULL, HFILL }},
		{ &hf_gen_datatype,
		  { "数据类型 (Data type)", "nari_net_iec103.gen.datatype", FT_UINT8, BASE_DEC,
		    VALS(gdd_type_vals), 0x0, NULL, HFILL }},
		{ &hf_gen_datasize,
		  { "数据宽度 (Data size)", "nari_net_iec103.gen.datasize", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_datanumber,
		  { "数据数目 (Data number)", "nari_net_iec103.gen.datanumber", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_gid,
		  { "通用标识数据 (GID)", "nari_net_iec103.gen.gid", FT_BYTES, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_desc,
		  { "描述 (Description)", "nari_net_iec103.gen.desc", FT_STRING, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_gid_ui,
		  { "无符号整数 (GID UI)", "nari_net_iec103.gen.gid_ui", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_gid_float,
		  { "浮点数 (GID R32.23)", "nari_net_iec103.gen.gid_float", FT_FLOAT, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_col,
		  { "兼容级别 (COL)", "nari_net_iec103.col", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_dco,
		  { "双命令 (DCO)", "nari_net_iec103.dco", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_tov,
		  { "扰动值类型 (TOV)", "nari_net_iec103.tov", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_fan,
		  { "故障序号 (FAN)", "nari_net_iec103.fan", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_acc,
		  { "实际通道 (ACC)", "nari_net_iec103.acc", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_ndv,
		  { "扰动值个数 (NDV)", "nari_net_iec103.ndv", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nfe,
		  { "电网故障序号 (NFE)", "nari_net_iec103.nfe", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_sdv,
		  { "扰动值 (SDV)", "nari_net_iec103.sdv", FT_BYTES, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_nof,
		  { "电网故障序号 (NOF)", "nari_net_iec103.nof", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_noc,
		  { "通道数目 (NOC)", "nari_net_iec103.noc", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_noe,
		  { "电网故障数目 (NOE)", "nari_net_iec103.noe", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_too,
		  { "命令类型 (TOO)", "nari_net_iec103.too", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_rpv,
		  { "额定一次值 (RPV)", "nari_net_iec103.rpv", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_rdv,
		  { "额定二次值 (RDV)", "nari_net_iec103.rdv", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_rfa,
		  { "参比因子 (RFA)", "nari_net_iec103.rfa", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_ret,
		  { "相对时间 (RET)", "nari_net_iec103.ret", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_dist_entry,
		  { "扰动条目 (Disturbance entry)", "nari_net_iec103.dist.entry", FT_NONE, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_tag,
		  { "状态变位标志 (Tag)", "nari_net_iec103.tag", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_udp_mark,
		  { "广播标识", "nari_net_iec103.udp.mark", FT_UINT8, BASE_HEX,
		    NULL, 0x0, "固定为FFH", HFILL }},
		{ &hf_udp_time_flag,
		  { "时标标志", "nari_net_iec103.udp.time_flag", FT_BOOLEAN, 8,
		    TFS(&tfs_time_flag_set), 0x0, NULL, HFILL }},
		{ &hf_udp_name,
		  { "主站名称 (Master name)", "nari_net_iec103.udp.name", FT_STRING, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_udp_padding,
		  { "填充 (Padding)", "nari_net_iec103.udp.padding", FT_BYTES, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
	};

	static int *ett[] = {
		&ett_nari_net_iec103,
		&ett_nari_asdu,
		&ett_nari_cp56time,
		&ett_nari_gen,
		&ett_nari_gen_entry,
		&ett_nari_dist,
		&ett_nari_dist_entry,
		&ett_nari_udp,
	};

	static ei_register_info ei[] = {
		{ &ei_asdu_truncated,
		  { "nari_net_iec103.asdu_truncated", PI_MALFORMED, PI_WARN,
		    "ASDU truncated", EXPFILL }},
		{ &ei_asdu_unknown,
		  { "nari_net_iec103.asdu_unknown", PI_UNDECODED, PI_NOTE,
		    "Unknown ASDU type", EXPFILL }},
	};

	expert_module_t *expert_mod;

	proto_nari_net_iec103 = proto_register_protocol(
		"南自网络103规约",
		"南自网络103",
		"nari_net_iec103");

	proto_register_field_array(proto_nari_net_iec103, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_mod = expert_register_protocol(proto_nari_net_iec103);
	expert_register_field_array(expert_mod, ei, array_length(ei));

	prefs_register_protocol(proto_nari_net_iec103, NULL);

	nari_net_iec103_tcp_handle = register_dissector("nari_net_iec103",
		dissect_nari_net_iec103_tcp, proto_nari_net_iec103);
	nari_net_iec103_udp_handle = register_dissector("nari_net_iec103_udp",
		dissect_nari_net_iec103_udp, proto_nari_net_iec103);
}

void
proto_reg_handoff_nari_net_iec103(void)
{
	dissector_add_uint_with_preference("tcp.port", NARI_NET_IEC103_TCP_PORT,
		nari_net_iec103_tcp_handle);
	dissector_add_uint_with_preference("udp.port", NARI_NET_IEC103_UDP_PORT,
		nari_net_iec103_udp_handle);
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
