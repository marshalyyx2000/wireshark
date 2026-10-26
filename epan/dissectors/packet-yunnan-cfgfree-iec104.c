/* packet-yunnan-cfgfree-iec104.c
 *
 * Yunnan (南网) configuration-free master-substation protocol over IEC 60870-5-104.
 * APCI: 68H + uint16 LE length + 4-byte control (CMH_104_Len2).
 * ASDU: per 保信子站免配置技术方案 (20251120) chapter 4.
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

#include "packet-tcp.h"

void proto_register_yunnan_cfgfree_iec104(void);
void proto_reg_handoff_yunnan_cfgfree_iec104(void);

#define YN_CFGFREE_PORT_MAINTAIN 2405
#define YN_CFGFREE_PORT_BUSINESS 2404

#define APCI_START           0x68
#define APCI_CTRL_LEN        4
#define APCI_HDR_LEN         3
#define APDU_MIN_LEN         4
#define APDU_MAX_BODY        2048
#define FILENAME_LEN         100

#define I_TYPE 0
#define S_TYPE 1
#define U_TYPE 3

#define HDR_ADDR2 0
#define HDR_ADDR1_RII 1

static int proto_yunnan_cfgfree_iec104;
static dissector_handle_t yunnan_cfgfree_iec104_handle;

static int ett_yunnan;
static int ett_yunnan_apci;
static int ett_yunnan_apci_len;
static int ett_yunnan_apci_ctrl;
static int ett_yunnan_asdu;
static int ett_yunnan_cp56time;
static int ett_yunnan_data_pkt;

static int hf_start;
static int hf_apdulen;
static int hf_apdulen_lo;
static int hf_apdulen_hi;
static int hf_apdulen_calc;
static int hf_apci_ctrl;
static int hf_apci_ns;
static int hf_apci_nr;
static int hf_apcitype;
static int hf_apciutype;
static int hf_junk;
static int hf_typeid;
static int hf_vsq;
static int hf_vsq_sq;
static int hf_vsq_num;
static int hf_cot;
static int hf_asdu_addr;
static int hf_asdu_addr2;
static int hf_fun;
static int hf_inf;
static int hf_rii;
static int hf_pad;
static int hf_device_no;
static int hf_frame_seq;
static int hf_protyp;
static int hf_cmdtyp;
static int hf_reserved;
static int hf_rst;
static int hf_pkt_type;
static int hf_pkt_len;
static int hf_encap_data;
static int hf_ctrl_cmd;
static int hf_filename;
static int hf_follow_flag;
static int hf_file_offset;
static int hf_file_len;
static int hf_file_time;
static int hf_file_data;
static int hf_mes_count;
static int hf_xfer_size;
static int hf_ack_flag;
static int hf_recv_len;
static int hf_target_ip;
static int hf_target_port;
static int hf_capture_ctrl;
static int hf_query_start;
static int hf_query_end;
static int hf_file_num_l;
static int hf_file_num_h;
static int hf_raw;

static expert_field ei_apdu_bad_len;
static expert_field ei_asdu_truncated;

static bool pref_heuristic_2404 = true;
static range_t *pref_tcp_ports = NULL;

static const value_string apci_types[] = {
	{ I_TYPE, "信息帧(I)" },
	{ S_TYPE, "监视帧(S)" },
	{ U_TYPE, "控制帧(U)" },
	{ 0, NULL }
};

static const value_string u_func_vals[] = {
	{ 0x04, "启动数据传输激活" },
	{ 0x08, "启动数据传输确认" },
	{ 0x10, "停止数据传输激活" },
	{ 0x20, "停止数据传输确认" },
	{ 0x40, "测试帧激活" },
	{ 0x80, "测试帧确认" },
	{ 0, NULL }
};

static const value_string asdu_type_vals[] = {
	{ 0x65, "ASDU101 召一般文件列表" },
	{ 0x66, "ASDU102 上送一般文件列表" },
	{ 0x67, "ASDU103 召文件内容" },
	{ 0x68, "ASDU104 上送文件内容" },
	{ 0x69, "ASDU105 下装文件基本信息" },
	{ 0x6A, "ASDU106 确认下装文件基本信息" },
	{ 0x6B, "ASDU107 下装文件内容" },
	{ 0x6C, "ASDU108 确认下装文件内容" },
	{ 0xC8, "ASDU200 主站对下传输(与装置通讯)" },
	{ 0xC9, "ASDU201 对上传输装置内容" },
	{ 0xCA, "ASDU202 远程运维控制命令" },
	{ 0xCB, "ASDU203 远程运维控制应答" },
	{ 0xCC, "ASDU204 抓包子站与装置TCP报文" },
	{ 0xCD, "ASDU205 抓包应答" },
	{ 0, NULL }
};

static const value_string cmdtyp_vals[] = {
	{ 0, "建立链路" },
	{ 1, "关闭链路" },
	{ 2, "转发数据包" },
	{ 0, NULL }
};

static const value_string rst_vals[] = {
	{ 0, "成功" },
	{ 1, "失败" },
	{ 0, NULL }
};

static const value_string ctrl_cmd_vals[] = {
	{ 0x01, "生效103配置文件" },
	{ 0x02, "生效61850配置文件" },
	{ 0x03, "备份配置文件" },
	{ 0x04, "还原配置文件" },
	{ 0x05, "备份程序" },
	{ 0x06, "更新程序" },
	{ 0x07, "还原程序" },
	{ 0x08, "更新系统补丁" },
	{ 0x09, "系统重启" },
	{ 0x0A, "备份子站私有运行日志" },
	{ 0x0B, "私有配置生效" },
	{ 0, NULL }
};

static const value_string capture_ctrl_vals[] = {
	{ 0, "停止抓包" },
	{ 1, "启动抓包" },
	{ 0, NULL }
};

static const value_string protyp_vals[] = {
	{ 1,  "DL/T860" },
	{ 2,  "南瑞继保网络103" },
	{ 3,  "四方UDP 103" },
	{ 4,  "深瑞网络103" },
	{ 5,  "许继网络103" },
	{ 6,  "南自网络103" },
	{ 7,  "华东网络103" },
	{ 8,  "浙江网络103" },
	{ 9,  "串口103" },
	{ 10, "许继串口103" },
	{ 11, "南自串口103" },
	{ 12, "南瑞串口103" },
	{ 0, NULL }
};

static const true_false_string tfs_apci_set = { "置位", "未置位" };

static int
trim_nul_len(tvbuff_t *tvb, int offset, int len)
{
	while (len > 0 && tvb_get_uint8(tvb, offset + len - 1) == 0)
		len--;
	return len;
}

static void
proto_tree_add_zh_string(proto_tree *tree, int hfindex, tvbuff_t *tvb, int offset, int len)
{
	int slim = trim_nul_len(tvb, offset, len);
	if (slim <= 0) {
		proto_tree_add_string(tree, hfindex, tvb, offset, len, "");
		return;
	}
	proto_tree_add_item(tree, hfindex, tvb, offset, slim, ENC_GB18030);
}

static bool
is_yunnan_asdu_type(uint8_t typ)
{
	if (typ >= 0x65 && typ <= 0x6C)
		return true;
	if (typ >= 0xC8 && typ <= 0xCD)
		return true;
	return false;
}

static int
asdu_header_mode(uint8_t typ)
{
	if (typ == 0xC8 || typ == 0xC9)
		return HDR_ADDR2;
	return HDR_ADDR1_RII;
}

static bool
needs_pad_byte(uint8_t typ)
{
	return (typ == 0x69 || typ == 0x6B || typ == 0xCA);
}

static bool
try_apdu_at(tvbuff_t *tvb, int base, unsigned off, unsigned remaining,
	unsigned *out_body, unsigned *out_total, bool check_asdu)
{
	uint8_t ctrl0;
	unsigned body;

	if (off + 2 >= remaining && remaining - off < APCI_HDR_LEN)
		return false;
	if (tvb_get_uint8(tvb, base + (int)off) != APCI_START)
		return false;
	if (off + 2 >= remaining) {
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
		if (check_asdu && body > APCI_CTRL_LEN
				&& off + APCI_HDR_LEN + APCI_CTRL_LEN < remaining) {
			uint8_t typ = tvb_get_uint8(tvb,
				base + (int)off + APCI_HDR_LEN + APCI_CTRL_LEN);
			if (!is_yunnan_asdu_type(typ))
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

	ti = proto_tree_add_time(tree, hf_file_time, tvb, *offset, 7, &datetime);
	tm_tree = proto_item_add_subtree(ti, ett_yunnan_cp56time);
	proto_tree_add_uint_format(tm_tree, hf_file_time, tvb, *offset, 2, ms,
		"毫秒: %u", ms);
	proto_tree_add_uint_format(tm_tree, hf_file_time, tvb, *offset + 2, 1, min,
		"分: %u", min);
	proto_tree_add_uint_format(tm_tree, hf_file_time, tvb, *offset + 3, 1, hour,
		"时: %u", hour);
	proto_tree_add_uint_format(tm_tree, hf_file_time, tvb, *offset + 4, 1, day_dow,
		"日/星期: %u", day_dow);
	proto_tree_add_uint_format(tm_tree, hf_file_time, tvb, *offset + 5, 1, month,
		"月: %u", month);
	proto_tree_add_uint_format(tm_tree, hf_file_time, tvb, *offset + 6, 1, year,
		"年: %u", year);
	*offset += 7;
}

static void
dissect_ms200_201(proto_tree *tree, tvbuff_t *tvb, int *offset, int end, uint8_t typ)
{
	uint8_t cmdtyp;

	if (*offset >= end)
		return;

	proto_tree_add_item(tree, hf_rii, tvb, *offset, 1, ENC_NA);
	(*offset)++;

	if (end - *offset < 2)
		return;
	proto_tree_add_item(tree, hf_device_no, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
	*offset += 2;

	if (end - *offset < 2)
		return;
	proto_tree_add_item(tree, hf_frame_seq, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
	*offset += 2;

	if (*offset >= end)
		return;
	proto_tree_add_item(tree, hf_protyp, tvb, *offset, 1, ENC_NA);
	(*offset)++;

	if (*offset >= end)
		return;
	cmdtyp = tvb_get_uint8(tvb, *offset);
	proto_tree_add_item(tree, hf_cmdtyp, tvb, *offset, 1, ENC_NA);
	(*offset)++;

	if (end - *offset >= 4) {
		proto_tree_add_item(tree, hf_reserved, tvb, *offset, 4, ENC_NA);
		*offset += 4;
	}

	if (typ == 0xC9 && *offset < end) {
		proto_tree_add_item(tree, hf_rst, tvb, *offset, 1, ENC_NA);
		(*offset)++;
	}

	if (cmdtyp == 2 && *offset < end) {
		proto_item *pi;
		proto_tree *pt;
		int pkt_len;

		if (*offset >= end)
			return;
		proto_tree_add_item(tree, hf_pkt_type, tvb, *offset, 1, ENC_NA);
		(*offset)++;

		if (end - *offset < 4)
			return;
		pkt_len = (int)tvb_get_letohl(tvb, *offset);
		proto_tree_add_uint(tree, hf_pkt_len, tvb, *offset, 4, pkt_len);
		*offset += 4;

		if (pkt_len > 0 && *offset < end) {
			int avail = end - *offset;
			int show = pkt_len < avail ? pkt_len : avail;
			pi = proto_tree_add_item(tree, hf_encap_data, tvb, *offset, show, ENC_NA);
			pt = proto_item_add_subtree(pi, ett_yunnan_data_pkt);
			proto_tree_add_item(pt, hf_raw, tvb, *offset, show, ENC_NA);
			*offset += show;
		}
	}
}

static void
dissect_file_upload_call(proto_tree *tree, tvbuff_t *tvb, int *offset, int end)
{
	if (end - *offset >= 14) {
		dissect_cp56time(tvb, offset, tree);
		dissect_cp56time(tvb, offset, tree);
	}
	if (end - *offset >= FILENAME_LEN)
		proto_tree_add_zh_string(tree, hf_filename, tvb, *offset, FILENAME_LEN);
	if (end - *offset >= FILENAME_LEN)
		*offset += FILENAME_LEN;
}

static void
dissect_file_list_entry(proto_tree *tree, tvbuff_t *tvb, int *offset, int end)
{
	int name_len;

	if (end - *offset >= FILENAME_LEN) {
		name_len = FILENAME_LEN;
		proto_tree_add_zh_string(tree, hf_filename, tvb, *offset, name_len);
		*offset += FILENAME_LEN;
	}
	if (end - *offset >= 7)
		dissect_cp56time(tvb, offset, tree);
	if (end - *offset >= 4)
		proto_tree_add_item(tree, hf_file_len, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
	if (end - *offset >= 4)
		*offset += 4;
}

static void
dissect_file_upload_content(proto_tree *tree, tvbuff_t *tvb, int *offset, int end)
{
	if (end - *offset >= FILENAME_LEN) {
		proto_tree_add_zh_string(tree, hf_filename, tvb, *offset, FILENAME_LEN);
		*offset += FILENAME_LEN;
	}
	if (end - *offset >= 4) {
		proto_tree_add_item(tree, hf_file_offset, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
		*offset += 4;
	}
	if (*offset < end)
		proto_tree_add_item(tree, hf_file_data, tvb, *offset, end - *offset, ENC_NA);
}

static void
dissect_file_download_info(proto_tree *tree, tvbuff_t *tvb, int *offset, int end)
{
	if (*offset < end) {
		proto_tree_add_item(tree, hf_mes_count, tvb, *offset, 1, ENC_NA);
		(*offset)++;
	}
	if (end - *offset >= FILENAME_LEN) {
		proto_tree_add_zh_string(tree, hf_filename, tvb, *offset, FILENAME_LEN);
		*offset += FILENAME_LEN;
	}
	if (end - *offset >= 1) {
		proto_tree_add_item(tree, hf_xfer_size, tvb, *offset, 1, ENC_NA);
		(*offset)++;
	}
	if (end - *offset >= FILENAME_LEN) {
		proto_tree_add_zh_string(tree, hf_filename, tvb, *offset, FILENAME_LEN);
		*offset += FILENAME_LEN;
	}
	if (end - *offset >= 7)
		dissect_cp56time(tvb, offset, tree);
	if (end - *offset >= 4)
		proto_tree_add_item(tree, hf_file_len, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
	if (end - *offset >= 4)
		*offset += 4;
}

static void
dissect_file_download_chunk(proto_tree *tree, tvbuff_t *tvb, int *offset, int end)
{
	if (*offset < end) {
		proto_tree_add_item(tree, hf_follow_flag, tvb, *offset, 1, ENC_NA);
		(*offset)++;
	}
	if (end - *offset >= 4) {
		proto_tree_add_item(tree, hf_file_offset, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
		*offset += 4;
	}
	if (*offset < end)
		proto_tree_add_item(tree, hf_file_data, tvb, *offset, end - *offset, ENC_NA);
}

static void
dissect_file_download_ack(proto_tree *tree, tvbuff_t *tvb, int *offset, int end)
{
	if (*offset < end) {
		proto_tree_add_item(tree, hf_ack_flag, tvb, *offset, 1, ENC_NA);
		(*offset)++;
	}
	if (end - *offset >= 4)
		proto_tree_add_item(tree, hf_recv_len, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
}

static void
dissect_tcpdump_body(proto_tree *tree, tvbuff_t *tvb, int *offset, int end)
{
	uint32_t ip_raw;
	gchar ip_str[16];

	if (end - *offset < 7)
		return;

	ip_raw = tvb_get_letohl(tvb, *offset);
	g_snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
		(ip_raw >> 24) & 0xff, (ip_raw >> 16) & 0xff,
		(ip_raw >> 8) & 0xff, ip_raw & 0xff);
	proto_tree_add_ipv4_format_value(tree, hf_target_ip, tvb, *offset, 4,
		ip_raw, "%s", ip_str);
	*offset += 4;

	proto_tree_add_item(tree, hf_target_port, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
	*offset += 2;

	proto_tree_add_item(tree, hf_capture_ctrl, tvb, *offset, 1, ENC_NA);
	(*offset)++;
}

static void
dissect_asdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *asdu_item;
	proto_tree *asdu_tree;
	int offset = 0;
	int end = (int)tvb_reported_length(tvb);
	uint8_t typ, cot, fun, inf, vsq_num;
	int hdr_mode;

	if (end < 6) {
		if (end > 0)
			proto_tree_add_item(tree, hf_raw, tvb, 0, end, ENC_NA);
		return;
	}

	typ = tvb_get_uint8(tvb, 0);
	hdr_mode = asdu_header_mode(typ);

	asdu_item = proto_tree_add_item(tree, proto_yunnan_cfgfree_iec104, tvb, 0, end, ENC_NA);
	proto_item_set_text(asdu_item, "云南免配置主子站 ASDU");
	asdu_tree = proto_item_add_subtree(asdu_item, ett_yunnan_asdu);

	proto_tree_add_item(asdu_tree, hf_typeid, tvb, offset, 1, ENC_NA);
	col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s",
		val_to_str_const(typ, asdu_type_vals, "ASDU"));
	offset++;

	vsq_num = tvb_get_uint8(tvb, offset) & 0x7f;
	proto_tree_add_item(asdu_tree, hf_vsq, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(asdu_tree, hf_vsq_sq, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(asdu_tree, hf_vsq_num, tvb, offset, 1, ENC_NA);
	offset++;

	cot = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(asdu_tree, hf_cot, tvb, offset, 1, ENC_NA);
	col_append_fstr(pinfo->cinfo, COL_INFO, " COT=%u", cot);
	offset++;

	if (hdr_mode == HDR_ADDR2) {
		proto_tree_add_item(asdu_tree, hf_asdu_addr2, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
	} else {
		proto_tree_add_item(asdu_tree, hf_asdu_addr, tvb, offset, 1, ENC_NA);
		offset++;
	}

	fun = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(asdu_tree, hf_fun, tvb, offset, 1, ENC_NA);
	offset++;

	inf = tvb_get_uint8(tvb, offset);
	if (typ == 0xCA || typ == 0xCB)
		proto_tree_add_item(asdu_tree, hf_ctrl_cmd, tvb, offset, 1, ENC_NA);
	else
		proto_tree_add_item(asdu_tree, hf_inf, tvb, offset, 1, ENC_NA);
	offset++;

	if (hdr_mode == HDR_ADDR1_RII) {
		proto_tree_add_item(asdu_tree, hf_rii, tvb, offset, 1, ENC_NA);
		offset++;
		if (needs_pad_byte(typ) && offset < end) {
			proto_tree_add_item(asdu_tree, hf_pad, tvb, offset, 1, ENC_NA);
			offset++;
		}
	}

	switch (typ) {
	case 0xC8:
	case 0xC9:
		dissect_ms200_201(asdu_tree, tvb, &offset, end, typ);
		break;
	case 0xCA:
		/* 运维生效命令可能在填充后再带 1 字节 RII 副本 */
		if (offset < end)
			proto_tree_add_item(asdu_tree, hf_rii, tvb, offset, 1, ENC_NA);
		break;
	case 0xCB:
		break;
	case 0x65:
		dissect_file_upload_call(asdu_tree, tvb, &offset, end);
		break;
	case 0x66:
		if (offset < end) {
			proto_tree_add_item(asdu_tree, hf_follow_flag, tvb, offset, 1, ENC_NA);
			offset++;
		}
		if (offset < end)
			proto_tree_add_item(asdu_tree, hf_file_num_l, tvb, offset, 1, ENC_NA);
		if (offset + 1 < end)
			proto_tree_add_item(asdu_tree, hf_file_num_h, tvb, offset + 1, 1, ENC_NA);
		if (offset + 2 <= end)
			offset += 2;
		if (end - offset >= 14) {
			dissect_cp56time(tvb, &offset, asdu_tree);
			dissect_cp56time(tvb, &offset, asdu_tree);
		}
		while (offset + FILENAME_LEN + 11 <= end) {
			dissect_file_list_entry(asdu_tree, tvb, &offset, end);
		}
		break;
	case 0x67:
		if (end - offset >= FILENAME_LEN) {
			proto_tree_add_zh_string(asdu_tree, hf_filename, tvb, offset, FILENAME_LEN);
			offset += FILENAME_LEN;
		}
		if (end - offset >= 4)
			proto_tree_add_item(asdu_tree, hf_file_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		break;
	case 0x68:
		dissect_file_upload_content(asdu_tree, tvb, &offset, end);
		break;
	case 0x69:
	case 0x6A:
		dissect_file_download_info(asdu_tree, tvb, &offset, end);
		break;
	case 0x6B:
	case 0x6C:
		if (typ == 0x6B)
			dissect_file_download_chunk(asdu_tree, tvb, &offset, end);
		else
			dissect_file_download_ack(asdu_tree, tvb, &offset, end);
		break;
	case 0xCC:
	case 0xCD:
		dissect_tcpdump_body(asdu_tree, tvb, &offset, end);
		break;
	default:
		break;
	}

	if (offset < end)
		proto_tree_add_item(asdu_tree, hf_raw, tvb, offset, end - offset, ENC_NA);
}

static uint8_t
dissect_apci_control(proto_tree *apci_tree, tvbuff_t *tvb, int offset, wmem_strbuf_t *out_info)
{
	uint8_t b1 = tvb_get_uint8(tvb, offset);
	uint8_t b2 = tvb_get_uint8(tvb, offset + 1);
	uint8_t b3 = tvb_get_uint8(tvb, offset + 2);
	uint8_t b4 = tvb_get_uint8(tvb, offset + 3);
	uint8_t type;
	uint16_t ns, nr;

	if ((b1 & 0x01) == 0)
		type = I_TYPE;
	else
		type = b1 & 0x03;

	proto_tree_add_item(apci_tree, hf_apci_ctrl, tvb, offset, 4, ENC_NA);

	if (type == I_TYPE) {
		ns = (uint16_t)((b1 >> 1) | ((uint16_t)b2 << 7));
		nr = (uint16_t)((b3 >> 1) | ((uint16_t)b4 << 7));
		proto_tree_add_uint(apci_tree, hf_apci_ns, tvb, offset, 2, ns);
		proto_tree_add_uint(apci_tree, hf_apci_nr, tvb, offset + 2, 2, nr);
		proto_tree_add_uint(apci_tree, hf_apcitype, tvb, offset, 1, I_TYPE);
		wmem_strbuf_append_printf(out_info, "信息帧(I) N(S)=%u N(R)=%u", ns, nr);
	} else if (type == S_TYPE) {
		nr = (uint16_t)((b3 >> 1) | ((uint16_t)b4 << 7));
		proto_tree_add_uint(apci_tree, hf_apci_nr, tvb, offset + 2, 2, nr);
		proto_tree_add_uint(apci_tree, hf_apcitype, tvb, offset, 1, S_TYPE);
		wmem_strbuf_append_printf(out_info, "监视帧(S) N(R)=%u", nr);
	} else {
		proto_tree_add_uint(apci_tree, hf_apciutype, tvb, offset, 1, b1 & 0xfc);
		wmem_strbuf_append_printf(out_info, "控制帧(U) %s",
			val_to_str_const(b1 & 0xfc, u_func_vals, "未知"));
	}
	return type;
}

static unsigned
get_yunnan_apdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	unsigned body, total;

	if (try_apdu_at(tvb, 0, (unsigned)offset, tvb_reported_length(tvb), &body, &total, true))
		return total - (unsigned)offset;
	return 0;
}

static int
dissect_yunnan_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
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

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "云南免配置104");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_yunnan_cfgfree_iec104, tvb, 0, -1, ENC_NA);
	proto_item_set_text(ti, "云南免配置主子站104规约");
	apci_tree = proto_item_add_subtree(ti, ett_yunnan_apci);

	for (off = 0; (int)off + 2 < tcp_len; off++) {
		if (try_apdu_at(tvb, 0, off, (unsigned)tcp_len, &body, &total, true)) {
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

	proto_tree_add_uint_format_value(apci_tree, hf_start, tvb, offset, 1, APCI_START,
		"0x%02x", APCI_START);
	offset++;

	len_lo = tvb_get_uint8(tvb, offset);
	len_hi = tvb_get_uint8(tvb, offset + 1);
	len_ti = proto_tree_add_uint_format_value(apci_tree, hf_apdulen_calc, tvb, offset, 2, body,
		"%u (= 低字节%u + 高字节%u×256, 含控制域+ASDU)",
		body, len_lo, len_hi);
	len_tree = proto_item_add_subtree(len_ti, ett_yunnan_apci_len);
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

	type = dissect_apci_control(apci_tree, tvb, offset, res);
	col_append_str(pinfo->cinfo, COL_INFO, wmem_strbuf_get_str(res));
	proto_item_append_text(ti, ": %s", wmem_strbuf_get_str(res));
	offset += APCI_CTRL_LEN;

	if (type == I_TYPE && body > APCI_CTRL_LEN) {
		int asdu_len = (int)body - APCI_CTRL_LEN;
		if (offset + asdu_len <= tcp_len) {
			tvbuff_t *asdu_tvb = tvb_new_subset_length(tvb, offset, asdu_len);
			dissect_asdu(asdu_tvb, pinfo, tree);
		} else {
			expert_add_info(pinfo, ti, &ei_asdu_truncated);
		}
	}

	return tvb_captured_length(tvb);
}

static bool
looks_like_yunnan_first_apdu(tvbuff_t *tvb)
{
	unsigned body, total;
	uint8_t typ;

	if (!try_apdu_at(tvb, 0, 0, tvb_reported_length(tvb), &body, &total, false))
		return false;
	if (body <= APCI_CTRL_LEN)
		return true;
	typ = tvb_get_uint8(tvb, APCI_HDR_LEN + APCI_CTRL_LEN);
	return is_yunnan_asdu_type(typ);
}

static int
dissect_yunnan_cfgfree_iec104_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	unsigned remaining = tvb_reported_length(tvb);

	if (remaining < APCI_HDR_LEN)
		return 0;

	if (pinfo->match_uint == YN_CFGFREE_PORT_BUSINESS && pref_heuristic_2404) {
		if (!looks_like_yunnan_first_apdu(tvb))
			return 0;
	}

	tcp_dissect_pdus(tvb, pinfo, tree, true, APCI_HDR_LEN + APCI_CTRL_LEN,
		get_yunnan_apdu_len, dissect_yunnan_apdu, data);
	return tvb_captured_length(tvb);
}

static void
yunnan_cfgfree_prefs_apply(void)
{
	static bool ports_registered = false;

	if (ports_registered) {
		dissector_delete_uint_range("tcp.port", pref_tcp_ports, yunnan_cfgfree_iec104_handle);
	} else {
		ports_registered = true;
	}

	dissector_add_uint_range("tcp.port", pref_tcp_ports, yunnan_cfgfree_iec104_handle);
}

void
proto_register_yunnan_cfgfree_iec104(void)
{
	static hf_register_info hf[] = {
		{ &hf_start, { "启动字符", "yunnan_cfgfree_iec104.start", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_apdulen, { "APDU长度", "yunnan_cfgfree_iec104.apdulen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_apdulen_lo, { "长度低字节", "yunnan_cfgfree_iec104.apdulen.lo", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_apdulen_hi, { "长度高字节", "yunnan_cfgfree_iec104.apdulen.hi", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_apdulen_calc, { "APDU长度", "yunnan_cfgfree_iec104.apdulen.calc", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_apci_ctrl, { "控制域", "yunnan_cfgfree_iec104.apci.ctrl", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_apci_ns, { "发送序号N(S)", "yunnan_cfgfree_iec104.apci.ns", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_apci_nr, { "接收序号N(R)", "yunnan_cfgfree_iec104.apci.nr", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_apcitype, { "帧类型", "yunnan_cfgfree_iec104.apci.type", FT_UINT32, BASE_HEX, VALS(apci_types), 0x0, NULL, HFILL }},
		{ &hf_apciutype, { "U功能", "yunnan_cfgfree_iec104.apci.utype", FT_UINT8, BASE_HEX, VALS(u_func_vals), 0x0, NULL, HFILL }},
		{ &hf_junk, { "前导无效数据", "yunnan_cfgfree_iec104.junk", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_typeid, { "类型标识", "yunnan_cfgfree_iec104.typeid", FT_UINT8, BASE_DEC, VALS(asdu_type_vals), 0x0, NULL, HFILL }},
		{ &hf_vsq, { "可变结构限定词", "yunnan_cfgfree_iec104.vsq", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_vsq_sq, { "顺序位(SQ)", "yunnan_cfgfree_iec104.vsq.sq", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
		{ &hf_vsq_num, { "信息体数目", "yunnan_cfgfree_iec104.vsq.num", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }},
		{ &hf_cot, { "传送原因", "yunnan_cfgfree_iec104.cot", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_asdu_addr, { "ASDU地址", "yunnan_cfgfree_iec104.asdu_addr", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_asdu_addr2, { "ASDU地址", "yunnan_cfgfree_iec104.asdu_addr2", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_fun, { "功能类型(FUN)", "yunnan_cfgfree_iec104.fun", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_inf, { "信息序号(INF)", "yunnan_cfgfree_iec104.inf", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_rii, { "返回信息标识符(RII)", "yunnan_cfgfree_iec104.rii", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_pad, { "填充字节", "yunnan_cfgfree_iec104.pad", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_device_no, { "装置编号", "yunnan_cfgfree_iec104.device_no", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_frame_seq, { "帧序号", "yunnan_cfgfree_iec104.frame_seq", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_protyp, { "规约类型", "yunnan_cfgfree_iec104.protyp", FT_UINT8, BASE_DEC, VALS(protyp_vals), 0x0, NULL, HFILL }},
		{ &hf_cmdtyp, { "命令类型", "yunnan_cfgfree_iec104.cmdtyp", FT_UINT8, BASE_DEC, VALS(cmdtyp_vals), 0x0, NULL, HFILL }},
		{ &hf_reserved, { "保留", "yunnan_cfgfree_iec104.reserved", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_rst, { "结果", "yunnan_cfgfree_iec104.rst", FT_UINT8, BASE_DEC, VALS(rst_vals), 0x0, NULL, HFILL }},
		{ &hf_pkt_type, { "包类型", "yunnan_cfgfree_iec104.pkt_type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_pkt_len, { "包长度", "yunnan_cfgfree_iec104.pkt_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_encap_data, { "封装数据", "yunnan_cfgfree_iec104.encap_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_ctrl_cmd, { "控制命令类型", "yunnan_cfgfree_iec104.ctrl_cmd", FT_UINT8, BASE_HEX, VALS(ctrl_cmd_vals), 0x0, NULL, HFILL }},
		{ &hf_filename, { "文件名", "yunnan_cfgfree_iec104.filename", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_follow_flag, { "后续位标志", "yunnan_cfgfree_iec104.follow_flag", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_file_offset, { "起始传输位置", "yunnan_cfgfree_iec104.file_offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_file_len, { "文件长度", "yunnan_cfgfree_iec104.file_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_file_time, { "文件时间", "yunnan_cfgfree_iec104.file_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }},
		{ &hf_file_data, { "文件数据", "yunnan_cfgfree_iec104.file_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_mes_count, { "确认帧数", "yunnan_cfgfree_iec104.mes_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_xfer_size, { "传输标志/窗口", "yunnan_cfgfree_iec104.xfer_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_ack_flag, { "确认标志", "yunnan_cfgfree_iec104.ack_flag", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_recv_len, { "已接收有效长度", "yunnan_cfgfree_iec104.recv_len", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_target_ip, { "目标IP", "yunnan_cfgfree_iec104.target_ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_target_port, { "目标端口", "yunnan_cfgfree_iec104.target_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_capture_ctrl, { "启停控制", "yunnan_cfgfree_iec104.capture_ctrl", FT_UINT8, BASE_DEC, VALS(capture_ctrl_vals), 0x0, NULL, HFILL }},
		{ &hf_query_start, { "查询起始时间", "yunnan_cfgfree_iec104.query_start", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }},
		{ &hf_query_end, { "查询终止时间", "yunnan_cfgfree_iec104.query_end", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }},
		{ &hf_file_num_l, { "本帧文件数L", "yunnan_cfgfree_iec104.file_num_l", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_file_num_h, { "本帧文件数H", "yunnan_cfgfree_iec104.file_num_h", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_raw, { "原始数据", "yunnan_cfgfree_iec104.raw", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
	};

	static int *ett[] = {
		&ett_yunnan,
		&ett_yunnan_apci,
		&ett_yunnan_apci_len,
		&ett_yunnan_apci_ctrl,
		&ett_yunnan_asdu,
		&ett_yunnan_cp56time,
		&ett_yunnan_data_pkt,
	};

	static ei_register_info ei[] = {
		{ &ei_apdu_bad_len, { "yunnan_cfgfree_iec104.apdu_bad_len", PI_MALFORMED, PI_ERROR, "APDU length invalid", EXPFILL }},
		{ &ei_asdu_truncated, { "yunnan_cfgfree_iec104.asdu_truncated", PI_MALFORMED, PI_WARN, "ASDU truncated", EXPFILL }},
	};

	module_t *module;
	expert_module_t *expert_mod;

	proto_yunnan_cfgfree_iec104 = proto_register_protocol(
		"云南免配置主子站104规约",
		"云南免配置104",
		"yunnan_cfgfree_iec104");

	proto_register_field_array(proto_yunnan_cfgfree_iec104, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_mod = expert_register_protocol(proto_yunnan_cfgfree_iec104);
	expert_register_field_array(expert_mod, ei, array_length(ei));

	yunnan_cfgfree_iec104_handle = register_dissector("yunnan_cfgfree_iec104",
		dissect_yunnan_cfgfree_iec104_tcp, proto_yunnan_cfgfree_iec104);

	module = prefs_register_protocol(proto_yunnan_cfgfree_iec104, yunnan_cfgfree_prefs_apply);
	prefs_register_bool_preference(module, "heuristic_2404",
		"在2404端口启用启发式识别",
		"若关闭，2404端口仅由其他解析器(如山东103)处理；开启时仅当ASDU类型属于免配置规约时才解析",
		&pref_heuristic_2404);
	range_convert_str(wmem_epan_scope(), &pref_tcp_ports, "2405,2404", 65535);
	prefs_register_range_preference(module, "tcp_ports", "TCP端口",
		"云南免配置主子站104规约使用的TCP端口", &pref_tcp_ports, 65535);
}

void
proto_reg_handoff_yunnan_cfgfree_iec104(void)
{
	yunnan_cfgfree_prefs_apply();
}
