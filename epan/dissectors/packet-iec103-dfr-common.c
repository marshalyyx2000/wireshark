/* packet-iec103-dfr-common.c
 *
 * 录波器 68 帧共享引擎。见 packet-iec103-dfr-common.h 的帧布局说明。
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>
#include <time.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/tfs.h>
#include <epan/to_str.h>
#include <wsutil/array.h>

#include "packet-iec103-dfr-common.h"

#define DFR_MAX_PROFILES 32
/* 主站一次取文件的块大小上限：超过这个值就基本可以判定长度字段不可信。 */
#define DFR_MAX_FRAME    262144

typedef enum {
	HF_START,
	HF_ADDR,
	HF_CMD,
	HF_ANSWER,
	HF_PASSWD,
	HF_TOTAL_LEN,
	HF_CHECKSUM,
	HF_TIME_YEAR,
	HF_TIME_MONTH,
	HF_TIME_DAY,
	HF_TIME_HOUR,
	HF_TIME_MINUTE,
	HF_TIME_SECOND,
	HF_FILE_LEN,
	HF_FILE_NAME,
	HF_FILE_TYPE,
	HF_FAULT_FLAG,
	HF_OFFSET,
	HF_FRAME,
	HF_HEADER,
	HF_BODY,
	HF_DATA,
	HF_COUNT
} dfr_hf_id_t;

typedef struct {
	int proto;
	int ett_root;
	int ett_hdr;
	int ett_body;
	int ett_time;
	int hf[HF_COUNT];
} dfr_regs_t;

static dfr_regs_t g_regs[DFR_MAX_PROFILES];
static unsigned g_profile_count;

static expert_field ei_bad_start;
static expert_field ei_bad_len;
static expert_field ei_unknown_cmd;

static const value_string dfr_cmd_vals[] = {
	{ DFR_CMD_WORKSTATUS,   "查询工作状态" },
	{ DFR_CMD_SEARCHFILE,   "检索录波文件目录" },
	{ DFR_CMD_DOWNLOADFILE, "请求下载文件" },
	{ DFR_CMD_REQUESTDATA,  "请求实时数据/定值" },
	{ DFR_CMD_CONTROL,      "遥控/启动录波" },
	{ DFR_CMD_RESETCOMM,    "复位通信" },
	{ DFR_CMD_TIMESYNC,     "对时" },
	{ 0, NULL }
};

static const value_string dfr_answer_vals[] = {
	{ DFR_ANSWER_SUCCESS, "成功" },
	{ DFR_ANSWER_FAIL,    "失败" },
	{ 0, NULL }
};

static const dfr_vendor_profile_t *g_profiles[DFR_MAX_PROFILES];

static dfr_regs_t *
regs_for_proto(int proto)
{
	for (unsigned i = 0; i < g_profile_count; i++) {
		if (g_regs[i].proto == proto)
			return &g_regs[i];
	}
	return NULL;
}

const char *
dfr_cmd_name(const dfr_vendor_profile_t *profile, uint8_t cmd)
{
	const char *s = NULL;

	if (profile != NULL && profile->cmd_vals != NULL)
		s = try_val_to_str(cmd, profile->cmd_vals);
	if (s == NULL)
		s = try_val_to_str(cmd, dfr_cmd_vals);
	return s;
}

bool
dfr_looks_like_frame(tvbuff_t *tvb, int offset, int remaining)
{
	uint32_t total;

	if (remaining < DFR_HDR_LEN)
		return false;
	if (tvb_get_uint8(tvb, offset) != DFR_START)
		return false;

	total = tvb_get_letohl(tvb, offset + 6);
	/* 长度字段含 10 字节头；过小或过大都不可信。 */
	if (total < DFR_HDR_LEN || total > DFR_MAX_FRAME)
		return false;
	return true;
}

/* 命令码之后的主体布局。录波器规约各命令共用同一套字段，只有解释不同。 */
static void
dissect_body(tvbuff_t *tvb, int *offset, int end, packet_info *pinfo, proto_tree *tree,
	     const dfr_regs_t *R, const dfr_vendor_profile_t *profile, uint8_t cmd)
{
	uint8_t answer = (uint8_t)tvb_get_uint8(tvb, 2);

	switch (cmd) {
	case DFR_CMD_SEARCHFILE:
		/* 检索应答：文件长度(4) + 文件名(28) + 类型/故障标志 */
		if (answer == DFR_ANSWER_SUCCESS && end - *offset >= 32) {
			proto_tree_add_item(tree, R->hf[HF_FILE_LEN], tvb, *offset, 4,
					    ENC_LITTLE_ENDIAN);
			*offset += 4;
			proto_tree_add_item(tree, R->hf[HF_FILE_NAME], tvb, *offset, 28,
					    ENC_ASCII | ENC_NA);
			*offset += 28;
		}
		break;

	case DFR_CMD_TIMESYNC:
		if (end - *offset >= 6) {
			proto_tree *tt = proto_item_add_subtree(
				proto_tree_add_item(tree, R->hf[HF_TIME_YEAR], tvb, *offset, 1,
						    ENC_LITTLE_ENDIAN),
				R->ett_time);
			proto_tree_add_item(tt, R->hf[HF_TIME_MONTH], tvb, *offset + 1, 1,
					    ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tt, R->hf[HF_TIME_DAY], tvb, *offset + 2, 1,
					    ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tt, R->hf[HF_TIME_HOUR], tvb, *offset + 3, 1,
					    ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tt, R->hf[HF_TIME_MINUTE], tvb, *offset + 4, 1,
					    ENC_LITTLE_ENDIAN);
			proto_tree_add_item(tt, R->hf[HF_TIME_SECOND], tvb, *offset + 5, 1,
					    ENC_LITTLE_ENDIAN);
			*offset += 6;
		}
		break;

	case DFR_CMD_DOWNLOADFILE:
		if (end - *offset >= 4) {
			proto_tree_add_item(tree, R->hf[HF_OFFSET], tvb, *offset, 4,
					    ENC_LITTLE_ENDIAN);
			*offset += 4;
		}
		break;

	default:
		break;
	}

	if (profile->dissect_extra_cmd != NULL &&
	    profile->dissect_extra_cmd(tvb, offset, end, pinfo, tree, profile))
		return;

	if (*offset < end)
		proto_tree_add_item(tree, R->hf[HF_DATA], tvb, *offset, end - *offset, ENC_NA);
}

static void
dissect_one_frame(tvbuff_t *tvb, int start, int end, packet_info *pinfo, proto_tree *tree,
		  const dfr_regs_t *R, const dfr_vendor_profile_t *profile)
{
	uint8_t cmd = tvb_get_uint8(tvb, start + 2);
	uint8_t answer = tvb_get_uint8(tvb, start + 3);
	uint32_t total = tvb_get_letohl(tvb, start + 6);
	const char *cmd_name = dfr_cmd_name(profile, cmd);
	int offset = start + DFR_HDR_LEN;

	proto_item *fi = proto_tree_add_none_format(tree, R->hf[HF_FRAME], tvb, start,
						    end - start, "录波器帧");
	proto_tree *ft = proto_item_add_subtree(fi, R->ett_root);

	proto_item *hi = proto_tree_add_none_format(ft, R->hf[HF_HEADER], tvb, start,
						    DFR_HDR_LEN, "报文头");
	proto_tree *ht = proto_item_add_subtree(hi, R->ett_hdr);

	proto_tree_add_item(ht, R->hf[HF_START], tvb, start, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ht, R->hf[HF_ADDR], tvb, start + 1, 1, ENC_LITTLE_ENDIAN);
	proto_item *ci = proto_tree_add_item(ht, R->hf[HF_CMD], tvb, start + 2, 1,
					     ENC_LITTLE_ENDIAN);
	proto_item_append_text(ci, " %s", cmd_name ? cmd_name : "未知命令");
	proto_tree_add_item(ht, R->hf[HF_ANSWER], tvb, start + 3, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ht, R->hf[HF_PASSWD], tvb, start + 4, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ht, R->hf[HF_TOTAL_LEN], tvb, start + 6, 4, ENC_LITTLE_ENDIAN);

	if (total != (uint32_t)(end - start)) {
		proto_tree_add_expert_format(ft, pinfo, &ei_bad_len, tvb, start + 6, 4,
					    "长度字段 %u 与实际帧长 %d 不一致", total, end - start);
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, profile->col_protocol);
	col_clear(pinfo->cinfo, COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s 地址=%u %s",
		     cmd_name ? cmd_name : "未知命令",
		     tvb_get_uint8(tvb, start + 1),
		     val_to_str_const(answer, dfr_answer_vals, "未知"));

	if (cmd_name == NULL) {
		proto_tree_add_expert_format(ft, pinfo, &ei_unknown_cmd, tvb, start + 2, 1,
					    "%s：命令码 0x%02X 未专门解码",
					    profile->unknown_cmd_prefix
						    ? profile->unknown_cmd_prefix
						    : "未知命令",
					    cmd);
	}

	proto_item *bi = proto_tree_add_none_format(ft, R->hf[HF_BODY], tvb, offset,
						    end - offset, "报文体");
	proto_tree *bt = proto_item_add_subtree(bi, R->ett_body);
	if (offset < end)
		dissect_body(tvb, &offset, end, pinfo, bt, R, profile, cmd);
	proto_item_set_len(bi, offset - (start + DFR_HDR_LEN));
}

static void
dissect_frames(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	       const dfr_vendor_profile_t *profile)
{
	const dfr_regs_t *R = regs_for_proto(profile->proto);
	int total = (int)tvb_reported_length(tvb);
	int offset = 0;
	int guard = 0;

	if (R == NULL)
		return;

	proto_item *ti = proto_tree_add_item(tree, profile->proto, tvb, 0, total, ENC_NA);
	proto_item_append_text(ti, " (%d 字节)", total);
	proto_tree *root = proto_item_add_subtree(ti, R->ett_root);

	while (offset < total && guard++ < 1024) {
		int remaining = total - offset;
		uint32_t frame_len;

		if (tvb_get_uint8(tvb, offset) != DFR_START) {
			proto_tree_add_expert_format(root, pinfo, &ei_bad_start, tvb, offset, 1,
						    "启动字符应为 0x68");
			proto_tree_add_item(root, R->hf[HF_DATA], tvb, offset, remaining, ENC_NA);
			break;
		}
		if (remaining < DFR_HDR_LEN) {
			proto_tree_add_item(root, R->hf[HF_DATA], tvb, offset, remaining, ENC_NA);
			break;
		}

		frame_len = tvb_get_letohl(tvb, offset + 6);
		if (frame_len < DFR_HDR_LEN || frame_len > (uint32_t)remaining)
			frame_len = (uint32_t)remaining;

		dissect_one_frame(tvb, offset, offset + (int)frame_len, pinfo, root, R, profile);
		offset += (int)frame_len;
	}
}

int
dfr_dissect_stream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		   const dfr_vendor_profile_t *profile)
{
	int total = (int)tvb_reported_length(tvb);

	if (total < DFR_HDR_LEN)
		return 0;
	if (!profile->lenient_start && tvb_get_uint8(tvb, 0) != DFR_START)
		return 0;
	if (!dfr_looks_like_frame(tvb, 0, total))
		return 0;

	dissect_frames(tvb, pinfo, tree, profile);
	return total;
}

int
dfr_dissect_datagram(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		     const dfr_vendor_profile_t *profile)
{
	return dfr_dissect_stream(tvb, pinfo, tree, profile);
}

typedef struct {
	int id;
	const char *suffix;
	const char *name;
	enum ftenum type;
	int display;
	const void *vals;
} dfr_hf_spec_t;

static const dfr_hf_spec_t g_hf_specs[] = {
	{ HF_START,      "start",      "启动字符",     FT_UINT8,  BASE_HEX, NULL },
	{ HF_ADDR,       "addr",       "装置地址",     FT_UINT8,  BASE_DEC, NULL },
	{ HF_CMD,        "cmd",        "命令码",       FT_UINT8,  BASE_HEX, VALS(dfr_cmd_vals) },
	{ HF_ANSWER,     "answer",     "应答标志",     FT_UINT8,  BASE_DEC, VALS(dfr_answer_vals) },
	{ HF_PASSWD,     "passwd",     "密码/保留",    FT_UINT16, BASE_HEX, NULL },
	{ HF_TOTAL_LEN,  "total_len",  "报文总长",     FT_UINT32, BASE_DEC, NULL },
	{ HF_CHECKSUM,   "checksum",   "校验和",       FT_UINT8,  BASE_HEX, NULL },
	{ HF_TIME_YEAR,  "time.year",  "年",           FT_UINT8,  BASE_DEC, NULL },
	{ HF_TIME_MONTH, "time.month", "月",           FT_UINT8,  BASE_DEC, NULL },
	{ HF_TIME_DAY,   "time.day",   "日",           FT_UINT8,  BASE_DEC, NULL },
	{ HF_TIME_HOUR,  "time.hour",  "时",           FT_UINT8,  BASE_DEC, NULL },
	{ HF_TIME_MINUTE,"time.min",   "分",           FT_UINT8,  BASE_DEC, NULL },
	{ HF_TIME_SECOND,"time.sec",   "秒",           FT_UINT8,  BASE_DEC, NULL },
	{ HF_FILE_LEN,   "file.len",   "文件长度",     FT_UINT32, BASE_DEC, NULL },
	{ HF_FILE_NAME,  "file.name",  "文件名",       FT_STRING, BASE_NONE, NULL },
	{ HF_FILE_TYPE,  "file.type",  "文件类型",     FT_UINT8,  BASE_DEC, NULL },
	{ HF_FAULT_FLAG, "file.fault", "故障标志",     FT_UINT8,  BASE_DEC, NULL },
	{ HF_OFFSET,     "file.offset","文件偏移",     FT_UINT32, BASE_DEC, NULL },
	{ HF_FRAME,      "frame_item", "录波器帧",     FT_NONE,   BASE_NONE, NULL },
	{ HF_HEADER,     "hdr_item",   "报文头",       FT_NONE,   BASE_NONE, NULL },
	{ HF_BODY,       "body_item",  "报文体",       FT_NONE,   BASE_NONE, NULL },
	{ HF_DATA,       "data",       "数据",         FT_BYTES,  BASE_NONE, NULL },
};

void
dfr_common_register(const dfr_vendor_profile_t *profile)
{
	static int *ett_roots[DFR_MAX_PROFILES];
	static int *ett_hdrs[DFR_MAX_PROFILES];
	static int *ett_bodies[DFR_MAX_PROFILES];
	static int *ett_times[DFR_MAX_PROFILES];

	if (g_profile_count >= DFR_MAX_PROFILES) {
		ws_warning("dfr: profile table full (%u), dropping %s",
			   DFR_MAX_PROFILES, proto_get_protocol_filter_name(profile->proto));
		return;
	}

	unsigned slot = g_profile_count;
	dfr_regs_t *R = &g_regs[slot];
	R->proto = profile->proto;
	g_profiles[slot] = profile;
	g_profile_count++;

	const char *short_name = proto_get_protocol_filter_name(profile->proto);
	const unsigned spec_count = array_length(g_hf_specs);
	hf_register_info *hf = g_new0(hf_register_info, spec_count);
	for (unsigned i = 0; i < spec_count; i++) {
		const dfr_hf_spec_t *spec = &g_hf_specs[i];
		hf[i].p_id = &R->hf[spec->id];
		hf[i].hfinfo.name = spec->name;
		hf[i].hfinfo.abbrev = g_strdup_printf("%s.%s", short_name, spec->suffix);
		hf[i].hfinfo.type = spec->type;
		hf[i].hfinfo.display = spec->display;
		hf[i].hfinfo.strings = spec->vals;
		hf[i].hfinfo.bitmask = 0;
		hf[i].hfinfo.blurb = NULL;
		hf[i].hfinfo.parent = -1;
		hf[i].hfinfo.ref_type = HF_REF_TYPE_NONE;
		hf[i].hfinfo.same_name_prev_id = -1;
		hf[i].hfinfo.same_name_next = NULL;
	}
	proto_register_field_array(profile->proto, hf, (int)spec_count);

	ett_roots[slot] = &R->ett_root;
	ett_hdrs[slot] = &R->ett_hdr;
	ett_bodies[slot] = &R->ett_body;
	ett_times[slot] = &R->ett_time;
	int *ett[] = { ett_roots[slot], ett_hdrs[slot], ett_bodies[slot], ett_times[slot] };
	proto_register_subtree_array(ett, array_length(ett));

	static bool experts_done;
	if (!experts_done) {
		experts_done = true;
		static ei_register_info ei[] = {
			{ &ei_bad_start, { "dfr.start.bad", PI_MALFORMED, PI_ERROR,
					   "启动字符应为 0x68", EXPFILL }},
			{ &ei_bad_len, { "dfr.len.bad", PI_MALFORMED, PI_WARN,
					 "长度字段与实际帧长不一致", EXPFILL }},
			{ &ei_unknown_cmd, { "dfr.cmd.unknown", PI_UNDECODED, PI_NOTE,
					     "未专门解码的命令码", EXPFILL }},
		};
		expert_module_t *expert = expert_register_protocol(profile->proto);
		expert_register_field_array(expert, ei, array_length(ei));
	}
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
