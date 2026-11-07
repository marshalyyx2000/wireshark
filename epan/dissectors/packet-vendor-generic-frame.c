/* packet-vendor-generic-frame.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <wsutil/array.h>

#include "packet-vendor-generic-frame.h"

#define VGF_MAX_PROFILES 32

typedef enum {
	VGF_HF_ADDR,
	VGF_HF_CMD,
	VGF_HF_LEN,
	VGF_HF_CRC,
	VGF_HF_CRC_OK,
	VGF_HF_BODY,
	VGF_HF_FRAME,
	VGF_HF_SIG,
	VGF_HF_TAIL,
	VGF_HF_COUNT
} vgf_hf_id_t;

typedef struct {
	int proto;
	int ett_root;
	int ett_frame;
	int hf[VGF_HF_COUNT];
} vgf_regs_t;

static vgf_regs_t g_regs[VGF_MAX_PROFILES];
static unsigned g_profile_count;
static const vgf_profile_t *g_profiles[VGF_MAX_PROFILES];

static expert_field ei_vgf_sync;
static expert_field ei_vgf_len;
static expert_field ei_vgf_crc;
static expert_field ei_vgf_unknown_cmd;

static vgf_regs_t *
regs_for_proto(int proto)
{
	for (unsigned i = 0; i < g_profile_count; i++) {
		if (g_regs[i].proto == proto)
			return &g_regs[i];
	}
	return NULL;
}

static uint16_t
vgf_crc16_modbus(tvbuff_t *tvb, int offset, int len)
{
	uint16_t crc = 0xFFFF;

	for (int i = 0; i < len; i++) {
		crc ^= tvb_get_uint8(tvb, offset + i);
		for (int b = 0; b < 8; b++)
			crc = (crc & 1) ? (uint16_t)((crc >> 1) ^ 0xA001) : (uint16_t)(crc >> 1);
	}
	return crc;
}

static bool
vgf_crc_check(tvbuff_t *tvb, int start, int len, const vgf_profile_t *p, uint16_t *computed)
{
	int body = len - p->crc_tail - p->crc_tail_extra;
	int from = (p->crc_off > 0 && p->crc_off < body) ? p->crc_off : 0;
	int span;

	if (body - from <= 0) {
		*computed = 0;
		return false;
	}
	span = body - from;

	switch (p->crc) {
	case VGF_CRC_SUM8: {
		/* 参考实现用 WORD 累加（CheckSum 返回 long/WORD），所以必须按
		 * 16 位求和，不能截断到 8 位。 */
		uint16_t sum = 0;
		for (int i = 0; i < span; i++)
			sum = (uint16_t)(sum + tvb_get_uint8(tvb, start + from + i));
		*computed = sum;
		return tvb_get_letohs(tvb, start + body) == sum;
	}
	case VGF_CRC_SUM8_LOW: {
		uint8_t sum = 0;
		for (int i = 0; i < span; i++)
			sum = (uint8_t)(sum + tvb_get_uint8(tvb, start + from + i));
		*computed = sum;
		return tvb_get_uint8(tvb, start + body) == sum;
	}
	case VGF_CRC_MODBUS16:
		*computed = vgf_crc16_modbus(tvb, start + from, span);
		return tvb_get_letohs(tvb, start + body) == *computed;
	default:
		*computed = 0;
		return true;
	}
}

static bool
vgf_sig_ok(tvbuff_t *tvb, int offset, int remaining, const vgf_profile_t *p)
{
	if (p->sig_len == 0)
		return true;
	if ((int)p->sig_len > remaining)
		return false;
	for (unsigned i = 0; i < p->sig_len; i++) {
		if (tvb_get_uint8(tvb, offset + (int)i) != p->sig[i])
			return false;
	}
	return true;
}

static int vgf_frame_len(tvbuff_t *tvb, int offset, int remaining,
			 const vgf_profile_t *p);

/* 文本行帧：从帧首到 CR/LF 为止。返回 0 表示不是可打印文本行。 */
static int
vgf_ascii_line_len(tvbuff_t *tvb, int offset, int remaining, const vgf_profile_t *p)
{
	int len;

	if (!p->ascii_line)
		return 0;
	for (len = 0; len < remaining && len < p->max_len; len++) {
		uint8_t c = tvb_get_uint8(tvb, offset + len);
		if (c == 0x0D || c == 0x0A)
			return (len + 1 >= p->min_len) ? len + 1 : 0;
		if (c != 0x09 && (c < 0x20 || c > 0x7E))
			return 0;
	}
	return 0;
}

/* 没有帧同步签名的厂家只能靠长度自洽 + 校验通过来确认；否则会把任意数据
 * 都当成这一家的帧。 */
static bool
vgf_looks_like_frame(tvbuff_t *tvb, int offset, int remaining, const vgf_profile_t *p)
{
	int len;

	if (!vgf_sig_ok(tvb, offset, remaining, p))
		return false;

	if (p->ascii_line)
		return vgf_ascii_line_len(tvb, offset, remaining, p) > 0;

	if (p->sig_len > 0)
		return true;

	len = vgf_frame_len(tvb, offset, remaining, p);
	if (len < p->min_len)
		return false;
	if (p->crc == VGF_CRC_NONE)
		/* 既无签名又无校验：只能靠"用户显式选中本规约"来保证不被误判，
		 * 因为本解析器没有端口绑定，非显式选择时根本不会被调用。 */
		return true;
	{
		uint16_t computed;
		return vgf_crc_check(tvb, offset, len, p, &computed);
	}
}

static int
vgf_frame_len(tvbuff_t *tvb, int offset, int remaining, const vgf_profile_t *p)
{
	int field;
	int total;

	if (p->fixed_len > 0)
		return (p->fixed_len <= remaining) ? p->fixed_len : remaining;

	if (p->len_off < 0)
		return remaining;
	if (p->len_off + p->len_size > remaining)
		return remaining;

	field = tvb_get_uint8(tvb, offset + p->len_off);
	if (p->len_size == 2) {
		field = p->len_be ? tvb_get_ntohs(tvb, offset + p->len_off)
				  : tvb_get_letohs(tvb, offset + p->len_off);
	} else if (p->len_size == 4) {
		field = p->len_be ? (int)tvb_get_ntohl(tvb, offset + p->len_off)
				  : (int)tvb_get_letohl(tvb, offset + p->len_off);
	}

	total = field + p->len_bias;
	if (total < p->min_len || total > p->max_len)
		return remaining;
	return (total <= remaining) ? total : remaining;
}

static void
vgf_dissect_one(tvbuff_t *tvb, int start, int len, packet_info *pinfo, proto_tree *tree,
		const vgf_regs_t *R, const vgf_profile_t *p)
{
	proto_item *fi = proto_tree_add_none_format(tree, R->hf[VGF_HF_FRAME], tvb, start, len,
						    "%s 帧", p->col_protocol);
	proto_tree *ft = proto_item_add_subtree(fi, R->ett_frame);

	if (p->sig_len > 0 && (int)p->sig_len <= len) {
		proto_tree_add_item(ft, R->hf[VGF_HF_SIG], tvb, start, (int)p->sig_len, ENC_NA);
	} else if (p->sig_len > 0) {
		proto_tree_add_expert(ft, pinfo, &ei_vgf_sync, tvb, start, len);
	}

	if (p->addr_off >= 0 && p->addr_off + p->addr_size <= len) {
		proto_tree_add_item(ft, R->hf[VGF_HF_ADDR], tvb, start + p->addr_off,
				    p->addr_size, ENC_LITTLE_ENDIAN);
	}

	if (p->cmd_off >= 0 && p->cmd_off < len) {
		uint8_t cmd = tvb_get_uint8(tvb, start + p->cmd_off);
		const char *name = NULL;

		if (p->cmd_vals != NULL)
			name = try_val_to_str(cmd, p->cmd_vals);
		proto_item *ci = proto_tree_add_item(ft, R->hf[VGF_HF_CMD],
						     tvb, start + p->cmd_off, 1,
						     ENC_LITTLE_ENDIAN);
		proto_item_append_text(ci, " %s", name ? name : "自定义");
		col_append_fstr(pinfo->cinfo, COL_INFO, " 命令=0x%02X", cmd);
		if (name == NULL) {
			proto_tree_add_expert_format(ft, pinfo, &ei_vgf_unknown_cmd,
						    tvb, start + p->cmd_off, 1,
						    "命令码 0x%02X 未定义", cmd);
		}
	}

	if (p->len_off >= 0 && p->len_off + p->len_size <= len) {
		proto_tree_add_item(ft, R->hf[VGF_HF_LEN], tvb, start + p->len_off,
				    p->len_size, p->len_be ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN);
	}

	int body_end = len - p->crc_tail - p->crc_tail_extra;
	if (body_end < 0)
		body_end = 0;
	if (body_end > len)
		body_end = len;

	if (p->crc != VGF_CRC_NONE && p->crc_tail > 0 && body_end <= len) {
		uint16_t computed = 0;
		bool ok = vgf_crc_check(tvb, start, len, p, &computed);
		proto_item *ci = proto_tree_add_item(ft, R->hf[VGF_HF_CRC],
						     tvb, start + body_end, p->crc_tail,
						     ENC_LITTLE_ENDIAN);
		proto_item *si = proto_tree_add_boolean(ft, R->hf[VGF_HF_CRC_OK], tvb,
							start + body_end, p->crc_tail, ok);
		proto_item_set_generated(si);
		proto_item_append_text(ci, " %s (计算值 0x%04X)", ok ? "校验正确" : "校验错误",
				       computed);
		if (!ok)
			proto_tree_add_expert(ft, pinfo, &ei_vgf_crc, tvb, start + body_end,
					      p->crc_tail);
	}

	if (body_end > 0 && (int)p->sig_len < body_end) {
		int off = (int)p->sig_len;
		int body = body_end - off;
		if (body > 0) {
			proto_item *bi = proto_tree_add_item(ft, R->hf[VGF_HF_BODY], tvb,
							     start + off, body,
							     p->ascii_line ? (ENC_ASCII | ENC_NA)
									   : ENC_NA);
			if (p->ascii_line)
				proto_item_append_text(bi, "（文本命令）");
			else
				proto_item_append_text(bi, "（%d 字节厂家自定义主体）", body);
		}
	}
	if (p->crc_tail_extra > 0) {
		int tail_off = len - p->crc_tail_extra;
		if (tail_off >= 0)
			proto_tree_add_item(ft, R->hf[VGF_HF_TAIL], tvb, start + tail_off,
					    p->crc_tail_extra, ENC_NA);
	}
}

int
vgf_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	const vgf_profile_t *p = (const vgf_profile_t *)data;
	const vgf_regs_t *R;
	int total = (int)tvb_reported_length(tvb);
	int offset = 0;
	int guard = 0;

	if (p == NULL)
		return 0;
	R = regs_for_proto(p->proto);
	if (R == NULL || total < p->min_len)
		return 0;
	if (!vgf_looks_like_frame(tvb, 0, total, p))
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, p->col_protocol);
	col_clear(pinfo->cinfo, COL_INFO);

	proto_item *ti = proto_tree_add_item(tree, p->proto, tvb, 0, total, ENC_NA);
	if (p->note != NULL)
		proto_item_append_text(ti, " — %s", p->note);
	proto_tree *root = proto_item_add_subtree(ti, R->ett_root);

	while (offset < total && guard++ < 1024) {
		int remaining = total - offset;
		int len;

		if (!vgf_looks_like_frame(tvb, offset, remaining, p)) {
			proto_tree_add_expert(root, pinfo, &ei_vgf_sync, tvb, offset, remaining);
			break;
		}
		len = vgf_frame_len(tvb, offset, remaining, p);
		if (p->ascii_line) {
			len = vgf_ascii_line_len(tvb, offset, remaining, p);
			if (len <= 0)
				break;
		}
		if (len <= 0)
			break;
		vgf_dissect_one(tvb, offset, len, pinfo, root, R, p);
		offset += len;
		if (p->len_off < 0 && p->fixed_len <= 0)
			break;
	}
	if (offset < total) {
		proto_item *bi = proto_tree_add_item(root, R->hf[VGF_HF_BODY], tvb, offset,
						     total - offset, ENC_NA);
		proto_item_append_text(bi, "（未成帧的剩余字节）");
	}
	(void)ei_vgf_len;
	return total;
}

typedef struct {
	int id;
	const char *suffix;
	const char *name;
	enum ftenum type;
	int display;
} vgf_hf_spec_t;

static const vgf_hf_spec_t g_hf_specs[] = {
	{ VGF_HF_ADDR,   "addr",     "地址",         FT_UINT32, BASE_DEC },
	{ VGF_HF_CMD,    "cmd",      "命令/类型",    FT_UINT8,  BASE_HEX },
	{ VGF_HF_LEN,    "len",      "长度字段",     FT_UINT32, BASE_DEC },
	{ VGF_HF_CRC,    "crc",      "校验",         FT_UINT16, BASE_HEX },
	{ VGF_HF_CRC_OK, "crc.ok",   "校验通过",     FT_BOOLEAN, BASE_NONE },
	{ VGF_HF_BODY,   "body",     "厂家自定义主体", FT_BYTES, BASE_NONE },
	{ VGF_HF_FRAME,  "frame",    "帧",           FT_NONE,   BASE_NONE },
	{ VGF_HF_SIG,    "sig",      "帧同步字符",   FT_BYTES,  BASE_NONE },
	{ VGF_HF_TAIL,   "tail",     "帧尾",         FT_BYTES,  BASE_NONE },
};

void
vgf_register(const vgf_profile_t *profile)
{
	static int *ett_roots[VGF_MAX_PROFILES];
	static int *ett_frames[VGF_MAX_PROFILES];

	if (g_profile_count >= VGF_MAX_PROFILES) {
		ws_warning("vgf: profile table full (%u), dropping %s",
			   VGF_MAX_PROFILES, proto_get_protocol_filter_name(profile->proto));
		return;
	}

	unsigned slot = g_profile_count;
	vgf_regs_t *R = &g_regs[slot];
	R->proto = profile->proto;
	g_profiles[slot] = profile;
	g_profile_count++;

	const char *short_name = proto_get_protocol_filter_name(profile->proto);
	const unsigned spec_count = array_length(g_hf_specs);
	hf_register_info *hf = g_new0(hf_register_info, spec_count);
	for (unsigned i = 0; i < spec_count; i++) {
		const vgf_hf_spec_t *spec = &g_hf_specs[i];
		hf[i].p_id = &R->hf[spec->id];
		hf[i].hfinfo.name = spec->name;
		hf[i].hfinfo.abbrev = g_strdup_printf("%s.%s", short_name, spec->suffix);
		hf[i].hfinfo.type = spec->type;
		hf[i].hfinfo.display = spec->display;
		hf[i].hfinfo.strings = NULL;
		hf[i].hfinfo.bitmask = 0;
		hf[i].hfinfo.blurb = NULL;
		hf[i].hfinfo.parent = -1;
		hf[i].hfinfo.ref_type = HF_REF_TYPE_NONE;
		hf[i].hfinfo.same_name_prev_id = -1;
		hf[i].hfinfo.same_name_next = NULL;
	}
	proto_register_field_array(profile->proto, hf, (int)spec_count);

	ett_roots[slot] = &R->ett_root;
	ett_frames[slot] = &R->ett_frame;
	int *ett[] = { ett_roots[slot], ett_frames[slot] };
	proto_register_subtree_array(ett, array_length(ett));

	static bool experts_done;
	if (!experts_done) {
		experts_done = true;
		static ei_register_info ei[] = {
			{ &ei_vgf_sync, { "vgf.sync.bad", PI_MALFORMED, PI_ERROR,
					  "帧同步字符不匹配", EXPFILL }},
			{ &ei_vgf_len, { "vgf.len.bad", PI_MALFORMED, PI_WARN,
					 "长度字段异常", EXPFILL }},
			{ &ei_vgf_crc, { "vgf.crc.bad", PI_CHECKSUM, PI_WARN,
					 "校验错误", EXPFILL }},
			{ &ei_vgf_unknown_cmd, { "vgf.cmd.unknown", PI_UNDECODED, PI_NOTE,
						 "未定义的命令码", EXPFILL }},
		};
		expert_module_t *expert = expert_register_protocol(profile->proto);
		expert_register_field_array(expert, ei, array_length(ei));
	}

	prefs_register_protocol(profile->proto, NULL);
	(void)g_profiles;
}
