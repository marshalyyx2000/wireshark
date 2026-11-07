/* packet-modbus-vendor-common.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <wsutil/array.h>

#include "packet-modbus-vendor-common.h"

#define MB_MAX_PROFILES 16
#define MB_FN_READ_COILS 0x01
#define MB_FN_READ_DI 0x02
#define MB_FN_READ_HOLDING 0x03
#define MB_FN_READ_INPUT 0x04
#define MB_FN_WRITE_COIL 0x05
#define MB_FN_WRITE_REG 0x06
#define MB_FN_WRITE_MULTI 0x10
#define MB_FN_EXCEPTION_FLAG 0x80

typedef enum {
	HF_UNIT,
	HF_FN,
	HF_START_ADDR,
	HF_COUNT,
	HF_BYTE_COUNT,
	HF_REG_VALUE,
	HF_REG_ITEM,
	HF_CRC,
	HF_CRC_STATUS,
	HF_EXCEPTION,
	HF_TXN,
	HF_PROTO_ID,
	HF_MBAP_LEN,
	HF_FRAME_ITEM,
	HF_DATA,
	HF_REGS,
	HF_ITEM_COUNT
} mb_hf_id_t;

typedef struct {
	int proto;
	int ett_root;
	int ett_frame;
	int ett_regs;
	int ett_reg;
	int hf[HF_ITEM_COUNT];
} mb_regs_t;

static mb_regs_t g_regs[MB_MAX_PROFILES];
static unsigned g_profile_count;
static const modbus_vendor_profile_t *g_profiles[MB_MAX_PROFILES];

static expert_field ei_bad_crc;
static expert_field ei_bad_len;
static expert_field ei_unknown_fn;

static const value_string mb_fn_vals[] = {
	{ MB_FN_READ_COILS,      "读线圈 (0x01)" },
	{ MB_FN_READ_DI,         "读离散输入 (0x02)" },
	{ MB_FN_READ_HOLDING,    "读保持寄存器 (0x03)" },
	{ MB_FN_READ_INPUT,      "读输入寄存器 (0x04)" },
	{ MB_FN_WRITE_COIL,      "写单线圈 (0x05)" },
	{ MB_FN_WRITE_REG,       "写单寄存器 (0x06)" },
	{ MB_FN_WRITE_MULTI,     "写多寄存器 (0x10)" },
	{ 0, NULL }
};

static const value_string mb_exception_vals[] = {
	{ 0x01, "非法功能码" },
	{ 0x02, "非法数据地址" },
	{ 0x03, "非法数据值" },
	{ 0x04, "从站设备故障" },
	{ 0x05, "确认（处理中）" },
	{ 0x06, "从站设备忙" },
	{ 0x08, "存储奇偶性差错" },
	{ 0x0A, "网关路径不可用" },
	{ 0x0B, "网关目标设备无响应" },
	{ 0, NULL }
};

/* Modbus CRC16: poly 0xA001, initial 0xFFFF, LSB first on the wire. */
static uint16_t
mb_crc16(tvbuff_t *tvb, int offset, int len)
{
	uint16_t crc = 0xFFFF;

	for (int i = 0; i < len; i++) {
		crc ^= tvb_get_uint8(tvb, offset + i);
		for (int b = 0; b < 8; b++) {
			if (crc & 0x0001)
				crc = (uint16_t)((crc >> 1) ^ 0xA001);
			else
				crc >>= 1;
		}
	}
	return crc;
}

bool
modbus_vendor_crc_ok(tvbuff_t *tvb, int offset, int len)
{
	uint16_t crc;

	if (len < 3)
		return false;
	crc = mb_crc16(tvb, offset, len - 2);
	return tvb_get_letohs(tvb, offset + len - 2) == crc;
}

static mb_regs_t *
regs_for_proto(int proto)
{
	for (unsigned i = 0; i < g_profile_count; i++) {
		if (g_regs[i].proto == proto)
			return &g_regs[i];
	}
	return NULL;
}

static const char *
fn_name(const modbus_vendor_profile_t *profile, uint8_t fn)
{
	const char *s = NULL;

	if (profile->extra_fn_vals != NULL)
		s = try_val_to_str(fn, profile->extra_fn_vals);
	if (s == NULL)
		s = try_val_to_str(fn, mb_fn_vals);
	return s;
}

/* 解码一个 请求/应答 帧的主体（含 CRC）。 */
static void
dissect_rtu_frame(tvbuff_t *tvb, int start, int len, packet_info *pinfo, proto_tree *tree,
		  const mb_regs_t *R, const modbus_vendor_profile_t *profile)
{
	uint8_t unit = tvb_get_uint8(tvb, start);
	uint8_t fn = tvb_get_uint8(tvb, start + 1);
	uint8_t base_fn = (uint8_t)(fn & ~MB_FN_EXCEPTION_FLAG);
	bool is_exception = (fn & MB_FN_EXCEPTION_FLAG) != 0;
	const char *name = fn_name(profile, base_fn);
	int offset = start + 2;

	proto_item *fi = proto_tree_add_none_format(tree, R->hf[HF_FRAME_ITEM], tvb, start, len,
						    "Modbus 帧");
	proto_tree *ft = proto_item_add_subtree(fi, R->ett_frame);

	proto_tree_add_item(ft, R->hf[HF_UNIT], tvb, start, 1, ENC_LITTLE_ENDIAN);
	proto_item *fni = proto_tree_add_item(ft, R->hf[HF_FN], tvb, start + 1, 1,
					      ENC_LITTLE_ENDIAN);
	proto_item_append_text(fni, " %s%s", name ? name : "未知功能码",
			       is_exception ? "（异常应答）" : "");

	if (name == NULL) {
		proto_tree_add_expert_format(ft, pinfo, &ei_unknown_fn, tvb, start + 1, 1,
					    "%s：功能码 0x%02X 未专门解码",
					    profile->unknown_fn_prefix
						    ? profile->unknown_fn_prefix : "未知功能码",
					    base_fn);
	}

	if (is_exception) {
		if (offset < start + len)
			proto_tree_add_item(ft, R->hf[HF_EXCEPTION], tvb, offset, 1,
					    ENC_LITTLE_ENDIAN);
	} else {
		switch (base_fn) {
		case MB_FN_READ_HOLDING:
		case MB_FN_READ_INPUT:
		case MB_FN_READ_COILS:
		case MB_FN_READ_DI:
			if (offset + 4 <= start + len - 2) {
				/* 请求：起始地址 + 数量；应答：字节数 + 数据 */
				uint8_t first = tvb_get_uint8(tvb, offset);
				if (first == (uint8_t)(len - 5) && (len - 5) % 2 == 0) {
					proto_tree_add_item(ft, R->hf[HF_BYTE_COUNT], tvb, offset,
							    1, ENC_LITTLE_ENDIAN);
					offset++;
					int count = tvb_reported_length_remaining(tvb, offset) - 2;
					if (count > 0) {
						proto_item *ri = proto_tree_add_none_format(
							ft, R->hf[HF_REGS], tvb, offset, count,
							"寄存器数据");
						proto_tree *rt = proto_item_add_subtree(ri, R->ett_regs);
						unsigned idx = 0;
						while (offset + 2 <= start + len - 2) {
							uint16_t value = tvb_get_ntohs(tvb, offset);
							proto_item *ei = proto_tree_add_uint_format_value(
								rt, R->hf[HF_REG_VALUE], tvb, offset, 2,
								value, "R%u = %u (0x%04X)", idx, value,
								value);
							(void)ei;
							offset += 2;
							idx++;
						}
					}
				} else {
					proto_tree_add_item(ft, R->hf[HF_START_ADDR], tvb, offset, 2,
							    ENC_BIG_ENDIAN);
					proto_tree_add_item(ft, R->hf[HF_COUNT], tvb, offset + 2, 2,
							    ENC_BIG_ENDIAN);
					offset += 4;
				}
			}
			break;

		case MB_FN_WRITE_REG:
		case MB_FN_WRITE_COIL:
			if (offset + 4 <= start + len - 2) {
				proto_tree_add_item(ft, R->hf[HF_START_ADDR], tvb, offset, 2,
						    ENC_BIG_ENDIAN);
				proto_tree_add_item(ft, R->hf[HF_REG_VALUE], tvb, offset + 2, 2,
						    ENC_BIG_ENDIAN);
				offset += 4;
			}
			break;

		case MB_FN_WRITE_MULTI:
			if (offset + 5 <= start + len - 2) {
				proto_tree_add_item(ft, R->hf[HF_START_ADDR], tvb, offset, 2,
						    ENC_BIG_ENDIAN);
				proto_tree_add_item(ft, R->hf[HF_COUNT], tvb, offset + 2, 2,
						    ENC_BIG_ENDIAN);
				proto_tree_add_item(ft, R->hf[HF_BYTE_COUNT], tvb, offset + 4, 1,
						    ENC_LITTLE_ENDIAN);
				offset += 5;
				int count = tvb_reported_length_remaining(tvb, offset) - 2;
				if (count > 0) {
					proto_item *ri = proto_tree_add_none_format(
						ft, R->hf[HF_REGS], tvb, offset, count,
						"待写入寄存器");
					proto_tree *rt = proto_item_add_subtree(ri, R->ett_regs);
					while (offset + 2 <= start + len - 2) {
						uint16_t value = tvb_get_ntohs(tvb, offset);
						proto_tree_add_uint_format_value(
							rt, R->hf[HF_REG_VALUE], tvb, offset, 2,
							value, "W = %u (0x%04X)", value, value);
						offset += 2;
					}
				}
			}
			break;

		default:
			break;
		}
	}

	if (len >= 4) {
		bool ok = modbus_vendor_crc_ok(tvb, start, len);
		proto_item *ci = proto_tree_add_item(ft, R->hf[HF_CRC], tvb, start + len - 2, 2,
						     ENC_LITTLE_ENDIAN);
		proto_item *si = proto_tree_add_boolean(ft, R->hf[HF_CRC_STATUS], tvb,
							start + len - 2, 2, ok);
		proto_item_set_generated(si);
		proto_item_append_text(ci, " %s", ok ? "（校验正确）" : "（校验错误）");
		if (!ok) {
			proto_tree_add_expert(ft, pinfo, &ei_bad_crc, tvb, start + len - 2, 2);
		}
	}

	if (offset < start + len - 2)
		proto_tree_add_item(ft, R->hf[HF_DATA], tvb, offset, start + len - 2 - offset,
				    ENC_NA);

	col_add_fstr(pinfo->cinfo, COL_INFO, "单元 %u %s%s", unit,
		     name ? name : "未知功能码", is_exception ? " 异常" : "");
}

/* RTU 帧长度：请求固定 8 字节；应答按字节数字段推算。返回 0 表示不像 Modbus。 */
static int
rtu_frame_len(tvbuff_t *tvb, int offset, int remaining)
{
	uint8_t fn;
	int len;

	if (remaining < MODBUS_RTU_MIN_LEN)
		return 0;
	fn = (uint8_t)(tvb_get_uint8(tvb, offset + 1) & ~MB_FN_EXCEPTION_FLAG);
	if (tvb_get_uint8(tvb, offset + 1) & MB_FN_EXCEPTION_FLAG)
		return (remaining >= 5) ? 5 : remaining;

	switch (fn) {
	case MB_FN_READ_COILS:
	case MB_FN_READ_DI:
	case MB_FN_READ_HOLDING:
	case MB_FN_READ_INPUT:
		/* 用 CRC 校验区分请求(8) 与应答(5+n)。 */
		if (remaining >= 8 && modbus_vendor_crc_ok(tvb, offset, 8))
			return 8;
		if (remaining >= 5) {
			len = 5 + tvb_get_uint8(tvb, offset + 2);
			if (len <= remaining && modbus_vendor_crc_ok(tvb, offset, len))
				return len;
		}
		return (remaining >= 8) ? 8 : remaining;

	case MB_FN_WRITE_COIL:
	case MB_FN_WRITE_REG:
		return (remaining >= 8) ? 8 : remaining;

	case MB_FN_WRITE_MULTI:
		if (remaining >= 9) {
			len = 9 + tvb_get_uint8(tvb, offset + 6);
			if (len <= remaining)
				return len;
		}
		return (remaining >= 8) ? 8 : remaining;

	default:
		/* 未知功能码：到 CRC 通过为止。 */
		for (len = 4; len <= remaining; len++) {
			if (modbus_vendor_crc_ok(tvb, offset, len))
				return len;
		}
		return remaining;
	}
}

int
modbus_vendor_dissect_rtu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
			  const modbus_vendor_profile_t *profile)
{
	const mb_regs_t *R = regs_for_proto(profile->proto);
	int total = (int)tvb_reported_length(tvb);
	int offset = 0;
	int guard = 0;

	if (R == NULL || total < MODBUS_RTU_MIN_LEN)
		return 0;
	if (rtu_frame_len(tvb, 0, total) == 0)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, profile->col_protocol);
	col_clear(pinfo->cinfo, COL_INFO);

	proto_item *ti = proto_tree_add_item(tree, profile->proto, tvb, 0, total, ENC_NA);
	proto_tree *root = proto_item_add_subtree(ti, R->ett_root);

	while (offset < total && guard++ < 512) {
		int len = rtu_frame_len(tvb, offset, total - offset);

		if (len <= 0)
			break;
		dissect_rtu_frame(tvb, offset, len, pinfo, root, R, profile);
		offset += len;
	}
	if (offset < total)
		proto_tree_add_item(root, R->hf[HF_DATA], tvb, offset, total - offset, ENC_NA);
	return total;
}

int
modbus_vendor_dissect_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
			  const modbus_vendor_profile_t *profile)
{
	const mb_regs_t *R = regs_for_proto(profile->proto);
	int total = (int)tvb_reported_length(tvb);
	int offset = 0;
	int guard = 0;

	if (R == NULL || total < 8)
		return 0;
	if (tvb_get_ntohs(tvb, 2) != 0)      /* 协议标识必须为 0 */
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, profile->col_protocol);
	col_clear(pinfo->cinfo, COL_INFO);

	proto_item *ti = proto_tree_add_item(tree, profile->proto, tvb, 0, total, ENC_NA);
	proto_tree *root = proto_item_add_subtree(ti, R->ett_root);

	while (offset + 8 <= total && guard++ < 512) {
		uint16_t mbap_len = tvb_get_ntohs(tvb, offset + 4);
		int len = 6 + (int)mbap_len;

		if (mbap_len < 2 || len > total - offset)
			break;

		proto_item *fi = proto_tree_add_none_format(root, R->hf[HF_FRAME_ITEM], tvb,
							    offset, len, "Modbus/TCP 帧");
		proto_tree *ft = proto_item_add_subtree(fi, R->ett_frame);
		proto_tree_add_item(ft, R->hf[HF_TXN], tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(ft, R->hf[HF_PROTO_ID], tvb, offset + 2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(ft, R->hf[HF_MBAP_LEN], tvb, offset + 4, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(ft, R->hf[HF_UNIT], tvb, offset + 6, 1, ENC_LITTLE_ENDIAN);

		/* PDU 部分按无 CRC 处理：把 PDU 单独切出来解。 */
		tvbuff_t *pdu = tvb_new_subset_length(tvb, offset + 7, len - 7);
		uint8_t fn = tvb_get_uint8(pdu, 0);
		const char *name = fn_name(profile, (uint8_t)(fn & ~MB_FN_EXCEPTION_FLAG));
		proto_item *fni = proto_tree_add_uint_format_value(ft, R->hf[HF_FN], tvb,
								   offset + 7, 1, fn,
								   "0x%02X %s", fn,
								   name ? name : "未知功能码");
		(void)fni;
		if (len - 9 > 0)
			proto_tree_add_item(ft, R->hf[HF_DATA], tvb, offset + 8, len - 9,
					    ENC_NA);

		col_add_fstr(pinfo->cinfo, COL_INFO, "单元 %u %s",
			     tvb_get_uint8(tvb, offset + 6), name ? name : "未知功能码");

		offset += len;
	}
	return total;
}

typedef struct {
	int id;
	const char *suffix;
	const char *name;
	enum ftenum type;
	int display;
	const void *vals;
} mb_hf_spec_t;

static const mb_hf_spec_t g_hf_specs[] = {
	{ HF_UNIT,        "unit",        "单元标识",     FT_UINT8,  BASE_DEC, NULL },
	{ HF_FN,          "fn",          "功能码",       FT_UINT8,  BASE_HEX, VALS(mb_fn_vals) },
	{ HF_START_ADDR,  "start_addr",  "起始地址",     FT_UINT16, BASE_DEC, NULL },
	{ HF_COUNT,       "count",       "数量",         FT_UINT16, BASE_DEC, NULL },
	{ HF_BYTE_COUNT,  "byte_count",  "字节数",       FT_UINT8,  BASE_DEC, NULL },
	{ HF_REG_VALUE,   "reg",         "寄存器值",     FT_UINT16, BASE_DEC, NULL },
	{ HF_REG_ITEM,    "reg_item",    "寄存器",       FT_NONE,   BASE_NONE, NULL },
	{ HF_REGS,        "regs_item",   "寄存器列表",   FT_NONE,   BASE_NONE, NULL },
	{ HF_CRC,         "crc",         "CRC16",        FT_UINT16, BASE_HEX, NULL },
	{ HF_CRC_STATUS,  "crc.ok",      "CRC 校验通过", FT_BOOLEAN, BASE_NONE, NULL },
	{ HF_EXCEPTION,   "exception",   "异常码",       FT_UINT8,  BASE_DEC, VALS(mb_exception_vals) },
	{ HF_TXN,         "mbap.txn",    "事务号",       FT_UINT16, BASE_DEC, NULL },
	{ HF_PROTO_ID,    "mbap.proto",  "协议标识",     FT_UINT16, BASE_DEC, NULL },
	{ HF_MBAP_LEN,    "mbap.len",    "后续长度",     FT_UINT16, BASE_DEC, NULL },
	{ HF_FRAME_ITEM,  "frame_item",  "帧",           FT_NONE,   BASE_NONE, NULL },
	{ HF_DATA,        "data",        "数据",         FT_BYTES,  BASE_NONE, NULL },
};

/* 帧容器与寄存器列表都用 FT_NONE 字段，避免 "field is not of type FT_NONE"。 */

void
modbus_vendor_register(const modbus_vendor_profile_t *profile, module_t *module)
{
	static int *ett_roots[MB_MAX_PROFILES];
	static int *ett_frames[MB_MAX_PROFILES];
	static int *ett_regss[MB_MAX_PROFILES];
	static int *ett_regs_item[MB_MAX_PROFILES];

	if (g_profile_count >= MB_MAX_PROFILES) {
		ws_warning("modbus: profile table full (%u), dropping %s",
			   MB_MAX_PROFILES, proto_get_protocol_filter_name(profile->proto));
		return;
	}

	unsigned slot = g_profile_count;
	mb_regs_t *R = &g_regs[slot];
	R->proto = profile->proto;
	g_profiles[slot] = profile;
	g_profile_count++;

	const char *short_name = proto_get_protocol_filter_name(profile->proto);
	const unsigned spec_count = array_length(g_hf_specs);
	hf_register_info *hf = g_new0(hf_register_info, spec_count);
	for (unsigned i = 0; i < spec_count; i++) {
		const mb_hf_spec_t *spec = &g_hf_specs[i];
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
	ett_frames[slot] = &R->ett_frame;
	ett_regss[slot] = &R->ett_regs;
	ett_regs_item[slot] = &R->ett_reg;
	int *ett[] = { ett_roots[slot], ett_frames[slot], ett_regss[slot], ett_regs_item[slot] };
	proto_register_subtree_array(ett, array_length(ett));

	static bool experts_done;
	if (!experts_done) {
		experts_done = true;
		static ei_register_info ei[] = {
			{ &ei_bad_crc, { "modbus_vendor.crc.bad", PI_CHECKSUM, PI_WARN,
					 "CRC16 校验错误", EXPFILL }},
			{ &ei_bad_len, { "modbus_vendor.len.bad", PI_MALFORMED, PI_WARN,
					 "长度字段异常", EXPFILL }},
			{ &ei_unknown_fn, { "modbus_vendor.fn.unknown", PI_UNDECODED, PI_NOTE,
					    "未专门解码的功能码", EXPFILL }},
		};
		expert_module_t *expert = expert_register_protocol(profile->proto);
		expert_register_field_array(expert, ei, array_length(ei));
	}

	if (module != NULL)
		;  /* 偏好模块由厂家模块自行注册，这里不再重复注册。 */
	(void)g_profiles;
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
