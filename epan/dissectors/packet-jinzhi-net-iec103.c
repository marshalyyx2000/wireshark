/* packet-jinzhi-net-iec103.c
 *
 * 金智（Jinzhi）网络 IEC 60870-5-103 over TCP 6000.
 *
 * APDU: 68H | length (2 bytes, little endian) | control (12 or 13 bytes) | ASDU
 *
 * The control field is IEC 60870-5-104's 4 bytes followed by source station
 * address, 16-bit source device address, destination station address and
 * 16-bit destination device address (plus one spare byte in the 13-byte form).
 * Both lengths appear in the field, so the ASDU start is auto-detected.
 *
 * Basis: 网络103变电站通讯链路层规范 V2.0 / 网络103变电站通讯应用层规范 V2.0.
 * See tools/iec103-docs/jinzhi.md.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tfs.h>
#include <epan/to_str.h>
#include <wsutil/array.h>

#include "packet-iec103-vendor-common.h"

void proto_register_jinzhi_net_iec103(void);
void proto_reg_handoff_jinzhi_net_iec103(void);

#define JZ_START          0x68
#define JZ_HDR_MIN        3          /* 68H + 2 length bytes */
#define JZ_CTRL_STD       4          /* 104 style I/S/U control bytes */
#define JZ_CTRL_LEN_12    12
#define JZ_CTRL_LEN_13    13
#define JZ_APDU_MAX       1024

enum jz_ctrl_len_pref {
	JZ_CTRL_AUTO = 0,
	JZ_CTRL_FIXED_12,
	JZ_CTRL_FIXED_13
};

static int proto_jinzhi_net_iec103;
static int ett_jinzhi;
static int ett_jz_apci;
static int ett_jz_ctrl;
static int ett_jz_addr;

static int hf_jz_start;
static int hf_jz_length;
static int hf_jz_ctrl;
static int hf_jz_frame_type;
static int hf_jz_tx;
static int hf_jz_rx;
static int hf_jz_u_func;
static int hf_jz_src_station;
static int hf_jz_src_dev;
static int hf_jz_dst_station;
static int hf_jz_dst_dev;
static int hf_jz_spare;
static int hf_jz_addr_item;
static int hf_jz_uint;
static int hf_jz_bytes;
static int hf_jz_apdu_item;
static int hf_jz_raw;

static dissector_handle_t jinzhi_net_tcp_handle;

static int jz_ctrl_len_pref = JZ_CTRL_AUTO;

static const enum_val_t jz_ctrl_len_vals[] = {
	{ "auto", "自动识别 (12/13 字节)", JZ_CTRL_AUTO },
	{ "12",   "固定 12 字节",         JZ_CTRL_FIXED_12 },
	{ "13",   "固定 13 字节",         JZ_CTRL_FIXED_13 },
	{ NULL, NULL, 0 }
};

static const value_string jz_frame_type_vals[] = {
	{ 0, "I 格式(信息传输)" },
	{ 1, "S 格式(监视)" },
	{ 2, "U 格式(控制)" },
	{ 0, NULL }
};

static const value_string jz_u_func_vals[] = {
	{ 0x07, "STARTDT 生效" },
	{ 0x0B, "STARTDT 确认" },
	{ 0x13, "STOPDT 生效" },
	{ 0x23, "STOPDT 确认" },
	{ 0x43, "TESTFR 生效" },
	{ 0x83, "TESTFR 确认" },
	{ 0, NULL }
};

/* Vendor TYP names outside the 103 compatible range (application layer 3.x). */
static const value_string jz_extra_asdu_vals[] = {
	{ 0xCB, "ASDU203 联锁数据请求" },
	{ 0xCC, "ASDU204 联锁数据发送" },
	{ 0xDC, "ASDU220 通用历史数据查询" },
	{ 0xDD, "ASDU221 文件召唤/选择" },
	{ 0xDE, "ASDU222 文件目录响应" },
	{ 0xDF, "ASDU223 文件准备就绪" },
	{ 0xE0, "ASDU224 节准备就绪" },
	{ 0xE1, "ASDU225 段的发送" },
	{ 0xE2, "ASDU226 最后段/末节" },
	{ 0xE3, "ASDU227 文件/节确认" },
	{ 0xE4, "ASDU228 遥控校验命令" },
	{ 0xE5, "ASDU229 遥控校验结果" },
	{ 0, NULL }
};

static bool
jz_dissect_extra_asdu(tvbuff_t *tvb, int *offset, int end, packet_info *pinfo _U_,
		      proto_tree *tree, const iec103_vendor_profile_t *profile _U_);

static const value_string jz_extra_cot_vals[] = {
	{ 0x80, "历史数据查询" },
	{ 0x81, "历史数据查询结束" },
	{ 0x82, "文件传输" },
	{ 0, NULL }
};

static iec103_vendor_profile_t jz_profile = {
	0,
	"金智网络103",
	NULL,
	"金智网络103",
	IEC103_POINTS_JINZHI,
	jz_extra_asdu_vals,
	jz_extra_cot_vals,
	jz_dissect_extra_asdu
};

static int
jz_frame_type(uint8_t ctrl0)
{
	if ((ctrl0 & 0x01) == 0)
		return 0;   /* I */
	if ((ctrl0 & 0x02) == 0)
		return 1;   /* S */
	return 2;           /* U */
}

/* ------------------------------------------------------------------ */
/* Vendor-specific ASDU bodies (application layer 3.x)                 */
/* ------------------------------------------------------------------ */

static const value_string jz_history_event_vals[] = {
	{ 1, "动作元件" }, { 2, "装置自检" }, { 3, "运行告警" }, { 4, "档位" },
	{ 5, "软压板" }, { 6, "硬压板" }, { 7, "遥信" }, { 8, "操作信息" },
	{ 0xFF, "所有事件类型" },
	{ 0, NULL }
};

static const value_string jz_scq_cmd_vals[] = {
	{ 1, "选择文件" }, { 2, "召唤文件" }, { 3, "停止激活文件" },
	{ 4, "删除文件" }, { 5, "召唤节" }, { 6, "停止激活节" }, { 7, "召唤目录" },
	{ 0, NULL }
};

static const value_string jz_scq_err_vals[] = {
	{ 0, "缺损" }, { 1, "无被请求的存储空间" }, { 2, "非所期望的通信服务" },
	{ 3, "非所期望的文件名称" }, { 4, "非所期望的节名称" },
	{ 0, NULL }
};

static const value_string jz_lsq_vals[] = {
	{ 1, "不带停止激活的节传输" }, { 2, "带停止激活的节传输" },
	{ 3, "不带停止激活的段传输" }, { 4, "带停止激活的段传输" },
	{ 0, NULL }
};

static const value_string jz_afq_vals[] = {
	{ 1, "文件传输肯定认可" }, { 2, "文件传输否定认可" },
	{ 3, "节传输肯定认可" }, { 4, "节传输否定认可" },
	{ 0, NULL }
};

static const value_string jz_otp_vals[] = {
	{ 1, "分" }, { 2, "合" },
	{ 0, NULL }
};

static const value_string jz_ldt_vals[] = {
	{ 0, "联锁数据(1 字节)" }, { 1, "正常数据(2 字节)" }, { 2, "保护测量(4 字节)" },
	{ 0, NULL }
};

/* cp56 is already 7 bytes; helper mirrors the shared engine's formatting. */
static void
jz_add_cp56(tvbuff_t *tvb, int *offset, int end, proto_tree *tree, const char *label)
{
	if (end - *offset < 7)
		return;
	proto_item *ti = proto_tree_add_bytes_format(tree, hf_jz_bytes, tvb, *offset, 7, NULL,
						     "%s", label);
	(void)ti;
	*offset += 7;
}

static bool
jz_dissect_extra_asdu(tvbuff_t *tvb, int *offset, int end, packet_info *pinfo _U_,
		      proto_tree *tree, const iec103_vendor_profile_t *profile _U_)
{
	int start = *offset - IEC103_ASDU_HDR_LEN;
	uint8_t typ = tvb_get_uint8(tvb, start);
	int o = *offset;

	/* Fields below use simple proto_tree_add_uint/bytes formatting; the exact
	 * widths come from the application layer tables in jinzhi.md. */
	const char *label = try_val_to_str(typ, jz_extra_asdu_vals);
	if (label == NULL)
		return false;

	switch (typ) {
	case 0xDC:   /* ASDU220 通用历史数据查询 */
		if (o < end)
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 1,
						   tvb_get_uint8(tvb, o), "事件类型 %s",
						   val_to_str_const(tvb_get_uint8(tvb, o),
								    jz_history_event_vals, "未定义"));
		o++;
		if (end - o >= 7) {
			proto_tree_add_bytes_format(tree, hf_jz_bytes, tvb, o, 7, NULL, "开始时间");
			o += 7;
		}
		if (end - o >= 7) {
			proto_tree_add_bytes_format(tree, hf_jz_bytes, tvb, o, 7, NULL, "结束时间");
			o += 7;
		}
		if (o < end)
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 1, tvb_get_uint8(tvb, o),
						   "返回信息标识 RII");
		o++;
		break;

	case 0xDD:   /* ASDU221 文件目录召唤 / 选择 / 召唤节 */
		if (end - o >= 2) {
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 2,
						   tvb_get_letohs(tvb, o), "文件名称 FNAM");
			o += 2;
		}
		if (o < end) {
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 1, tvb_get_uint8(tvb, o),
						   "节名称 SNAM");
			o++;
		}
		if (o < end) {
			uint8_t scq = tvb_get_uint8(tvb, o);
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 1, scq,
						   "选择限定词 SCQ 命令=%s 错误码=%s",
						   val_to_str_const(scq & 0x0F, jz_scq_cmd_vals,
								    "保留"),
						   val_to_str_const((scq >> 4) & 0x0F,
								    jz_scq_err_vals, "无"));
			o++;
		}
		break;

	case 0xDE: {  /* ASDU222 文件目录响应：重复条目 */
		int count = tvb_get_uint8(tvb, start + 1) & 0x7F;
		for (int i = 0; i < count && end - o >= 14; i++) {
			proto_tree_add_bytes_format(tree, hf_jz_bytes, tvb, o, 14, NULL,
						    "文件条目 %d FNAM=%u FLEN=%u SOF=0x%02X",
						    i + 1, tvb_get_letohs(tvb, o),
						    tvb_get_letohl(tvb, o + 2),
						    tvb_get_uint8(tvb, o + 6));
			o += 14;
		}
		break;
	}

	case 0xDF:   /* ASDU223 文件准备就绪 */
		if (end - o >= 2) {
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 2, tvb_get_letohs(tvb, o),
						   "文件名称 FNAM");
			o += 2;
		}
		if (o < end)
			o++;
		if (end - o >= 4) {
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 4, tvb_get_letohl(tvb, o),
						   "文件长度 FLEN");
			o += 4;
		}
		if (o < end)
			o++;
		break;

	case 0xE0:   /* ASDU224 节准备就绪 */
		if (end - o >= 2) {
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 2, tvb_get_letohs(tvb, o),
						   "文件名称 FNAM");
			o += 2;
		}
		if (o < end)
			o++;
		if (end - o >= 4) {
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 4, tvb_get_letohl(tvb, o),
						   "节长度 SLEN");
			o += 4;
		}
		if (o < end) {
			uint8_t srq = tvb_get_uint8(tvb, o);
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 1, srq,
						   "准备好限定词 SRQ %s",
						   (srq & 0x80) ? "节未准备好装载" : "节准备好装载");
			o++;
		}
		break;

	case 0xE1: {  /* ASDU225 段的发送 */
		int dlen = 0;
		if (end - o >= 2) {
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 2, tvb_get_letohs(tvb, o),
						   "文件名称 FNAM");
			o += 2;
		}
		if (o < end)
			o++;
		if (end - o >= 2) {
			dlen = tvb_get_letohs(tvb, o);
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 2, dlen, "段长度 DLEN");
			o += 2;
		}
		if (dlen > 0 && end - o >= dlen) {
			proto_tree_add_bytes_format(tree, hf_jz_bytes, tvb, o, dlen, NULL, "段数据");
			o += dlen;
		}
		break;
	}

	case 0xE2:   /* ASDU226 最后段 / 末节 */
		if (end - o >= 2) {
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 2, tvb_get_letohs(tvb, o),
						   "文件名称 FNAM");
			o += 2;
		}
		if (o < end) {
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 1, tvb_get_uint8(tvb, o),
						   "最后节段限定词 LSQ %s",
						   val_to_str_const(tvb_get_uint8(tvb, o),
								    jz_lsq_vals, "保留"));
			o++;
		}
		break;

	case 0xE3:   /* ASDU227 文件 / 节确认 */
		if (o < end) {
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 1, tvb_get_uint8(tvb, o),
						   "确认限定词 AFQ %s",
						   val_to_str_const(tvb_get_uint8(tvb, o) & 0x0F,
								    jz_afq_vals, "保留"));
			o++;
		}
		break;

	case 0xE4:   /* ASDU228 遥控校验命令 */
	case 0xE5:   /* ASDU229 遥控校验结果 */
		if (o < end) {
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 1, tvb_get_uint8(tvb, o),
						   "返回信息标识 RII");
			o++;
		}
		if (o < end)
			o++;   /* NOG */
		if (end - o >= 2) {
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 2, tvb_get_letohs(tvb, o),
						   "厂站地址 FADDR");
			o += 2;
		}
		if (end - o >= 2) {
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 2, tvb_get_letohs(tvb, o),
						   "装置地址 DADDR");
			o += 2;
		}
		if (end - o >= 2) {
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 2, tvb_get_letohs(tvb, o),
						   "条目号 GIN");
			o += 2;
		}
		if (o < end) {
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 1, tvb_get_uint8(tvb, o),
						   "操作类型 %s",
						   val_to_str_const(tvb_get_uint8(tvb, o), jz_otp_vals,
								    "未定义"));
			o++;
		}
		break;

	case 0xCB: {  /* 联锁数据请求 */
		uint8_t lqt = 0;
		if (o < end) {
			lqt = tvb_get_uint8(tvb, o);
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 1, lqt,
						   "请求类型 LQT %s",
						   lqt == 0 ? "联锁数据" : "正常数据");
			o++;
		}
		while (end - o >= 4) {
			proto_tree_add_bytes_format(tree, hf_jz_bytes, tvb, o, 4, NULL,
						    "条目 装置地址=%u GIN=0x%04X",
						    tvb_get_letohs(tvb, o),
						    tvb_get_letohs(tvb, o + 2));
			o += 4;
		}
		if (o < end) {
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 1, tvb_get_uint8(tvb, o),
						   "返回信息标识 RII");
			o++;
		}
		break;
	}

	case 0xCC: {  /* 联锁数据发送 */
		uint8_t ldt = 0;
		int vlen;
		if (end - o >= 2) {
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 2, tvb_get_letohs(tvb, o),
						   "联锁条目 GIN");
			o += 2;
		}
		if (o < end) {
			ldt = tvb_get_uint8(tvb, o);
			proto_tree_add_uint_format(tree, hf_jz_uint, tvb, o, 1, ldt,
						   "数据类型 LDT %s",
						   val_to_str_const(ldt, jz_ldt_vals, "保留"));
			o++;
		}
		vlen = ldt == 0 ? 1 : (ldt == 1 ? 2 : (ldt == 2 ? 4 : 0));
		if (vlen > 0 && end - o >= vlen) {
			proto_tree_add_bytes_format(tree, hf_jz_bytes, tvb, o, vlen, NULL, "值");
			o += vlen;
		}
		break;
	}

	default:
		return false;
	}

	*offset = o;
	return true;
}

/* ------------------------------------------------------------------ */
static int
jz_ctrl_candidates(int *out, int max)
{
	int n = 0;

	if (jz_ctrl_len_pref != JZ_CTRL_FIXED_13 && n < max)
		out[n++] = JZ_CTRL_LEN_12;
	if (jz_ctrl_len_pref != JZ_CTRL_FIXED_12 && n < max)
		out[n++] = JZ_CTRL_LEN_13;
	return n;
}

/*
 * Locate the ASDU start inside one APDU. Returns the control length in use, or
 * 0 when no candidate position can hold an ASDU header.
 *
 * @p body_len is the value from the length field: it counts control + ASDU and
 * excludes the 3-byte 68H/len/len prefix (see jinzhi.md).
 */
static int
jz_pick_ctrl_len(tvbuff_t *tvb, int apdu_start, int body_len, bool *asdu_ok)
{
	int candidates[2];
	int count = jz_ctrl_candidates(candidates, 2);

	*asdu_ok = false;
	for (int i = 0; i < count; i++) {
		int ctrl_len = candidates[i];
		int asdu_off = apdu_start + JZ_HDR_MIN + ctrl_len;
		int remaining = body_len - ctrl_len;

		if (remaining < IEC103_ASDU_HDR_LEN)
			continue;
		if (asdu_off + remaining > (int)tvb_reported_length(tvb))
			continue;
		if (iec103_vendor_looks_like_asdu_ext(tvb, asdu_off, remaining, &jz_profile)) {
			*asdu_ok = true;
			return ctrl_len;
		}
	}

	return count > 0 ? candidates[0] : 0;
}

static void
jz_dissect_ctrl(tvbuff_t *tvb, int offset, proto_tree *tree, int ctrl_len,
		packet_info *pinfo)
{
	uint8_t c0 = tvb_get_uint8(tvb, offset);
	int ftype = jz_frame_type(c0);

	proto_item *ci = proto_tree_add_item(tree, hf_jz_ctrl, tvb, offset, ctrl_len, ENC_NA);
	proto_tree *ct = proto_item_add_subtree(ci, ett_jz_ctrl);
	proto_item_append_text(ci, " %s", val_to_str_const(ftype, jz_frame_type_vals, "未知"));

	proto_tree_add_uint(ct, hf_jz_frame_type, tvb, offset, 1, (uint32_t)ftype);

	if (ftype == 0) {
		uint16_t ns = (uint16_t)(((c0 & 0xFE) >> 1) |
					 (tvb_get_uint8(tvb, offset + 1) << 7));
		uint16_t nr = (uint16_t)(((tvb_get_uint8(tvb, offset + 2) & 0xFE) >> 1) |
					 (tvb_get_uint8(tvb, offset + 3) << 7));
		proto_tree_add_uint(ct, hf_jz_tx, tvb, offset, 2, ns);
		proto_tree_add_uint(ct, hf_jz_rx, tvb, offset + 2, 2, nr);
		col_append_fstr(pinfo->cinfo, COL_INFO, "I N(S)=%u N(R)=%u", ns, nr);
	} else if (ftype == 1) {
		uint16_t nr = (uint16_t)(((tvb_get_uint8(tvb, offset + 2) & 0xFE) >> 1) |
					 (tvb_get_uint8(tvb, offset + 3) << 7));
		proto_tree_add_uint(ct, hf_jz_rx, tvb, offset + 2, 2, nr);
		col_append_fstr(pinfo->cinfo, COL_INFO, "S N(R)=%u", nr);
	} else {
		proto_item *uf = proto_tree_add_item(ct, hf_jz_u_func, tvb, offset, 1, ENC_NA);
		proto_item_append_text(uf, " (%s)",
				       val_to_str_const(c0, jz_u_func_vals, "未定义"));
		col_append_fstr(pinfo->cinfo, COL_INFO, "U %s",
				val_to_str_const(c0, jz_u_func_vals, "未定义"));
	}

	/* Extended addressing: source/destination station and 16-bit device. */
	if (ctrl_len >= JZ_CTRL_LEN_12) {
		int o = offset + JZ_CTRL_STD;
		uint8_t src_st = tvb_get_uint8(tvb, o);
		uint16_t src_dev = tvb_get_letohs(tvb, o + 1);
		uint8_t dst_st = tvb_get_uint8(tvb, o + 3);
		uint16_t dst_dev = tvb_get_letohs(tvb, o + 4);

		proto_item *ai = proto_tree_add_none_format(ct, hf_jz_addr_item, tvb, o, 0,
							    "扩展地址 源 %u/%u → 目的 %u/%u",
							    src_st, src_dev, dst_st, dst_dev);
		proto_tree *at = proto_item_add_subtree(ai, ett_jz_addr);

		proto_tree_add_item(at, hf_jz_src_station, tvb, o, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(at, hf_jz_src_dev, tvb, o + 1, 2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(at, hf_jz_dst_station, tvb, o + 3, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(at, hf_jz_dst_dev, tvb, o + 4, 2, ENC_LITTLE_ENDIAN);
		if (ctrl_len >= JZ_CTRL_LEN_13)
			proto_tree_add_item(at, hf_jz_spare, tvb, o + 6, 1, ENC_NA);

		col_append_fstr(pinfo->cinfo, COL_INFO, " %u/%u→%u/%u",
				src_st, src_dev, dst_st, dst_dev);
	}
}

/* ------------------------------------------------------------------ */

static int
dissect_jinzhi_net(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	int total = (int)tvb_reported_length(tvb);
	int offset = 0;

	if (total < JZ_HDR_MIN)
		return 0;
	if (tvb_get_uint8(tvb, 0) != JZ_START)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, jz_profile.col_protocol);
	col_clear(pinfo->cinfo, COL_INFO);

	proto_item *ti = proto_tree_add_item(tree, proto_jinzhi_net_iec103, tvb, 0, total,
					     ENC_NA);
	proto_item_set_text(ti, "金智网络103/TCP");
	proto_tree *root = proto_item_add_subtree(ti, ett_jinzhi);

	while (offset + JZ_HDR_MIN <= total) {
		int remaining = total - offset;
		int body_len, apdu_len, ctrl_len, asdu_off, asdu_len;
		bool asdu_ok = false;

		if (tvb_get_uint8(tvb, offset) != JZ_START)
			break;

		body_len = tvb_get_letohs(tvb, offset + 1);
		if (body_len < JZ_CTRL_LEN_12 || body_len + JZ_HDR_MIN > JZ_APDU_MAX)
			break;

		apdu_len = body_len + JZ_HDR_MIN;
		if (apdu_len > remaining)
			apdu_len = remaining;   /* truncated capture */
		if (apdu_len <= JZ_HDR_MIN)
			break;

		proto_item *ape = proto_tree_add_none_format(root, hf_jz_apdu_item, tvb, offset,
							     apdu_len, "APDU");
		proto_tree *apci = proto_item_add_subtree(ape, ett_jz_apci);

		proto_tree_add_item(apci, hf_jz_start, tvb, offset, 1, ENC_NA);
		proto_item *li = proto_tree_add_item(apci, hf_jz_length, tvb, offset + 1, 2,
						     ENC_LITTLE_ENDIAN);
		proto_item_append_text(li, " (APDU 共 %d 字节)", apdu_len);

		ctrl_len = jz_pick_ctrl_len(tvb, offset, body_len, &asdu_ok);
		if (ctrl_len == 0) {
			proto_item_append_text(ape, " 控制域长度无法识别");
			offset += apdu_len;
			continue;
		}

		jz_dissect_ctrl(tvb, offset + JZ_HDR_MIN, apci, ctrl_len, pinfo);
		proto_item_append_text(ape, " 控制域 %d 字节", ctrl_len);

		col_append_fstr(pinfo->cinfo, COL_INFO, " ");

		asdu_off = offset + JZ_HDR_MIN + ctrl_len;
		asdu_len = body_len - ctrl_len;
		if (asdu_len > apdu_len - JZ_HDR_MIN - ctrl_len)
			asdu_len = apdu_len - JZ_HDR_MIN - ctrl_len;
		if (asdu_len >= IEC103_ASDU_HDR_LEN && asdu_ok) {
			iec103_vendor_dissect_one_asdu(tvb, asdu_off, asdu_len, pinfo, apci,
						       &jz_profile);
		} else if (asdu_len > 0) {
			proto_tree_add_item(apci, hf_jz_raw, tvb, asdu_off, asdu_len, ENC_NA);
		}

		offset += apdu_len;
	}

	return total;
}

void
proto_register_jinzhi_net_iec103(void)
{
	static hf_register_info hf[] = {
		{ &hf_jz_start,
		  { "启动字符", "jinzhi_net_iec103.start", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},
		{ &hf_jz_length,
		  { "APDU长度", "jinzhi_net_iec103.length", FT_UINT16, BASE_DEC, NULL, 0,
		    "包含控制域与 ASDU 的字节数（小端）", HFILL }},
		{ &hf_jz_ctrl,
		  { "控制域", "jinzhi_net_iec103.apci.ctrl", FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_jz_frame_type,
		  { "帧格式", "jinzhi_net_iec103.apci.frame_type", FT_UINT8, BASE_DEC,
		    VALS(jz_frame_type_vals), 0, NULL, HFILL }},
		{ &hf_jz_tx,
		  { "发送序号 N(S)", "jinzhi_net_iec103.apci.tx", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_jz_rx,
		  { "接收序号 N(R)", "jinzhi_net_iec103.apci.rx", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_jz_u_func,
		  { "U 帧功能", "jinzhi_net_iec103.apci.u_func", FT_UINT8, BASE_HEX,
		    VALS(jz_u_func_vals), 0, NULL, HFILL }},
		{ &hf_jz_src_station,
		  { "源厂站地址", "jinzhi_net_iec103.apci.src_station", FT_UINT8, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_jz_src_dev,
		  { "源设备地址", "jinzhi_net_iec103.apci.src_dev", FT_UINT16, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_jz_dst_station,
		  { "目的厂站地址", "jinzhi_net_iec103.apci.dst_station", FT_UINT8, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_jz_dst_dev,
		  { "目的设备地址", "jinzhi_net_iec103.apci.dst_dev", FT_UINT16, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_jz_spare,
		  { "备用", "jinzhi_net_iec103.apci.spare", FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_jz_addr_item,
		  { "扩展地址", "jinzhi_net_iec103.apci.addr", FT_NONE, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_jz_uint,
		  { "字段值", "jinzhi_net_iec103.field_uint", FT_UINT32, BASE_DEC, NULL, 0,
		    "扩展 ASDU 的数值字段", HFILL }},
		{ &hf_jz_bytes,
		  { "字段数据", "jinzhi_net_iec103.field_bytes", FT_BYTES, BASE_NONE, NULL, 0,
		    "扩展 ASDU 的字节字段", HFILL }},
		{ &hf_jz_apdu_item,
		  { "APDU", "jinzhi_net_iec103.apdu", FT_NONE, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_jz_raw,
		  { "数据", "jinzhi_net_iec103.data", FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
	};

	static int *ett[] = { &ett_jinzhi, &ett_jz_apci, &ett_jz_ctrl, &ett_jz_addr };

	proto_jinzhi_net_iec103 = proto_register_protocol(
		"金智网络103/TCP",
		"金智网络103",
		"jinzhi_net_iec103");

	proto_register_field_array(proto_jinzhi_net_iec103, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	jz_profile.proto = proto_jinzhi_net_iec103;

	jinzhi_net_tcp_handle = register_dissector("jinzhi_net_iec103", dissect_jinzhi_net,
						   proto_jinzhi_net_iec103);

	iec103_vendor_register(&jz_profile);

	module_t *mod = prefs_register_protocol(proto_jinzhi_net_iec103, NULL);
	iec103_vendor_register_prefs(mod, "金智网络103");
	prefs_register_enum_preference(mod, "apci_ctrl_len", "APCI 控制域长度",
		"12 字节或 13 字节（现场两种实现都有）；自动识别时用 ASDU 头校验",
		&jz_ctrl_len_pref, jz_ctrl_len_vals, false);
}

void
proto_reg_handoff_jinzhi_net_iec103(void)
{
	/* Neutral capture policy: TCP 6000 is decoded only after the user picks
	 * 网络103 → 金智网络103规约解析, which applies Decode As. */
	dissector_add_for_decode_as("tcp.port", jinzhi_net_tcp_handle);
	iec103_points_init();
}
