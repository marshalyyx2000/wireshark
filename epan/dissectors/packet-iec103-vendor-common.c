/* packet-iec103-vendor-common.c
 *
 * Shared IEC 60870-5-103 engine for vendor variants.
 *
 * Supports FT1.2 serial framing, raw ASDU over TCP and one ASDU per UDP
 * datagram, with a common ASDU field layout:
 *   TYP | VSQ | COT | COMADDR | FUN | INF | <body>
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

#include "packet-iec103-vendor-common.h"
#include "packet-iec103-points.h"

#define MAX_PROFILES 4

typedef enum {
	HF_CTRL,
	HF_CTRL_PRM,
	HF_CTRL_FCB,
	HF_CTRL_FCV,
	HF_CTRL_ACD,
	HF_CTRL_DFC,
	HF_CTRL_FUNC,
	HF_LINKADDR,
	HF_CHECKSUM,
	HF_STOPCHAR,
	HF_TYPEID,
	HF_VSQ,
	HF_VSQ_SQ,
	HF_VSQ_NUM,
	HF_COT,
	HF_COMADDR,
	HF_FUN,
	HF_INF,
	HF_DPI,
	HF_DPI_IV,
	HF_DPI_NT,
	HF_DPI_SB,
	HF_DPI_BL,
	HF_SPI,
	HF_SCN,
	HF_RII,
	HF_DCO,
	HF_NGD,
	HF_NGD_COUNT,
	HF_NGD_CONT,
	HF_NOG,
	HF_GIN_GROUP,
	HF_GIN_ENTRY,
	HF_KOD,
	HF_GDD_TYPE,
	HF_GDD_SIZE,
	HF_GDD_NUM,
	HF_GID,
	HF_FAN,
	HF_NOF,
	HF_NOT,
	HF_NDV,
	HF_NFE,
	HF_TOO,
	HF_TOV,
	HF_ACC,
	HF_RET,
	HF_RPV,
	HF_RSV,
	HF_RFA,
	HF_SOF,
	HF_SOF_TP,
	HF_SOF_TM,
	HF_SOF_TEST,
	HF_SOF_OTEV,
	HF_CP32,
	HF_CP32_MS,
	HF_CP32_MIN,
	HF_CP32_IV,
	HF_CP32_HOUR,
	HF_CP32_SU,
	HF_CP56,
	HF_CP56_MS,
	HF_CP56_MIN,
	HF_CP56_IV,
	HF_CP56_HOUR,
	HF_CP56_SU,
	HF_CP56_DAY,
	HF_CP56_DOW,
	HF_CP56_MONTH,
	HF_CP56_YEAR,
	HF_ASDU_ITEM,
	HF_ENTRY_ITEM,
	HF_SDV,
	HF_RAW,
	HF_COUNT
} iec103_hf_id_t;

typedef struct {
	int proto;
	int ett_root;
	int ett_ctrl;
	int ett_asdu;
	int ett_entry;
	int ett_cp32;
	int ett_cp56;
	int hf[HF_COUNT];
} iec103_regs_t;

static iec103_regs_t g_regs[MAX_PROFILES];
static unsigned g_profile_count;

static expert_field ei_bad_length;
static expert_field ei_bad_startchar;
static expert_field ei_bad_stopchar;
static expert_field ei_unknown_asdu;

static const value_string func_pri_vals[] = {
	{ 0,  "复位通信单元 C_RCU_NA_3" },
	{ 3,  "发送/确认 用户数据" },
	{ 4,  "发送/无回答 用户数据" },
	{ 7,  "复位帧计数位 C_RFB_NA_3" },
	{ 9,  "召唤链路状态 C_RLK_NA_3" },
	{ 10, "召唤1级数据 C_PL1_NA_3" },
	{ 11, "召唤2级数据 C_PL2_NA_3" },
	{ 0, NULL }
};

static const value_string func_sec_vals[] = {
	{ 0,  "确认 M_CON_NA_3" },
	{ 1,  "链路忙 M_BY_NA_3" },
	{ 8,  "以数据响应" },
	{ 9,  "无所召唤数据 M_NV_NA_3" },
	{ 11, "响应链路状态 M_LKR_NA_3" },
	{ 0, NULL }
};

static const value_string asdu_type_vals[] = {
	{ 1,  "ASDU1 带时标的报文(遥信)" },
	{ 2,  "ASDU2 保护动作事件" },
	{ 3,  "ASDU3 被测值(测量II)" },
	{ 4,  "ASDU4 带相对时间的故障序号" },
	{ 5,  "ASDU5 标识" },
	{ 6,  "ASDU6 时间同步" },
	{ 7,  "ASDU7 总查询启动" },
	{ 8,  "ASDU8 总查询终止" },
	{ 9,  "ASDU9 被测值(测量II扩展)" },
	{ 10, "ASDU10 通用分类数据" },
	{ 11, "ASDU11 通用分类标识" },
	{ 20, "ASDU20 一般命令" },
	{ 21, "ASDU21 通用分类命令" },
	{ 23, "ASDU23 被记录的扰动表" },
	{ 24, "ASDU24 扰动数据传输命令" },
	{ 25, "ASDU25 扰动数据传输认可" },
	{ 26, "ASDU26 扰动数据传输准备就绪" },
	{ 27, "ASDU27 通道传输准备就绪" },
	{ 28, "ASDU28 带标志状态变位准备就绪" },
	{ 29, "ASDU29 传送带标志的状态变位" },
	{ 30, "ASDU30 传输扰动值" },
	{ 31, "ASDU31 传送结束" },
	{ 0, NULL }
};

static const value_string cot_vals[] = {
	{ 1,  "自发(突发)" },
	{ 2,  "循环" },
	{ 3,  "复位FCB" },
	{ 4,  "复位CU" },
	{ 5,  "启动/重新启动" },
	{ 6,  "电源合上" },
	{ 7,  "测试模式" },
	{ 8,  "时间同步" },
	{ 9,  "总查询(总召唤)" },
	{ 10, "总查询终止" },
	{ 11, "当地操作" },
	{ 12, "远方操作" },
	{ 20, "命令肯定认可" },
	{ 21, "命令否定认可" },
	{ 31, "扰动数据传输" },
	{ 0, NULL }
};

static const value_string dpi_vals[] = {
	{ 0, "不确定" },
	{ 1, "分" },
	{ 2, "合" },
	{ 3, "不确定/无效" },
	{ 0, NULL }
};

static const value_string gdd_type_vals[] = {
	{ 0,  "无数据" },
	{ 1,  "OS8ASCII" },
	{ 2,  "BS1 位串" },
	{ 3,  "UI 无符号整数" },
	{ 4,  "I 整数" },
	{ 5,  "UF 无符号浮点" },
	{ 6,  "F 浮点" },
	{ 7,  "R32.23 短实数" },
	{ 8,  "R64.53 实数" },
	{ 9,  "双点信息" },
	{ 10, "单点信息" },
	{ 11, "带瞬变差错双点信息" },
	{ 23, "结构" },
	{ 0, NULL }
};

static const value_string too_vals[] = {
	{ 1,  "选择故障" },
	{ 2,  "请求扰动数据" },
	{ 3,  "中止扰动数据" },
	{ 8,  "请求通道" },
	{ 9,  "中止通道" },
	{ 16, "请求带标志的状态变位" },
	{ 17, "中止带标志的状态变位" },
	{ 24, "请求被记录扰动表" },
	{ 32, "扰动数据传输结束" },
	{ 64, "扰动数据传输认可(肯定)" },
	{ 65, "扰动数据传输不认可(否定)" },
	{ 0, NULL }
};

static const value_string tov_vals[] = {
	{ 0, "未用" },
	{ 1, "瞬时值" },
	{ 0, NULL }
};

/* ------------------------------------------------------------------ */

static iec103_regs_t *
regs_for_proto(int proto)
{
	for (unsigned i = 0; i < g_profile_count; i++) {
		if (g_regs[i].proto == proto)
			return &g_regs[i];
	}
	return NULL;
}

/* ASDU body length for the fixed-size types; -1 means "consume to end".
 * ASDU2 may omit the trailing CP56Time2a (4-byte CP32 fallback), so it is
 * handled in asdu_pdu_len() where the remaining length is known. */
static int
asdu_fixed_body_len(uint8_t typ)
{
	switch (typ) {
	case 1:  return 1 + 4;    /* DPI + CP32Time2a */
	case 3:  return -1;       /* measured values: rest of PDU */
	case 4:  return 2 + 2;    /* FAN + RET */
	case 6:  return 7;        /* CP56Time2a */
	case 7:  return 1;        /* SCN */
	case 8:  return 1;        /* SCN */
	case 20: return 2;        /* DCO + RII */
	case 24: return 1;        /* TOO */
	case 25: return 1;        /* TOO */
	case 26: return 1 + 2 + 2 + 1 + 2;  /* TOV + FAN + NOF + ACC + NFE */
	case 27: return 1 + 2 + 1 + 4 + 4 + 4; /* TOV + FAN + ACC + RPV + RSV + RFA */
	case 28: return 1 + 2 + 1;          /* TOV + FAN + NOT */
	case 29: return 1;        /* SPI (variable when NOT > 1) */
	case 31: return 1;        /* TOO */
	default: return -1;
	}
}

static int
asdu_scan_len(tvbuff_t *tvb, int offset, int remaining)
{
	/* Walk forward until another plausible ASDU type starts. */
	for (int scan = IEC103_ASDU_HDR_LEN; scan < remaining; scan++) {
		if (!iec103_vendor_looks_like_asdu(tvb, offset + scan, remaining - scan))
			continue;
		return scan;
	}
	return remaining;
}

bool
iec103_vendor_looks_like_asdu(tvbuff_t *tvb, int offset, int remaining)
{
	if (remaining < IEC103_ASDU_HDR_LEN)
		return false;

	uint8_t typ = tvb_get_uint8(tvb, offset);
	switch (typ) {
	case 1: case 2: case 3: case 4: case 5: case 6: case 7: case 8:
	case 9: case 10: case 11: case 20: case 21:
	case 23: case 24: case 25: case 26: case 27: case 28: case 29:
	case 30: case 31:
		break;
	default:
		return false;
	}

	uint8_t cot = tvb_get_uint8(tvb, offset + 2);
	if (cot == 0 || cot > 63)
		return false;

	return true;
}

static int
asdu_pdu_len(tvbuff_t *tvb, int offset, int remaining)
{
	uint8_t typ, vsq;
	int fixed;

	if (remaining < IEC103_ASDU_HDR_LEN)
		return remaining;

	if (!iec103_vendor_looks_like_asdu(tvb, offset, remaining))
		return asdu_scan_len(tvb, offset, remaining);

	typ = tvb_get_uint8(tvb, offset);
	vsq = tvb_get_uint8(tvb, offset + 1);

	fixed = asdu_fixed_body_len(typ);
	if (fixed >= 0) {
		int len = IEC103_ASDU_HDR_LEN + fixed;
		return (len <= remaining) ? len : remaining;
	}

	switch (typ) {
	case 23: {
		/* NOF(2) + NUM*(FAN(2)+SOF(1)+CP56(7)) */
		int len = IEC103_ASDU_HDR_LEN + 2 + (vsq & 0x7F) * 10;
		return (len <= remaining) ? len : remaining;
	}
	case 2: {
		/* DPI + RET + FAN + CP56Time2a, or CP32Time2a in short captures. */
		int len = IEC103_ASDU_HDR_LEN + 1 + 2 + 2 + 7;
		if (len <= remaining)
			return len;
		len = IEC103_ASDU_HDR_LEN + 1 + 2 + 2 + 4;
		return (len <= remaining) ? len : remaining;
	}
	case 30: {
		/* NDV then that many 2-byte samples; never read past the PDU. */
		int len = IEC103_ASDU_HDR_LEN;
		uint8_t ndv;

		if (len >= remaining)
			return remaining;
		ndv = tvb_get_uint8(tvb, offset + len);
		len += 1 + (int)ndv * 2;
		return (len <= remaining) ? len : remaining;
	}
	case 10:
	case 21: {
		/* Walk GIN/KOD/GDD/GID entries. */
		int pos = offset + IEC103_ASDU_HDR_LEN;
		int end = offset + remaining;
		bool is_command = (typ == 21);
		uint8_t ngd;

		if (pos >= end)
			return remaining;
		ngd = tvb_get_uint8(tvb, pos);
		pos++;
		if (is_command && pos < end) {
			pos++;   /* NOG */
		}
		unsigned count = ngd & 0x3F;
		for (unsigned i = 0; i < count && pos + 6 <= end; i++) {
			uint8_t datatype = tvb_get_uint8(tvb, pos + 3);
			uint8_t datasize = tvb_get_uint8(tvb, pos + 4);
			uint8_t datanum = tvb_get_uint8(tvb, pos + 5) & 0x7F;
			pos += 6;
			if (datatype != 23 && datasize > 0 && datanum > 0) {
				int dlen = (int)datasize * (int)datanum;
				if (pos + dlen > end)
					return end - offset;
				pos += dlen;
			}
		}
		return (pos > end ? end : pos) - offset;
	}
	default:
		return asdu_scan_len(tvb, offset, remaining);
	}
}

static void
add_cp32(tvbuff_t *tvb, int *offset, proto_tree *tree, const iec103_regs_t *R)
{
	uint16_t ms = tvb_get_letohs(tvb, *offset);
	uint8_t minute = tvb_get_uint8(tvb, *offset + 2) & 0x3F;
	uint8_t hour = tvb_get_uint8(tvb, *offset + 3) & 0x1F;
	nstime_t ts;

	memset(&ts, 0, sizeof(ts));
	ts.secs = hour * 3600 + minute * 60 + ms / 1000;
	ts.nsecs = (int)(ms % 1000) * 1000000;

	proto_item *ti = proto_tree_add_time(tree, R->hf[HF_CP32], tvb, *offset, 4, &ts);
	proto_tree *t = proto_item_add_subtree(ti, R->ett_cp32);
	proto_tree_add_item(t, R->hf[HF_CP32_MS], tvb, *offset, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(t, R->hf[HF_CP32_MIN], tvb, *offset + 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(t, R->hf[HF_CP32_IV], tvb, *offset + 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(t, R->hf[HF_CP32_HOUR], tvb, *offset + 3, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(t, R->hf[HF_CP32_SU], tvb, *offset + 3, 1, ENC_LITTLE_ENDIAN);
	*offset += 4;
}

static void
add_cp56(tvbuff_t *tvb, int *offset, proto_tree *tree, const iec103_regs_t *R)
{
	uint16_t ms = tvb_get_letohs(tvb, *offset);
	uint8_t minute = tvb_get_uint8(tvb, *offset + 2) & 0x3F;
	uint8_t hour = tvb_get_uint8(tvb, *offset + 3) & 0x1F;
	uint8_t day = tvb_get_uint8(tvb, *offset + 4) & 0x1F;
	uint8_t month = tvb_get_uint8(tvb, *offset + 5) & 0x0F;
	uint8_t year = tvb_get_uint8(tvb, *offset + 6) & 0x7F;
	nstime_t ts;

	memset(&ts, 0, sizeof(ts));
	if (month >= 1 && month <= 12 && day >= 1 && day <= 31) {
		struct tm tm;
		memset(&tm, 0, sizeof(tm));
		tm.tm_year = year + 100;
		tm.tm_mon = month - 1;
		tm.tm_mday = day;
		tm.tm_hour = hour;
		tm.tm_min = minute;
		tm.tm_sec = ms / 1000;
		ts.secs = mktime(&tm);
		ts.nsecs = (int)(ms % 1000) * 1000000;
	}

	proto_item *ti = proto_tree_add_time(tree, R->hf[HF_CP56], tvb, *offset, 7, &ts);
	proto_tree *t = proto_item_add_subtree(ti, R->ett_cp56);
	proto_tree_add_item(t, R->hf[HF_CP56_MS], tvb, *offset, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(t, R->hf[HF_CP56_MIN], tvb, *offset + 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(t, R->hf[HF_CP56_IV], tvb, *offset + 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(t, R->hf[HF_CP56_HOUR], tvb, *offset + 3, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(t, R->hf[HF_CP56_SU], tvb, *offset + 3, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(t, R->hf[HF_CP56_DAY], tvb, *offset + 4, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(t, R->hf[HF_CP56_DOW], tvb, *offset + 4, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(t, R->hf[HF_CP56_MONTH], tvb, *offset + 5, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(t, R->hf[HF_CP56_YEAR], tvb, *offset + 6, 1, ENC_LITTLE_ENDIAN);
	*offset += 7;
}

static void
add_dpi(tvbuff_t *tvb, int offset, proto_tree *tree, const iec103_regs_t *R)
{
	proto_tree_add_item(tree, R->hf[HF_DPI], tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, R->hf[HF_DPI_IV], tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, R->hf[HF_DPI_NT], tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, R->hf[HF_DPI_SB], tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, R->hf[HF_DPI_BL], tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

/* ASDU10 / ASDU21: NGD [NOG] { GIN KOD GDD GID } */
static void
dissect_generic(tvbuff_t *tvb, int *offset, int end, proto_tree *tree,
		const iec103_regs_t *R, packet_info *pinfo, bool is_command)
{
	if (*offset >= end)
		return;

	uint8_t ngd = tvb_get_uint8(tvb, *offset);
	bool cont = (ngd & 0x80) != 0;
	unsigned count = ngd & 0x3F;

	proto_item *gi = proto_tree_add_item(tree, R->hf[HF_NGD], tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_item_append_text(gi, " (数目=%u%s)", count, cont ? " 后续" : "");
	proto_tree_add_item(tree, R->hf[HF_NGD_COUNT], tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, R->hf[HF_NGD_CONT], tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	*offset += 1;

	if (is_command && *offset < end) {
		proto_tree_add_item(tree, R->hf[HF_NOG], tvb, *offset, 1, ENC_LITTLE_ENDIAN);
		*offset += 1;
	}

	for (unsigned i = 0; i < count && *offset < end; i++) {
		int entry_start = *offset;
		proto_item *ei = proto_tree_add_none_format(tree, R->hf[HF_ENTRY_ITEM], tvb, entry_start, 0,
							    "通用分类条目 %u", i + 1);
		proto_tree *et = proto_item_add_subtree(ei, R->ett_entry);

		uint8_t datatype = 0, datasize = 0, datanum = 0;

		if (*offset + 2 <= end) {
			proto_tree_add_item(et, R->hf[HF_GIN_GROUP], tvb, *offset, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(et, R->hf[HF_GIN_ENTRY], tvb, *offset + 1, 1,
					    ENC_LITTLE_ENDIAN);
			*offset += 2;
		}
		if (*offset + 1 <= end) {
			proto_tree_add_item(et, R->hf[HF_KOD], tvb, *offset, 1, ENC_LITTLE_ENDIAN);
			*offset += 1;
		}
		if (*offset + 2 <= end) {
			datatype = tvb_get_uint8(tvb, *offset);
			datasize = tvb_get_uint8(tvb, *offset + 1);
			proto_item *ti = proto_tree_add_item(et, R->hf[HF_GDD_TYPE], tvb, *offset, 1,
							     ENC_LITTLE_ENDIAN);
			proto_item_append_text(ti, " %s",
					       val_to_str_const(datatype, gdd_type_vals, "未知"));
			proto_tree_add_item(et, R->hf[HF_GDD_SIZE], tvb, *offset + 1, 1,
					    ENC_LITTLE_ENDIAN);
			*offset += 2;
		}
		if (*offset + 1 <= end) {
			datanum = tvb_get_uint8(tvb, *offset) & 0x7F;
			proto_tree_add_item(et, R->hf[HF_GDD_NUM], tvb, *offset, 1, ENC_LITTLE_ENDIAN);
			*offset += 1;
		}

		if (datatype != 23 && datasize > 0 && datanum > 0) {
			int dlen = (int)datasize * (int)datanum;
			if (*offset + dlen <= end) {
				proto_tree_add_item(et, R->hf[HF_GID], tvb, *offset, dlen, ENC_NA);
				*offset += dlen;
			} else {
				proto_tree_add_expert_format(et, pinfo, &ei_bad_length, tvb, *offset,
							    end - *offset,
							    "通用分类数据长度超出报文");
				*offset = end;
			}
		}
		proto_item_set_len(ei, *offset - entry_start);
	}
}

static void
dissect_asdu(tvbuff_t *tvb, int start, int end, packet_info *pinfo, proto_tree *tree,
	     const iec103_regs_t *R, const iec103_vendor_profile_t *profile)
{
	int offset = start;
	uint8_t typ, cot, fun, inf;

	if (end - offset < IEC103_ASDU_HDR_LEN) {
		proto_tree_add_item(tree, R->hf[HF_RAW], tvb, offset, end - offset, ENC_NA);
		return;
	}

	typ = tvb_get_uint8(tvb, offset);
	cot = tvb_get_uint8(tvb, offset + 2);
	fun = tvb_get_uint8(tvb, offset + 4);
	inf = tvb_get_uint8(tvb, offset + 5);

	proto_item *ai = proto_tree_add_none_format(tree, R->hf[HF_ASDU_ITEM], tvb, start, end - start,
						    "ASDU%u %s", typ,
						    val_to_str_const(typ, asdu_type_vals, "未知类型"));
	proto_tree *at = proto_item_add_subtree(ai, R->ett_asdu);

	proto_tree_add_item(at, R->hf[HF_TYPEID], tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_tree_add_item(at, R->hf[HF_VSQ], tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(at, R->hf[HF_VSQ_SQ], tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(at, R->hf[HF_VSQ_NUM], tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	proto_item *cot_item = proto_tree_add_item(at, R->hf[HF_COT], tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_item_append_text(cot_item, " %s", val_to_str_const(cot, cot_vals, "未知"));
	offset += 1;
	proto_tree_add_item(at, R->hf[HF_COMADDR], tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	const char *point_name = iec103_points_lookup(profile->points_vendor, fun, inf);
	proto_item *fun_item = proto_tree_add_item(at, R->hf[HF_FUN], tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_item *inf_item = proto_tree_add_item(at, R->hf[HF_INF], tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
	offset += 2;

	if (point_name) {
		proto_item_append_text(fun_item, " [%s]", point_name);
		proto_item_append_text(inf_item, " [%s]", point_name);
		proto_item_append_text(ai, " - %s", point_name);
	}

	switch (typ) {
	case 1:
		if (offset < end) {
			add_dpi(tvb, offset, at, R);
			offset++;
		}
		if (end - offset >= 4)
			add_cp32(tvb, &offset, at, R);
		break;

	case 2:
		if (offset < end) {
			add_dpi(tvb, offset, at, R);
			offset++;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(at, R->hf[HF_RET], tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(at, R->hf[HF_FAN], tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (end - offset >= 7)
			add_cp56(tvb, &offset, at, R);
		else if (end - offset >= 4)
			add_cp32(tvb, &offset, at, R);
		break;

	case 4:
		if (end - offset >= 2) {
			proto_tree_add_item(at, R->hf[HF_FAN], tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(at, R->hf[HF_RET], tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		break;

	case 3:  /* 被测值 */
	case 9:  /* 被测值 (II) */
	case 11: /* 通用分类标识 */
		proto_tree_add_item(at, R->hf[HF_RAW], tvb, offset, end - offset, ENC_NA);
		offset = end;
		break;

	case 5:  /* 标识: COL + 装置描述 */
		if (offset < end) {
			proto_tree_add_item(at, R->hf[HF_RAW], tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (offset < end) {
			proto_tree_add_item(at, R->hf[HF_RAW], tvb, offset, end - offset,
					    ENC_ASCII | ENC_NA);
			offset = end;
		}
		break;

	case 6:
		if (end - offset >= 7)
			add_cp56(tvb, &offset, at, R);
		break;

	case 7:
	case 8:
		if (offset < end) {
			proto_tree_add_item(at, R->hf[HF_SCN], tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		break;

	case 10:
		dissect_generic(tvb, &offset, end, at, R, pinfo, false);
		break;

	case 20:
		if (offset < end) {
			proto_tree_add_item(at, R->hf[HF_DCO], tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (offset < end) {
			proto_tree_add_item(at, R->hf[HF_RII], tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		break;

	case 21:
		dissect_generic(tvb, &offset, end, at, R, pinfo, true);
		break;

	case 23:
		if (end - offset >= 2) {
			proto_tree_add_item(at, R->hf[HF_NOF], tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		while (end - offset >= 10) {
			proto_item *ei = proto_tree_add_none_format(at, R->hf[HF_ENTRY_ITEM], tvb, offset, 10,
								    "扰动条目");
			proto_tree *et = proto_item_add_subtree(ei, R->ett_entry);
			int eo = offset;
			proto_tree_add_item(et, R->hf[HF_FAN], tvb, eo, 2, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(et, R->hf[HF_SOF], tvb, eo + 2, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(et, R->hf[HF_SOF_TP], tvb, eo + 2, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(et, R->hf[HF_SOF_TM], tvb, eo + 2, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(et, R->hf[HF_SOF_TEST], tvb, eo + 2, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(et, R->hf[HF_SOF_OTEV], tvb, eo + 2, 1, ENC_LITTLE_ENDIAN);
			eo += 3;
			add_cp56(tvb, &eo, et, R);
			offset += 10;
		}
		break;

	case 24:
	case 25:
	case 31:
		if (offset < end) {
			proto_item *ti = proto_tree_add_item(at, R->hf[HF_TOO], tvb, offset, 1,
							     ENC_LITTLE_ENDIAN);
			proto_item_append_text(ti, " %s",
					       val_to_str_const(tvb_get_uint8(tvb, offset),
								too_vals, "备用"));
			offset++;
		}
		break;

	case 26:
		if (offset < end) {
			proto_tree_add_item(at, R->hf[HF_TOV], tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(at, R->hf[HF_FAN], tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(at, R->hf[HF_NOF], tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (offset < end) {
			proto_tree_add_item(at, R->hf[HF_ACC], tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(at, R->hf[HF_NFE], tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		break;

	case 27:
		if (offset < end) {
			proto_tree_add_item(at, R->hf[HF_TOV], tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(at, R->hf[HF_FAN], tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (offset < end) {
			proto_tree_add_item(at, R->hf[HF_ACC], tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (end - offset >= 4) {
			proto_tree_add_item(at, R->hf[HF_RPV], tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
		if (end - offset >= 4) {
			proto_tree_add_item(at, R->hf[HF_RSV], tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
		if (end - offset >= 4) {
			proto_tree_add_item(at, R->hf[HF_RFA], tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}
		break;

	case 28:
		if (offset < end) {
			proto_tree_add_item(at, R->hf[HF_TOV], tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(at, R->hf[HF_FAN], tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (offset < end) {
			proto_tree_add_item(at, R->hf[HF_NOT], tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		break;

	case 29:
		if (offset < end) {
			proto_tree_add_item(at, R->hf[HF_SPI], tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		break;

	case 30:
		if (offset < end) {
			proto_tree_add_item(at, R->hf[HF_NDV], tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
		}
		while (end - offset >= 2) {
			proto_tree_add_item(at, R->hf[HF_SDV], tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		break;

	default:
		proto_tree_add_expert_format(at, pinfo, &ei_unknown_asdu, tvb, offset, end - offset,
					    "%s：ASDU 类型 %u 未专门解码",
					    profile->unknown_asdu_prefix
						    ? profile->unknown_asdu_prefix
						    : "未知 ASDU",
					    typ);
		break;
	}

	if (offset < end)
		proto_tree_add_item(at, R->hf[HF_RAW], tvb, offset, end - offset, ENC_NA);

	col_append_fstr(pinfo->cinfo, COL_INFO, "ASDU%u COT=%u", typ, cot);
	if (point_name)
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s", point_name);
}

static void
dissect_ctrl(tvbuff_t *tvb, int offset, proto_tree *tree, const iec103_regs_t *R)
{
	uint8_t ctrl = tvb_get_uint8(tvb, offset);
	bool prm = (ctrl & 0x40) != 0;

	proto_item *ci = proto_tree_add_item(tree, R->hf[HF_CTRL], tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree *ct = proto_item_add_subtree(ci, R->ett_ctrl);

	proto_tree_add_item(ct, R->hf[HF_CTRL_PRM], tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_item *fi;
	if (prm) {
		proto_tree_add_item(ct, R->hf[HF_CTRL_FCB], tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ct, R->hf[HF_CTRL_FCV], tvb, offset, 1, ENC_LITTLE_ENDIAN);
		fi = proto_tree_add_item(ct, R->hf[HF_CTRL_FUNC], tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_item_append_text(fi, " (%s)",
				       val_to_str_const(ctrl & 0x0F, func_pri_vals, "备用"));
	} else {
		proto_tree_add_item(ct, R->hf[HF_CTRL_ACD], tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ct, R->hf[HF_CTRL_DFC], tvb, offset, 1, ENC_LITTLE_ENDIAN);
		fi = proto_tree_add_item(ct, R->hf[HF_CTRL_FUNC], tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_item_append_text(fi, " (%s)",
				       val_to_str_const(ctrl & 0x0F, func_sec_vals, "备用"));
	}
	proto_item_append_text(ci, " %s %s", prm ? "主站->从站" : "从站->主站",
			       val_to_str_const(ctrl & 0x0F,
						prm ? func_pri_vals : func_sec_vals, "备用"));
}

/* ------------------------------------------------------------------ */
/* Transports                                                          */
/* ------------------------------------------------------------------ */

int
iec103_vendor_dissect_ft12(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
			   const iec103_vendor_profile_t *profile)
{
	const iec103_regs_t *R = regs_for_proto(profile->proto);
	int total = (int)tvb_reported_length(tvb);
	uint8_t start;

	if (!R || total < 1)
		return 0;

	start = tvb_get_uint8(tvb, 0);
	if (start != IEC103_FT12_VAR && start != IEC103_FT12_FIXED && start != IEC103_FT12_SINGLE)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, profile->col_protocol);
	col_clear(pinfo->cinfo, COL_INFO);

	proto_item *ti = proto_tree_add_item(tree, profile->proto, tvb, 0, total, ENC_NA);
	proto_tree *root = proto_item_add_subtree(ti, R->ett_root);

	if (start == IEC103_FT12_SINGLE) {
		col_set_str(pinfo->cinfo, COL_INFO,
			    profile->single_char_info ? profile->single_char_info : "单字符 E5");
		return 1;
	}

	if (start == IEC103_FT12_FIXED) {
		uint8_t ctrl, addr, cs;

		if (total < 5) {
			proto_tree_add_expert_format(root, pinfo, &ei_bad_length, tvb, 0, total,
						    "固定帧长度不足 5 字节");
			return total;
		}
		ctrl = tvb_get_uint8(tvb, 1);
		addr = tvb_get_uint8(tvb, 2);
		cs = tvb_get_uint8(tvb, 3);

		dissect_ctrl(tvb, 1, root, R);
		proto_tree_add_item(root, R->hf[HF_LINKADDR], tvb, 2, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(root, R->hf[HF_CHECKSUM], tvb, 3, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(root, R->hf[HF_STOPCHAR], tvb, 4, 1, ENC_LITTLE_ENDIAN);

		if ((uint8_t)(ctrl + addr) != cs) {
			proto_tree_add_expert_format(root, pinfo, &ei_bad_stopchar, tvb, 3, 1,
						    "校验和错误：应为 0x%02X",
						    (uint8_t)(ctrl + addr));
		}
		if (tvb_get_uint8(tvb, 4) != IEC103_FT12_STOP) {
			proto_tree_add_expert_format(root, pinfo, &ei_bad_stopchar, tvb, 4, 1,
						    "结束字符应为 0x16");
		}

		col_add_fstr(pinfo->cinfo, COL_INFO, "固定帧 Addr=%u %s", addr,
			     val_to_str_const(ctrl & 0x0F,
					      (ctrl & 0x40) ? func_pri_vals : func_sec_vals,
					      "备用"));
		return 5;
	}

	if (total < 8) {
		proto_tree_add_expert_format(root, pinfo, &ei_bad_length, tvb, 0, total,
					    "可变帧长度不足 8 字节");
		return total;
	}

	uint8_t len1 = tvb_get_uint8(tvb, 1);
	uint8_t len2 = tvb_get_uint8(tvb, 2);
	int asdu_start = 6;
	int asdu_end = 4 + len1;

	if (len1 != len2) {
		proto_tree_add_expert_format(root, pinfo, &ei_bad_length, tvb, 1, 2,
					    "两个长度字节不一致：0x%02X / 0x%02X", len1, len2);
		asdu_end = 4 + len2;
	}
	if (tvb_get_uint8(tvb, 3) != IEC103_FT12_VAR) {
		proto_tree_add_expert_format(root, pinfo, &ei_bad_startchar, tvb, 3, 1,
					    "第二个启动字符应为 0x68");
	}
	if (asdu_end > total - 2)
		asdu_end = total - 2;
	if (asdu_end < asdu_start)
		asdu_end = asdu_start;

	dissect_ctrl(tvb, 4, root, R);
	proto_tree_add_item(root, R->hf[HF_LINKADDR], tvb, 5, 1, ENC_LITTLE_ENDIAN);

	if (asdu_end > asdu_start) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "可变帧 Addr=%u ",
			     tvb_get_uint8(tvb, 5));
		dissect_asdu(tvb, asdu_start, asdu_end, pinfo, root, R, profile);
	}

	proto_tree_add_item(root, R->hf[HF_CHECKSUM], tvb, total - 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(root, R->hf[HF_STOPCHAR], tvb, total - 1, 1, ENC_LITTLE_ENDIAN);
	if (tvb_get_uint8(tvb, total - 1) != IEC103_FT12_STOP) {
		proto_tree_add_expert_format(root, pinfo, &ei_bad_stopchar, tvb, total - 1, 1,
					    "结束字符应为 0x16");
	}

	return total;
}

int
iec103_vendor_dissect_asdu_stream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
				  const iec103_vendor_profile_t *profile)
{
	const iec103_regs_t *R = regs_for_proto(profile->proto);
	int total = (int)tvb_reported_length(tvb);
	int offset = 0;

	if (!R || total < IEC103_ASDU_HDR_LEN)
		return 0;
	if (!iec103_vendor_looks_like_asdu(tvb, 0, total))
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, profile->col_protocol);
	col_clear(pinfo->cinfo, COL_INFO);

	proto_item *ti = proto_tree_add_item(tree, profile->proto, tvb, 0, total, ENC_NA);
	proto_tree *root = proto_item_add_subtree(ti, R->ett_root);

	while (offset + IEC103_ASDU_HDR_LEN <= total) {
		int len = asdu_pdu_len(tvb, offset, total - offset);
		if (len <= 0)
			break;
		dissect_asdu(tvb, offset, offset + len, pinfo, root, R, profile);
		offset += len;
	}

	return total;
}

int
iec103_vendor_dissect_asdu_datagram(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
				    const iec103_vendor_profile_t *profile)
{
	const iec103_regs_t *R = regs_for_proto(profile->proto);
	int total = (int)tvb_reported_length(tvb);

	if (!R || total < IEC103_ASDU_HDR_LEN)
		return 0;
	if (!iec103_vendor_looks_like_asdu(tvb, 0, total))
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, profile->col_protocol);
	col_clear(pinfo->cinfo, COL_INFO);

	proto_item *ti = proto_tree_add_item(tree, profile->proto, tvb, 0, total, ENC_NA);
	proto_tree *root = proto_item_add_subtree(ti, R->ett_root);

	dissect_asdu(tvb, 0, total, pinfo, root, R, profile);
	return total;
}

void
iec103_vendor_register_prefs(module_t *module, const char *title)
{
	iec103_points_register_prefs(module, title);
}

unsigned
iec103_vendor_point_rows(iec103_points_vendor_t vendor)
{
	return iec103_points_rows(vendor);
}

/* ------------------------------------------------------------------ */
/* Registration                                                        */
/* ------------------------------------------------------------------ */

static void
register_experts_once(int proto)
{
	static bool done;

	if (done)
		return;
	done = true;

	static ei_register_info ei[] = {
		{ &ei_bad_length, { "iec103_serial.length.bad", PI_MALFORMED, PI_ERROR,
				    "长度字段异常", EXPFILL }},
		{ &ei_bad_startchar, { "iec103_serial.start.bad", PI_MALFORMED, PI_ERROR,
				       "启动字符异常", EXPFILL }},
		{ &ei_bad_stopchar, { "iec103_serial.stop.bad", PI_PROTOCOL, PI_WARN,
				      "结束字符应为 0x16", EXPFILL }},
		{ &ei_unknown_asdu, { "iec103_serial.asdu.unknown", PI_UNDECODED, PI_NOTE,
				      "未专门解码的 ASDU 类型", EXPFILL }},
	};

	expert_module_t *expert = expert_register_protocol(proto);
	expert_register_field_array(expert, ei, array_length(ei));
}

typedef struct {
	int id;
	const char *suffix;
	const char *name;
	enum ftenum type;
	int display;
	const void *vals;
	uint64_t mask;
} iec103_hf_spec_t;

static const iec103_hf_spec_t g_hf_specs[] = {
	{ HF_CTRL, "ctrl", "控制域", FT_UINT8, BASE_HEX, NULL, 0 },
	{ HF_CTRL_PRM, "ctrl.prm", "PRM 启动报文位", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40 },
	{ HF_CTRL_FCB, "ctrl.fcb", "FCB 帧计数位", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20 },
	{ HF_CTRL_FCV, "ctrl.fcv", "FCV 帧计数有效位", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10 },
	{ HF_CTRL_ACD, "ctrl.acd", "ACD 要求访问位", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20 },
	{ HF_CTRL_DFC, "ctrl.dfc", "DFC 数据流控制位", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10 },
	{ HF_CTRL_FUNC, "ctrl.func", "功能码", FT_UINT8, BASE_DEC, NULL, 0x0F },
	{ HF_LINKADDR, "linkaddr", "链路地址", FT_UINT8, BASE_DEC, NULL, 0 },
	{ HF_CHECKSUM, "checksum", "帧校验和", FT_UINT8, BASE_HEX, NULL, 0 },
	{ HF_STOPCHAR, "stopchar", "结束字符", FT_UINT8, BASE_HEX, NULL, 0 },
	{ HF_TYPEID, "typeid", "类型标识 TYP", FT_UINT8, BASE_DEC, NULL, 0 },
	{ HF_VSQ, "vsq", "可变结构限定词 VSQ", FT_UINT8, BASE_HEX, NULL, 0 },
	{ HF_VSQ_SQ, "vsq.sq", "SQ", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80 },
	{ HF_VSQ_NUM, "vsq.num", "NUM", FT_UINT8, BASE_DEC, NULL, 0x7F },
	{ HF_COT, "cot", "传送原因 COT", FT_UINT8, BASE_DEC, NULL, 0 },
	{ HF_COMADDR, "comaddr", "公共地址", FT_UINT8, BASE_DEC, NULL, 0 },
	{ HF_FUN, "fun", "功能类型 FUN", FT_UINT8, BASE_DEC, NULL, 0 },
	{ HF_INF, "inf", "信息序号 INF", FT_UINT8, BASE_DEC, NULL, 0 },
	{ HF_DPI, "dpi", "双点信息 DPI", FT_UINT8, BASE_DEC, VALS(dpi_vals), 0x03 },
	{ HF_DPI_IV, "dpi.iv", "IV 无效", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80 },
	{ HF_DPI_NT, "dpi.nt", "NT 非当前值", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40 },
	{ HF_DPI_SB, "dpi.sb", "SB 取代", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20 },
	{ HF_DPI_BL, "dpi.bl", "BL 被闭锁", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10 },
	{ HF_SPI, "spi", "单点信息 SPI", FT_UINT8, BASE_DEC, NULL, 0x01 },
	{ HF_SCN, "scn", "扫描序号 SCN", FT_UINT8, BASE_DEC, NULL, 0 },
	{ HF_RII, "rii", "返回信息标识符 RII", FT_UINT8, BASE_DEC, NULL, 0 },
	{ HF_DCO, "dco", "命令 DCO", FT_UINT8, BASE_HEX, NULL, 0 },
	{ HF_NGD, "generic.ngd", "通用分类数目 NGD", FT_UINT8, BASE_HEX, NULL, 0 },
	{ HF_NGD_COUNT, "generic.count", "COUNT 计数器位", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40 },
	{ HF_NGD_CONT, "generic.cont", "CONT 后续状态位", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80 },
	{ HF_NOG, "generic.nog", "通用分类标识数目 NOG", FT_UINT8, BASE_DEC, NULL, 0 },
	{ HF_GIN_GROUP, "gin.group", "GIN 组号", FT_UINT8, BASE_DEC, NULL, 0 },
	{ HF_GIN_ENTRY, "gin.entry", "GIN 条目号", FT_UINT8, BASE_DEC, NULL, 0 },
	{ HF_KOD, "generic.kod", "描述类别 KOD", FT_UINT8, BASE_HEX, NULL, 0 },
	{ HF_GDD_TYPE, "generic.datatype", "数据类型", FT_UINT8, BASE_DEC, VALS(gdd_type_vals), 0 },
	{ HF_GDD_SIZE, "generic.datasize", "数据宽度", FT_UINT8, BASE_DEC, NULL, 0 },
	{ HF_GDD_NUM, "generic.datanum", "数据数目", FT_UINT8, BASE_DEC, NULL, 0 },
	{ HF_GID, "generic.data", "通用分类标识数据 GID", FT_BYTES, BASE_NONE, NULL, 0 },
	{ HF_FAN, "fan", "故障序号 FAN", FT_UINT16, BASE_DEC, NULL, 0 },
	{ HF_NOF, "nof", "电网故障序号 NOF", FT_UINT16, BASE_DEC, NULL, 0 },
	{ HF_NOT, "not", "带标志状态变位数目 NOT", FT_UINT8, BASE_DEC, NULL, 0 },
	{ HF_NDV, "ndv", "扰动值数目 NDV", FT_UINT8, BASE_DEC, NULL, 0 },
	{ HF_NFE, "nfe", "信息元素序号 NFE", FT_UINT16, BASE_DEC, NULL, 0 },
	{ HF_TOO, "too", "命令类型 TOO", FT_UINT8, BASE_DEC, VALS(too_vals), 0 },
	{ HF_TOV, "tov", "扰动值类型 TOV", FT_UINT8, BASE_DEC, VALS(tov_vals), 0 },
	{ HF_ACC, "acc", "实际通道号 ACC", FT_UINT8, BASE_DEC, NULL, 0 },
	{ HF_RET, "ret", "相对时间 RET", FT_UINT16, BASE_DEC, NULL, 0 },
	{ HF_RPV, "rpv", "额定一次值 RPV", FT_FLOAT, BASE_NONE, NULL, 0 },
	{ HF_RSV, "rsv", "额定二次值 RSV", FT_FLOAT, BASE_NONE, NULL, 0 },
	{ HF_RFA, "rfa", "参比因子 RFA", FT_FLOAT, BASE_NONE, NULL, 0 },
	{ HF_SOF, "sof", "故障状态 SOF", FT_UINT8, BASE_HEX, NULL, 0 },
	{ HF_SOF_TP, "sof.tp", "TP 跳闸", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01 },
	{ HF_SOF_TM, "sof.tm", "TM 扰动数据传输中", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02 },
	{ HF_SOF_TEST, "sof.test", "TEST 测试模式", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04 },
	{ HF_SOF_OTEV, "sof.otev", "OTEV 其他事件触发", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08 },
	{ HF_CP32, "cp32time", "CP32Time2a", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0 },
	{ HF_CP32_MS, "cp32time.ms", "毫秒", FT_UINT16, BASE_DEC, NULL, 0 },
	{ HF_CP32_MIN, "cp32time.min", "分", FT_UINT8, BASE_DEC, NULL, 0x3F },
	{ HF_CP32_IV, "cp32time.iv", "IV", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80 },
	{ HF_CP32_HOUR, "cp32time.hour", "时", FT_UINT8, BASE_DEC, NULL, 0x1F },
	{ HF_CP32_SU, "cp32time.su", "SU 夏时制", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80 },
	{ HF_CP56, "cp56time", "CP56Time2a", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0 },
	{ HF_CP56_MS, "cp56time.ms", "毫秒", FT_UINT16, BASE_DEC, NULL, 0 },
	{ HF_CP56_MIN, "cp56time.min", "分", FT_UINT8, BASE_DEC, NULL, 0x3F },
	{ HF_CP56_IV, "cp56time.iv", "IV", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80 },
	{ HF_CP56_HOUR, "cp56time.hour", "时", FT_UINT8, BASE_DEC, NULL, 0x1F },
	{ HF_CP56_SU, "cp56time.su", "SU 夏时制", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80 },
	{ HF_CP56_DAY, "cp56time.day", "日", FT_UINT8, BASE_DEC, NULL, 0x1F },
	{ HF_CP56_DOW, "cp56time.dow", "星期", FT_UINT8, BASE_DEC, NULL, 0xE0 },
	{ HF_CP56_MONTH, "cp56time.month", "月", FT_UINT8, BASE_DEC, NULL, 0x0F },
	{ HF_CP56_YEAR, "cp56time.year", "年", FT_UINT8, BASE_DEC, NULL, 0x7F },
	{ HF_SDV, "sdv", "单个扰动值 SDV", FT_INT16, BASE_DEC, NULL, 0 },
	{ HF_ASDU_ITEM, "asdu", "ASDU", FT_NONE, BASE_NONE, NULL, 0 },
	{ HF_ENTRY_ITEM, "entry", "条目", FT_NONE, BASE_NONE, NULL, 0 },
	{ HF_RAW, "data", "数据", FT_BYTES, BASE_NONE, NULL, 0 },
};

void
iec103_vendor_register(const iec103_vendor_profile_t *profile)
{
	if (g_profile_count >= MAX_PROFILES)
		return;

	unsigned slot = g_profile_count;
	iec103_regs_t *R = &g_regs[slot];
	R->proto = profile->proto;
	g_profile_count++;

	const char *short_name = proto_get_protocol_filter_name(profile->proto);

	/* Keep the array alive: proto_register_field_array() stores pointers
	 * into it and is documented for static storage only. */
	static hf_register_info *hf_tables[MAX_PROFILES];
	static bool hf_fields_registered;
	const unsigned spec_count = array_length(g_hf_specs);
	hf_register_info *hf = g_new0(hf_register_info, spec_count);
	for (unsigned i = 0; i < spec_count; i++) {
		const iec103_hf_spec_t *spec = &g_hf_specs[i];
		hf[i].p_id = &R->hf[spec->id];
		hf[i].hfinfo.name = spec->name;
		hf[i].hfinfo.abbrev = g_strdup_printf("%s.%s", short_name, spec->suffix);
		hf[i].hfinfo.type = spec->type;
		hf[i].hfinfo.display = spec->display;
		hf[i].hfinfo.strings = spec->vals;
		hf[i].hfinfo.bitmask = spec->mask;
		hf[i].hfinfo.blurb = NULL;
		hf[i].hfinfo.parent = -1;
		hf[i].hfinfo.ref_type = HF_REF_TYPE_NONE;
		hf[i].hfinfo.same_name_prev_id = -1;
		hf[i].hfinfo.same_name_next = NULL;
	}
	hf_tables[slot] = hf;
	proto_register_field_array(profile->proto, hf, (int)spec_count);
	(void)hf_fields_registered;



	static int *ett_roots[MAX_PROFILES];
	static int *ett_ctrls[MAX_PROFILES];
	static int *ett_asdus[MAX_PROFILES];
	static int *ett_entries[MAX_PROFILES];
	static int *ett_cp32s[MAX_PROFILES];
	static int *ett_cp56s[MAX_PROFILES];

	ett_roots[slot] = &R->ett_root;
	ett_ctrls[slot] = &R->ett_ctrl;
	ett_asdus[slot] = &R->ett_asdu;
	ett_entries[slot] = &R->ett_entry;
	ett_cp32s[slot] = &R->ett_cp32;
	ett_cp56s[slot] = &R->ett_cp56;

	int *ett[] = { ett_roots[slot], ett_ctrls[slot], ett_asdus[slot], ett_entries[slot],
		       ett_cp32s[slot], ett_cp56s[slot] };
	proto_register_subtree_array(ett, array_length(ett));

	register_experts_once(profile->proto);
}
