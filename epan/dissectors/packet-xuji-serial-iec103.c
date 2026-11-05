/* packet-xuji-serial-iec103.c
 *
 * 许继串口 IEC 60870-5-103（FT1.2），依据《许继103通信规约》
 * （许继电气 CBZ8000，2005-12-11 / DL/T 667-1999）。
 *
 * 链路层：FT1.2 固定/可变/单字符帧。
 * ASDU：6 字节头 (TYPE/VSQ/COT/COMADDR/FUN/INF) + 许继正文定义。
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/tfs.h>
#include <wsutil/array.h>

void proto_register_xuji_serial_iec103(void);
void proto_reg_handoff_xuji_serial_iec103(void);

#define XUJI_FT12_VAR     0x68
#define XUJI_FT12_FIXED   0x10
#define XUJI_FT12_SINGLE  0xE5
#define XUJI_FT12_STOP    0x16
#define XUJI_ASDU_HDR_LEN 6

static int proto_xuji_serial_iec103;

static int ett_xuji;
static int ett_xuji_ctrl;
static int ett_xuji_asdu;
static int ett_xuji_cp32;
static int ett_xuji_cp56;
static int ett_xuji_dpi;
static int ett_xuji_sof;
static int ett_xuji_dist;
static int ett_xuji_sdv;

static int hf_frame;
static int hf_length;
static int hf_length_dup;
static int hf_ctrl;
static int hf_ctrl_prm;
static int hf_ctrl_fcb;
static int hf_ctrl_fcv;
static int hf_ctrl_dfc;
static int hf_ctrl_acd;
static int hf_ctrl_func;
static int hf_linkaddr;
static int hf_checksum;
static int hf_stopchar;

static int hf_typeid;
static int hf_vsq;
static int hf_vsq_sq;
static int hf_vsq_num;
static int hf_cot;
static int hf_comaddr;
static int hf_fun;
static int hf_inf;
static int hf_col;
static int hf_model;
static int hf_ver_frac;
static int hf_ver_int;
static int hf_crc_rom;
static int hf_scn;
static int hf_dpi_byte;
static int hf_dpi;
static int hf_dpi_iv;
static int hf_dpi_nt;
static int hf_dpi_bl;
static int hf_dpi_sb;
static int hf_spi;
static int hf_dco;
static int hf_sin;
static int hf_fan;
static int hf_too;
static int hf_tov;
static int hf_acc;
static int hf_nof;
static int hf_noc;
static int hf_noe;
static int hf_interval;
static int hf_not;
static int hf_ndv;
static int hf_nfe;
static int hf_rpv;
static int hf_rdv;
static int hf_rfa;
static int hf_nva;
static int hf_sof;
static int hf_sof_tp;
static int hf_sof_tm;
static int hf_sof_test;
static int hf_sof_otev;
static int hf_cp32;
static int hf_cp32_ms;
static int hf_cp32_min;
static int hf_cp32_iv;
static int hf_cp32_hour;
static int hf_cp32_su;
static int hf_cp56;
static int hf_cp56_ms;
static int hf_cp56_min;
static int hf_cp56_iv;
static int hf_cp56_hour;
static int hf_cp56_su;
static int hf_cp56_day;
static int hf_cp56_dow;
static int hf_cp56_month;
static int hf_cp56_year;
static int hf_dist_entry;
static int hf_sdv;
static int hf_raw;

static expert_field ei_length_mismatch;
static expert_field ei_frame_mismatch;
static expert_field ei_stopchar_invalid;
static expert_field ei_asdu_unknown;

static dissector_handle_t xuji_serial_iec103_handle;

static const value_string frame_vals[] = {
	{ XUJI_FT12_VAR,    "可变帧长" },
	{ XUJI_FT12_FIXED,  "固定帧长" },
	{ XUJI_FT12_SINGLE, "单字符" },
	{ 0, NULL }
};

static const value_string prm_vals[] = {
	{ 0, "从站->主站" },
	{ 1, "主站->从站" },
	{ 0, NULL }
};

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

/* 《许继103通信规约》ASDU 类型 */
static const value_string asdu_type_vals[] = {
	{ 1,  "ASDU1  带时标的报文/遥信" },
	{ 2,  "ASDU2  事故信号" },
	{ 4,  "ASDU4  故障测距" },
	{ 5,  "ASDU5  标识" },
	{ 6,  "ASDU6  时间同步" },
	{ 7,  "ASDU7  总查询" },
	{ 8,  "ASDU8  总查询终止" },
	{ 9,  "ASDU9  遥测值(测量II)" },
	{ 10, "ASDU10 通用分类数据" },
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
	{ 36, "ASDU36 电度量数据" },
	{ 39, "ASDU39 调压开关升降状态变位" },
	{ 40, "ASDU40 遥信(SPI)" },
	{ 41, "ASDU41 遥信变位(SPI)/告警" },
	{ 42, "ASDU42 遥信/断路器状态(DPI)" },
	{ 43, "ASDU43 遥信/断路器变位(DPI)" },
	{ 50, "ASDU50 遥测值/谐波" },
	{ 61, "ASDU61 定值命令" },
	{ 62, "ASDU62 故障报告结束" },
	{ 64, "ASDU64 断路器控制" },
	{ 65, "ASDU65 调压开关控制" },
	{ 67, "ASDU67 同期方式选择" },
	{ 70, "ASDU70 事故/故障报告" },
	{ 73, "ASDU73 自检与运行事件(保护)" },
	{ 74, "ASDU74 自检与运行事件(测控)" },
	{ 88, "ASDU88 电度量冻结/结束" },
	{ 93, "ASDU93 调遥测否定确认/结束" },
	{ 94, "ASDU94 自检事件召唤/结束" },
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
	{ 9,  "总召唤" },
	{ 10, "总召唤终止" },
	{ 11, "当地操作" },
	{ 12, "远方操作" },
	{ 20, "命令肯定认可" },
	{ 21, "命令否定认可" },
	{ 31, "扰动数据传输" },
	{ 64, "调版本号/调遥测" },
	{ 0, NULL }
};

static const value_string fun_vals[] = {
	{ 1,   "BU1" },
	{ 2,   "BU2" },
	{ 3,   "BU3" },
	{ 4,   "BU4" },
	{ 5,   "BU5" },
	{ 6,   "BU6" },
	{ 178, "线路保护" },
	{ 194, "变压器保护" },
	{ 210, "母线保护" },
	{ 254, "全局功能类型" },
	{ 255, "全局功能类型" },
	{ 0, NULL }
};

static const value_string dpi_vals[] = {
	{ 0, "不确定" },
	{ 1, "跳/分" },
	{ 2, "合" },
	{ 3, "不确定/无效" },
	{ 0, NULL }
};

static const value_string spi_vals[] = {
	{ 0, "正常/返回" },
	{ 1, "异常/动作" },
	{ 0, NULL }
};

/* 规约表40/42/44/47/48/50/52–55 命令类型 TOO */
static const value_string too_vals[] = {
	{ 1,  "启动故障录波数据上送/选择故障" },
	{ 2,  "请求送数据" },
	{ 3,  "退出扰动数据传送" },
	{ 8,  "发送本路模拟量" },
	{ 9,  "退出本路模拟量发送" },
	{ 16, "请求发送状态量" },
	{ 17, "终止发送状态量" },
	{ 32, "扰动数据发送结束" },
	{ 35, "本路模拟量发送结束" },
	{ 37, "退出本路模拟量发送(结束)" },
	{ 38, "状态量传送结束" },
	{ 40, "退出状态量传送" },
	{ 64, "扰动数据传送成功认可" },
	{ 65, "扰动数据传送失败认可" },
	{ 66, "本路模拟量发送成功" },
	{ 67, "本路模拟量发送失败" },
	{ 68, "状态量传送成功" },
	{ 69, "状态量传送失败" },
	{ 0, NULL }
};

/* 规约表49/50 模拟量通道名称 ACC */
static const value_string acc_vals[] = {
	{ 1, "IA" },
	{ 2, "IB" },
	{ 3, "IC" },
	{ 4, "3I0" },
	{ 5, "UA" },
	{ 6, "UB" },
	{ 7, "UC" },
	{ 8, "3U0" },
	{ 0, NULL }
};

static void
dissect_cp32time(tvbuff_t *tvb, int *offset, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *sub;
	uint16_t ms;
	uint8_t min, hour;

	if (tvb_reported_length_remaining(tvb, *offset) < 4)
		return;

	ms = tvb_get_letohs(tvb, *offset);
	min = tvb_get_uint8(tvb, *offset + 2) & 0x3f;
	hour = tvb_get_uint8(tvb, *offset + 3) & 0x1f;

	ti = proto_tree_add_none_format(tree, hf_cp32, tvb, *offset, 4,
		"时标 CP32Time2a: %02u:%02u.%03u", hour, min, ms);
	sub = proto_item_add_subtree(ti, ett_xuji_cp32);
	proto_tree_add_item(sub, hf_cp32_ms, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub, hf_cp32_min, tvb, *offset + 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub, hf_cp32_iv, tvb, *offset + 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub, hf_cp32_hour, tvb, *offset + 3, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub, hf_cp32_su, tvb, *offset + 3, 1, ENC_LITTLE_ENDIAN);
	*offset += 4;
}

static void
dissect_cp56time(tvbuff_t *tvb, int *offset, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *sub;
	uint16_t ms;
	uint8_t min, hour, day, month, year;

	if (tvb_reported_length_remaining(tvb, *offset) < 7)
		return;

	ms = tvb_get_letohs(tvb, *offset);
	min = tvb_get_uint8(tvb, *offset + 2) & 0x3f;
	hour = tvb_get_uint8(tvb, *offset + 3) & 0x1f;
	day = tvb_get_uint8(tvb, *offset + 4) & 0x1f;
	month = tvb_get_uint8(tvb, *offset + 5) & 0x0f;
	year = tvb_get_uint8(tvb, *offset + 6) & 0x7f;

	ti = proto_tree_add_none_format(tree, hf_cp56, tvb, *offset, 7,
		"时标 CP56Time2a: 20%02u-%02u-%02u %02u:%02u.%03u",
		year, month, day, hour, min, ms);
	sub = proto_item_add_subtree(ti, ett_xuji_cp56);
	proto_tree_add_item(sub, hf_cp56_ms, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub, hf_cp56_min, tvb, *offset + 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub, hf_cp56_iv, tvb, *offset + 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub, hf_cp56_hour, tvb, *offset + 3, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub, hf_cp56_su, tvb, *offset + 3, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub, hf_cp56_day, tvb, *offset + 4, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub, hf_cp56_dow, tvb, *offset + 4, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub, hf_cp56_month, tvb, *offset + 5, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub, hf_cp56_year, tvb, *offset + 6, 1, ENC_LITTLE_ENDIAN);
	*offset += 7;
}

static void
dissect_dpi_byte(tvbuff_t *tvb, int *offset, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *sub;

	if (tvb_reported_length_remaining(tvb, *offset) < 1)
		return;
	ti = proto_tree_add_item(tree, hf_dpi_byte, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	sub = proto_item_add_subtree(ti, ett_xuji_dpi);
	proto_tree_add_item(sub, hf_dpi, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub, hf_dpi_sb, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub, hf_dpi_bl, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub, hf_dpi_nt, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sub, hf_dpi_iv, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	*offset += 1;
}

static void
dissect_xuji_asdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *asdu_item;
	proto_tree *asdu_tree;
	int offset = 0;
	int end = (int)tvb_reported_length(tvb);
	uint8_t typ, vsq, cot, num;
	int i;

	if (end < XUJI_ASDU_HDR_LEN) {
		if (end > 0)
			proto_tree_add_item(tree, hf_raw, tvb, 0, end, ENC_NA);
		return;
	}

	asdu_item = proto_tree_add_item(tree, proto_xuji_serial_iec103, tvb, 0, end, ENC_NA);
	proto_item_set_text(asdu_item, "许继串口103 ASDU");
	asdu_tree = proto_item_add_subtree(asdu_item, ett_xuji_asdu);

	typ = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(asdu_tree, hf_typeid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	col_append_sep_str(pinfo->cinfo, COL_INFO, ", ",
		val_to_str_const(typ, asdu_type_vals, "ASDU"));
	offset++;

	vsq = tvb_get_uint8(tvb, offset);
	num = vsq & 0x7f;
	proto_tree_add_item(asdu_tree, hf_vsq, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(asdu_tree, hf_vsq_sq, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(asdu_tree, hf_vsq_num, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;

	cot = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(asdu_tree, hf_cot, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	col_append_fstr(pinfo->cinfo, COL_INFO, " COT=%u(%s)", cot,
		val_to_str_const(cot, cot_vals, "?"));
	offset++;

	proto_tree_add_item(asdu_tree, hf_comaddr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;
	proto_tree_add_item(asdu_tree, hf_fun, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;
	proto_tree_add_item(asdu_tree, hf_inf, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset++;

	switch (typ) {
	case 1: /* DPI + CP32Time2a (+ optional SCN) */
		dissect_dpi_byte(tvb, &offset, asdu_tree);
		dissect_cp32time(tvb, &offset, asdu_tree);
		if (offset < end)
			proto_tree_add_item(asdu_tree, hf_scn, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		break;

	case 2: /* 事故信号：DPI + RET + FAN + CP32 */
		dissect_dpi_byte(tvb, &offset, asdu_tree);
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_raw, tvb, offset, 2, ENC_NA); /* RET */
			offset += 2;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		dissect_cp32time(tvb, &offset, asdu_tree);
		break;

	case 5: /* COL + 8 ASCII + BCD ver + CRC */
		if (offset < end)
			proto_tree_add_item(asdu_tree, hf_col, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		if (end - offset >= 8) {
			proto_tree_add_item(asdu_tree, hf_model, tvb, offset, 8, ENC_ASCII);
			offset += 8;
		}
		if (end - offset >= 1)
			proto_tree_add_item(asdu_tree, hf_ver_frac, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		if (end - offset >= 1)
			proto_tree_add_item(asdu_tree, hf_ver_int, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_crc_rom, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		break;

	case 6:
		dissect_cp56time(tvb, &offset, asdu_tree);
		break;

	case 7:
	case 8:
		if (offset < end)
			proto_tree_add_item(asdu_tree, hf_scn, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		break;

	case 9:
	case 50: /* N 个 2 字节被测值（规约表12） */
		for (i = 0; i < num && end - offset >= 2; i++) {
			proto_tree_add_item(asdu_tree, hf_nva, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		break;

	case 20: /* 表24：DCO + RII */
	case 64: /* 表15：断路器控制 */
	case 65: /* 调压开关 */
	case 67: /* 同期方式 */
		if (offset < end)
			proto_tree_add_item(asdu_tree, hf_dco, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		if (offset < end)
			proto_tree_add_item(asdu_tree, hf_sin, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		break;

	case 93: /* 表13/14：调遥测命令/否定/结束 — 无附加信息元素 */
		break;

	case 23: {
		proto_tree *dist = proto_tree_add_subtree(asdu_tree, tvb, offset, -1, ett_xuji_dist, NULL,
			"被记录的扰动表");
		for (i = 0; i < num && end - offset >= 10; i++) {
			proto_item *ei;
			proto_tree *et, *sof_tree;
			uint8_t sof;

			ei = proto_tree_add_none_format(dist, hf_dist_entry, tvb, offset, 10,
				"扰动条目 %d", i + 1);
			et = proto_item_add_subtree(ei, ett_xuji_dist);
			proto_tree_add_item(et, hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
			sof = tvb_get_uint8(tvb, offset);
			sof_tree = proto_item_add_subtree(
				proto_tree_add_uint(et, hf_sof, tvb, offset, 1, sof), ett_xuji_sof);
			proto_tree_add_item(sof_tree, hf_sof_tp, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(sof_tree, hf_sof_tm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(sof_tree, hf_sof_test, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(sof_tree, hf_sof_otev, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset++;
			dissect_cp56time(tvb, &offset, et);
		}
		break;
	}

	case 24:
	case 25:
	case 31:
		if (end - offset >= 1)
			proto_tree_add_item(asdu_tree, hf_too, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		if (end - offset >= 1)
			proto_tree_add_item(asdu_tree, hf_tov, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (end - offset >= 1)
			proto_tree_add_item(asdu_tree, hf_acc, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		break;

	case 26: /* 表41：未用(1)+TOV+FAN+NOF+NOC+NOE(2)+INT(2)+CP32 */
		if (offset < end)
			proto_tree_add_item(asdu_tree, hf_raw, tvb, offset++, 1, ENC_NA); /* 未用 */
		if (offset < end)
			proto_tree_add_item(asdu_tree, hf_tov, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_nof, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (offset < end)
			proto_tree_add_item(asdu_tree, hf_noc, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_noe, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		dissect_cp32time(tvb, &offset, asdu_tree);
		break;

	case 27: /* 表49：未用(1)+TOV+FAN+ACC+RPV+RDV+RFA */
		if (offset < end)
			proto_tree_add_item(asdu_tree, hf_raw, tvb, offset++, 1, ENC_NA);
		if (offset < end)
			proto_tree_add_item(asdu_tree, hf_tov, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (offset < end)
			proto_tree_add_item(asdu_tree, hf_acc, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		if (end - offset >= 4) {
			proto_tree_add_item(asdu_tree, hf_rpv, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
		}
		if (end - offset >= 4) {
			proto_tree_add_item(asdu_tree, hf_rdv, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
		}
		if (end - offset >= 4) {
			proto_tree_add_item(asdu_tree, hf_rfa, tvb, offset, 4, ENC_LITTLE_ENDIAN);
			offset += 4;
		}
		break;

	case 28: /* 表43：未用×3 + FAN */
		if (end - offset >= 3) {
			proto_tree_add_item(asdu_tree, hf_raw, tvb, offset, 3, ENC_NA);
			offset += 3;
		}
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		break;

	case 29: {
		uint8_t not = 0;
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (offset < end) {
			not = tvb_get_uint8(tvb, offset);
			proto_tree_add_item(asdu_tree, hf_not, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		}
		for (i = 0; i < not && end - offset >= 5; i++) {
			proto_tree_add_item(asdu_tree, hf_raw, tvb, offset, 2, ENC_NA); /* TAP */
			offset += 2;
			proto_tree_add_item(asdu_tree, hf_fun, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(asdu_tree, hf_inf, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
			dissect_dpi_byte(tvb, &offset, asdu_tree);
		}
		break;
	}

	case 30: {
		uint8_t ndv = 0;
		proto_tree *sdv_tree;
		if (end - offset >= 2)
			offset += 2;
		if (end - offset >= 1)
			proto_tree_add_item(asdu_tree, hf_tov, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_fan, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		if (end - offset >= 1)
			proto_tree_add_item(asdu_tree, hf_acc, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		if (end - offset >= 1) {
			ndv = tvb_get_uint8(tvb, offset);
			proto_tree_add_item(asdu_tree, hf_ndv, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		}
		if (end - offset >= 2) {
			proto_tree_add_item(asdu_tree, hf_nfe, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		sdv_tree = proto_tree_add_subtree_format(asdu_tree, tvb, offset, ndv * 2,
			ett_xuji_sdv, NULL, "扰动采样值 NDV=%u", ndv);
		for (i = 0; i < ndv && end - offset >= 2; i++) {
			proto_tree_add_item(sdv_tree, hf_sdv, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
		col_append_fstr(pinfo->cinfo, COL_INFO, " NDV=%u", ndv);
		break;
	}

	case 40: /* SPI 列表 */
		for (i = 0; i < num && offset < end; i++)
			proto_tree_add_item(asdu_tree, hf_spi, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		if (offset < end)
			proto_tree_add_item(asdu_tree, hf_scn, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		break;

	case 41:
	case 43: /* 变位：INF+DPI[+CP32] 重复 */
		for (i = 0; i < num && offset < end; i++) {
			if (!(vsq & 0x80) && offset < end)
				proto_tree_add_item(asdu_tree, hf_inf, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
			dissect_dpi_byte(tvb, &offset, asdu_tree);
			if (typ == 43)
				dissect_cp32time(tvb, &offset, asdu_tree);
		}
		break;

	case 42: /* 多 DPI */
		for (i = 0; i < num && offset < end; i++) {
			if (!(vsq & 0x80) && offset < end)
				proto_tree_add_item(asdu_tree, hf_inf, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
			dissect_dpi_byte(tvb, &offset, asdu_tree);
		}
		if (offset < end)
			proto_tree_add_item(asdu_tree, hf_scn, tvb, offset++, 1, ENC_LITTLE_ENDIAN);
		break;

	default:
		expert_add_info(pinfo, asdu_item, &ei_asdu_unknown);
		break;
	}

	if (offset < end)
		proto_tree_add_item(asdu_tree, hf_raw, tvb, offset, end - offset, ENC_NA);
}

static int
dissect_xuji_serial_iec103(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *ti, *ctrl_item, *expert_item;
	proto_tree *xuji_tree, *ctrl_tree;
	uint8_t frametype, ctrl, prm;
	uint32_t length = 0, stopchar;
	unsigned asdu_len = 0;
	int offset = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "许继串口103");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_xuji_serial_iec103, tvb, 0, -1, ENC_NA);
	proto_item_set_text(ti, "许继串口103规约");
	xuji_tree = proto_item_add_subtree(ti, ett_xuji);

	frametype = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(xuji_tree, hf_frame, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	if (frametype == XUJI_FT12_SINGLE) {
		col_set_str(pinfo->cinfo, COL_INFO, "单字符确认 (E5H)");
		return offset;
	}

	if (frametype == XUJI_FT12_VAR) {
		uint8_t len1, len2;

		if (tvb_reported_length_remaining(tvb, offset) < 3)
			return tvb_captured_length(tvb);
		len1 = tvb_get_uint8(tvb, offset);
		len2 = tvb_get_uint8(tvb, offset + 1);
		proto_tree_add_item(xuji_tree, hf_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		expert_item = proto_tree_add_item(xuji_tree, hf_length_dup, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
		length = len1;
		if (len1 != len2) {
			expert_add_info(pinfo, expert_item, &ei_length_mismatch);
			col_set_str(pinfo->cinfo, COL_INFO, "长度字节不一致");
			return tvb_captured_length(tvb);
		}
		expert_item = proto_tree_add_item(xuji_tree, hf_frame, tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
		if (tvb_get_uint8(tvb, offset + 2) != XUJI_FT12_VAR) {
			expert_add_info(pinfo, expert_item, &ei_frame_mismatch);
			col_set_str(pinfo->cinfo, COL_INFO, "可变帧启动字符不一致");
			return tvb_captured_length(tvb);
		}
		offset += 3;
		asdu_len = (length >= 2) ? (length - 2) : 0;
	}

	if (tvb_reported_length_remaining(tvb, offset) < 2)
		return tvb_captured_length(tvb);

	ctrl = tvb_get_uint8(tvb, offset);
	prm = (ctrl & 0x40) ? 1 : 0;
	ctrl_item = proto_tree_add_item(xuji_tree, hf_ctrl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	ctrl_tree = proto_item_add_subtree(ctrl_item, ett_xuji_ctrl);
	proto_tree_add_item(ctrl_tree, hf_ctrl_prm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	if (prm) {
		col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Pri->Sec");
		proto_tree_add_item(ctrl_tree, hf_ctrl_fcb, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ctrl_tree, hf_ctrl_fcv, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ctrl_tree, hf_ctrl_func, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
			val_to_str_const(ctrl & 0x0F, func_pri_vals, "功能码"));
	} else {
		col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Sec->Pri");
		proto_tree_add_item(ctrl_tree, hf_ctrl_acd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ctrl_tree, hf_ctrl_dfc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ctrl_tree, hf_ctrl_func, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
			val_to_str_const(ctrl & 0x0F, func_sec_vals, "功能码"));
	}
	offset += 1;

	proto_tree_add_item(xuji_tree, hf_linkaddr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	col_append_fstr(pinfo->cinfo, COL_INFO, " Addr=%u", tvb_get_uint8(tvb, offset));
	offset += 1;

	if (frametype == XUJI_FT12_VAR && asdu_len > 0 &&
	    (unsigned)tvb_reported_length_remaining(tvb, offset) >= asdu_len) {
		tvbuff_t *asdu_tvb = tvb_new_subset_length(tvb, offset, (int)asdu_len);
		dissect_xuji_asdu(asdu_tvb, pinfo, xuji_tree);
		offset += (int)asdu_len;
	}

	if (tvb_reported_length_remaining(tvb, offset) >= 2) {
		proto_tree_add_item(xuji_tree, hf_checksum, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		expert_item = proto_tree_add_item_ret_uint(xuji_tree, hf_stopchar, tvb, offset + 1, 1,
			ENC_LITTLE_ENDIAN, &stopchar);
		if (stopchar != XUJI_FT12_STOP)
			expert_add_info(pinfo, expert_item, &ei_stopchar_invalid);
		offset += 2;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "许继串口103");
	return tvb_captured_length(tvb);
}

void
proto_register_xuji_serial_iec103(void)
{
	static hf_register_info hf[] = {
		{ &hf_frame, { "帧格式", "xuji_serial_iec103.frame", FT_UINT8, BASE_HEX, VALS(frame_vals), 0, NULL, HFILL }},
		{ &hf_length, { "长度 L", "xuji_serial_iec103.length", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_length_dup, { "长度 L(重复)", "xuji_serial_iec103.length_dup", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ctrl, { "控制域", "xuji_serial_iec103.ctrl", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ctrl_prm, { "PRM", "xuji_serial_iec103.ctrl.prm", FT_UINT8, BASE_DEC, VALS(prm_vals), 0x40, NULL, HFILL }},
		{ &hf_ctrl_fcb, { "FCB", "xuji_serial_iec103.ctrl.fcb", FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL }},
		{ &hf_ctrl_fcv, { "FCV", "xuji_serial_iec103.ctrl.fcv", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL }},
		{ &hf_ctrl_acd, { "ACD", "xuji_serial_iec103.ctrl.acd", FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL }},
		{ &hf_ctrl_dfc, { "DFC", "xuji_serial_iec103.ctrl.dfc", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL }},
		{ &hf_ctrl_func, { "功能码", "xuji_serial_iec103.ctrl.func", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
		{ &hf_linkaddr, { "链路地址(装置地址)", "xuji_serial_iec103.linkaddr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_checksum, { "校验和", "xuji_serial_iec103.checksum", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_stopchar, { "结束字符", "xuji_serial_iec103.stop", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

		{ &hf_typeid, { "类型标识 (TYPE)", "xuji_serial_iec103.typeid", FT_UINT8, BASE_DEC, VALS(asdu_type_vals), 0, NULL, HFILL }},
		{ &hf_vsq, { "可变结构限定词 (VSQ)", "xuji_serial_iec103.vsq", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_vsq_sq, { "SQ", "xuji_serial_iec103.vsq.sq", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
		{ &hf_vsq_num, { "信息元素数目", "xuji_serial_iec103.vsq.num", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }},
		{ &hf_cot, { "传送原因 (COT)", "xuji_serial_iec103.cot", FT_UINT8, BASE_DEC, VALS(cot_vals), 0, NULL, HFILL }},
		{ &hf_comaddr, { "单元公共地址 (COMADDR)", "xuji_serial_iec103.comaddr", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_fun, { "功能类型 (FUN)", "xuji_serial_iec103.fun", FT_UINT8, BASE_DEC, VALS(fun_vals), 0, NULL, HFILL }},
		{ &hf_inf, { "信息序号 (INF)", "xuji_serial_iec103.inf", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_col, { "兼容级别 (COL)", "xuji_serial_iec103.col", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_model, { "装置型号 (ASCII)", "xuji_serial_iec103.model", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_ver_frac, { "版本号小数(BCD)", "xuji_serial_iec103.ver_frac", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_ver_int, { "版本号整数(BCD)", "xuji_serial_iec103.ver_int", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_crc_rom, { "CRC(ROM和)", "xuji_serial_iec103.crc_rom", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_scn, { "扫描/总召序号 (SCN)", "xuji_serial_iec103.scn", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_dpi_byte, { "双点信息字节", "xuji_serial_iec103.dpi_byte", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_dpi, { "DPI", "xuji_serial_iec103.dpi", FT_UINT8, BASE_DEC, VALS(dpi_vals), 0x03, NULL, HFILL }},
		{ &hf_dpi_sb, { "SB 取代", "xuji_serial_iec103.dpi.sb", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL }},
		{ &hf_dpi_bl, { "BL 闭锁", "xuji_serial_iec103.dpi.bl", FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL }},
		{ &hf_dpi_nt, { "NT 非当前", "xuji_serial_iec103.dpi.nt", FT_UINT8, BASE_DEC, NULL, 0x40, NULL, HFILL }},
		{ &hf_dpi_iv, { "IV 无效", "xuji_serial_iec103.dpi.iv", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
		{ &hf_spi, { "SPI", "xuji_serial_iec103.spi", FT_UINT8, BASE_DEC, VALS(spi_vals), 0x01, NULL, HFILL }},
		{ &hf_dco, { "双命令 (DCO)", "xuji_serial_iec103.dco", FT_UINT8, BASE_DEC, VALS(dpi_vals), 0x03, NULL, HFILL }},
		{ &hf_sin, { "附加信息 (SIN)", "xuji_serial_iec103.sin", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_fan, { "故障序号 (FAN)", "xuji_serial_iec103.fan", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_too, { "命令类型 (TOO)", "xuji_serial_iec103.too", FT_UINT8, BASE_DEC, VALS(too_vals), 0, NULL, HFILL }},
		{ &hf_tov, { "数据类型 (TOV)", "xuji_serial_iec103.tov", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_acc, { "通道序号 (ACC)", "xuji_serial_iec103.acc", FT_UINT8, BASE_DEC, VALS(acc_vals), 0, NULL, HFILL }},
		{ &hf_nof, { "电网故障序号 (NOF)", "xuji_serial_iec103.nof", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_noc, { "模拟量路数 (NOC)", "xuji_serial_iec103.noc", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_noe, { "每路点数 (NOE)", "xuji_serial_iec103.noe", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_interval, { "采样间隔 INT(µs)", "xuji_serial_iec103.interval", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_not, { "带标志状态变位数目 (NOT)", "xuji_serial_iec103.not", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_ndv, { "扰动值数目 (NDV)", "xuji_serial_iec103.ndv", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_nfe, { "第一个信息元素序号 (NFE)", "xuji_serial_iec103.nfe", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_rpv, { "一次额定值 RPV", "xuji_serial_iec103.rpv", FT_FLOAT, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_rdv, { "二次额定值 RDV", "xuji_serial_iec103.rdv", FT_FLOAT, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_rfa, { "参比因子 RFA", "xuji_serial_iec103.rfa", FT_FLOAT, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_nva, { "被测值 NVA", "xuji_serial_iec103.nva", FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_sof, { "故障状态 (SOF)", "xuji_serial_iec103.sof", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_sof_tp, { "TP 跳闸", "xuji_serial_iec103.sof.tp", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
		{ &hf_sof_tm, { "TM 正在传输", "xuji_serial_iec103.sof.tm", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
		{ &hf_sof_test, { "TEST 测试模式", "xuji_serial_iec103.sof.test", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
		{ &hf_sof_otev, { "OTEV 其他事件触发", "xuji_serial_iec103.sof.otev", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
		{ &hf_cp32, { "CP32Time2a", "xuji_serial_iec103.cp32", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_cp32_ms, { "毫秒", "xuji_serial_iec103.cp32.ms", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_cp32_min, { "分", "xuji_serial_iec103.cp32.min", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL }},
		{ &hf_cp32_iv, { "IV", "xuji_serial_iec103.cp32.iv", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
		{ &hf_cp32_hour, { "时", "xuji_serial_iec103.cp32.hour", FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL }},
		{ &hf_cp32_su, { "SU", "xuji_serial_iec103.cp32.su", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
		{ &hf_cp56, { "CP56Time2a", "xuji_serial_iec103.cp56", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_cp56_ms, { "毫秒", "xuji_serial_iec103.cp56.ms", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_cp56_min, { "分", "xuji_serial_iec103.cp56.min", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL }},
		{ &hf_cp56_iv, { "IV", "xuji_serial_iec103.cp56.iv", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
		{ &hf_cp56_hour, { "时", "xuji_serial_iec103.cp56.hour", FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL }},
		{ &hf_cp56_su, { "SU", "xuji_serial_iec103.cp56.su", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
		{ &hf_cp56_day, { "日", "xuji_serial_iec103.cp56.day", FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL }},
		{ &hf_cp56_dow, { "星期", "xuji_serial_iec103.cp56.dow", FT_UINT8, BASE_DEC, NULL, 0xe0, NULL, HFILL }},
		{ &hf_cp56_month, { "月", "xuji_serial_iec103.cp56.month", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
		{ &hf_cp56_year, { "年", "xuji_serial_iec103.cp56.year", FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL }},
		{ &hf_dist_entry, { "扰动表条目", "xuji_serial_iec103.dist.entry", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_sdv, { "扰动采样 SDV", "xuji_serial_iec103.sdv", FT_INT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_raw, { "原始数据", "xuji_serial_iec103.data", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	};

	static int *ett[] = {
		&ett_xuji, &ett_xuji_ctrl, &ett_xuji_asdu, &ett_xuji_cp32, &ett_xuji_cp56,
		&ett_xuji_dpi, &ett_xuji_sof, &ett_xuji_dist, &ett_xuji_sdv,
	};

	static ei_register_info ei[] = {
		{ &ei_length_mismatch, { "xuji_serial_iec103.length.mismatch", PI_MALFORMED, PI_ERROR, "可变帧两个长度字节必须一致", EXPFILL }},
		{ &ei_frame_mismatch, { "xuji_serial_iec103.frame.mismatch", PI_MALFORMED, PI_ERROR, "可变帧两个启动字符必须为 0x68", EXPFILL }},
		{ &ei_stopchar_invalid, { "xuji_serial_iec103.stop.invalid", PI_PROTOCOL, PI_WARN, "结束字符应为 0x16", EXPFILL }},
		{ &ei_asdu_unknown, { "xuji_serial_iec103.asdu.unknown", PI_UNDECODED, PI_NOTE, "未专门解码的许继 ASDU 类型，见原始数据", EXPFILL }},
	};

	expert_module_t *expert_xuji;

	proto_xuji_serial_iec103 = proto_register_protocol(
		"许继串口IEC60870-5-103", "许继串口103", "xuji_serial_iec103");
	proto_register_field_array(proto_xuji_serial_iec103, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_xuji = expert_register_protocol(proto_xuji_serial_iec103);
	expert_register_field_array(expert_xuji, ei, array_length(ei));
	xuji_serial_iec103_handle = register_dissector(
		"xuji_serial_iec103", dissect_xuji_serial_iec103, proto_xuji_serial_iec103);
}

void
proto_reg_handoff_xuji_serial_iec103(void)
{
}
