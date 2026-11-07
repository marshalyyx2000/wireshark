/* packet-zh-recorder.c
 *
 * 武汉中元华电 ZH-2 / ZH-2A / ZH-2B / ZH-2B+ / ZH-101 / ZH-3 / ZH-5 系列电力故障
 * 录波装置以太网通信规约（2.1 版，TCP 764AH = 30282）。
 *
 * This is a vendor-specific binary protocol, NOT IEC 60870-5-103. Two frame
 * layouts are supported and auto-detected:
 *
 *   type 1: TYP(4) LEN(4) DAT(LEN)
 *   type 2: STX(4) STX(4) TYP(4) LEN(4) DAT(LEN) CHS(4) ETX(4) ETX(4)
 *
 * All integers are little endian. See tools/iec103-docs/zh-recorder.md.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/tfs.h>
#include <epan/to_str.h>
#include <epan/conversation.h>
#include <wsutil/array.h>

#include "packet-tcp.h"
#include "packet-zh-recorder-tap.h"

void proto_register_zh_recorder(void);
void proto_reg_handoff_zh_recorder(void);

#define ZH_STX            0x76337692u
#define ZH_ETX            0x76927633u
#define ZH_HDR_TYPE1      8
#define ZH_HDR_TYPE2      16
#define ZH_TRAILER_TYPE2  12          /* CHS(4) + ETX(4) + ETX(4) */
#define ZH_MAX_LEN        16376
#define ZH_MAX_PDU        (ZH_HDR_TYPE2 + ZH_MAX_LEN + ZH_TRAILER_TYPE2)

/* Structure sizes (bytes). */
#define ZH_SZ_DATE_TIME     16
#define ZH_SZ_SYSTEM_TIME   16
#define ZH_SZ_PACKET_RETURN 264
#define ZH_SZ_FILE_INFO     292
#define ZH_SZ_FILE_GET      268
#define ZH_SZ_FILE_VER      324
#define ZH_SZ_FAULT_INFO    502
#define ZH_SZ_ZHREC_YC      82
#define ZH_SZ_ZHREC_YX      66

/* PTYPE values. */
#define ZH_PTYPE_RETURN          0x00000001u
#define ZH_PTYPE_TIME            0x00000002u
#define ZH_PTYPE_PACKETSIZE      0x00000003u
#define ZH_PTYPE_FRAMEDELAY      0x00000004u
#define ZH_PTYPE_FILE_INFO       0x00000010u
#define ZH_PTYPE_FILE_DATA       0x00000011u
#define ZH_PTYPE_FILE_GET        0x00000012u
#define ZH_PTYPE_FILE_PUT        0x00000013u
#define ZH_PTYPE_FILE_VER        0x00000015u
#define ZH_PTYPE_DIR_GET         0x00000022u
#define ZH_PTYPE_WORK_PATH       0x0000003Au
#define ZH_PTYPE_DATA_PATH       0x0000003Bu
#define ZH_PTYPE_CANCEL          0x0000006Eu
#define ZH_PTYPE_RECORD          0x00000205u
#define ZH_PTYPE_RECORDERINFO    0x01000010u
#define ZH_PTYPE_GETMODEL        0x01000025u
#define ZH_PTYPE_GETNEWSTATUS    0x00000300u
#define ZH_PTYPE_RESETNEWSTATUS  0x00000301u
#define ZH_PTYPE_YC              0x00000303u
#define ZH_PTYPE_YX              0x00000304u
#define ZH_PTYPE_YCEX            0x00000305u
#define ZH_PTYPE_CHKFRMFMT       0x76337692u

static int proto_zh_recorder;
static int zh_tap;

static int ett_zh;
static int ett_zh_frame;
static int ett_zh_return;
static int ett_zh_time;
static int ett_zh_file_info;
static int ett_zh_file_get;
static int ett_zh_fault;
static int ett_zh_yc;
static int ett_zh_yx;

static int hf_zh_frame_type;
static int hf_zh_stx;
static int hf_zh_typ;
static int hf_zh_len;
static int hf_zh_chs;
static int hf_zh_chs_ok;
static int hf_zh_etx;

/* PACKET_RETURN */
static int hf_zh_ret_code;
static int hf_zh_ret_sender;
static int hf_zh_ret_message;

/* DATE_TIME / SYSTEM_TIME */
static int hf_zh_dt_year;
static int hf_zh_dt_month;
static int hf_zh_dt_day;
static int hf_zh_dt_hour;
static int hf_zh_dt_minute;
static int hf_zh_dt_second;
static int hf_zh_dt_ms;
static int hf_zh_dt_us;
static int hf_zh_st_dow;
static int hf_zh_st_dom;

/* FILE_INFO */
static int hf_zh_fi_from;
static int hf_zh_fi_size;
static int hf_zh_fi_attr;
static int hf_zh_fi_offset;
static int hf_zh_fi_length;
static int hf_zh_fi_name;

/* FILE_GET */
static int hf_zh_fg_from;
static int hf_zh_fg_flag;
static int hf_zh_fg_offset;
static int hf_zh_fg_fid;
static int hf_zh_fg_name;

/* FILE_VER */
static int hf_zh_fv_ver;

/* FAULT_INFO */
static int hf_zh_fault_type;
static int hf_zh_fault_datnum;
static int hf_zh_fault_jmp;
static int hf_zh_fault_id;
static int hf_zh_fault_size;
static int hf_zh_fault_devid;
static int hf_zh_fault_code;
static int hf_zh_fault_staid;
static int hf_zh_fault_type_id;
static int hf_zh_fault_dist;
static int hf_zh_fault_linename;
static int hf_zh_fault_filename;
static int hf_zh_fault_sti;

/* ZHREC_YC / ZHREC_YX */
static int hf_zh_yc_gno;
static int hf_zh_yc_ino;
static int hf_zh_yc_fv;
static int hf_zh_yc_fa2;
static int hf_zh_yc_fa1;
static int hf_zh_yc_fb1;
static int hf_zh_yc_name;
static int hf_zh_yc_unit1;
static int hf_zh_yc_unit2;
static int hf_zh_yx_gno;
static int hf_zh_yx_ino;
static int hf_zh_yx_fv;
static int hf_zh_yx_name;

/* Generic payloads */
static int hf_zh_word_value;
static int hf_zh_dword_value;
static int hf_zh_path;
static int hf_zh_data;
static int hf_zh_struct_item;

static expert_field ei_zh_len_invalid;
static expert_field ei_zh_chs_bad;
static expert_field ei_zh_truncated;

static dissector_handle_t zh_recorder_handle;

/* ------------------------------------------------------------------ */
/* Value tables                                                        */
/* ------------------------------------------------------------------ */

static const value_string zh_frame_type_vals[] = {
	{ 1, "类型一 (TYP/LEN/DAT)" },
	{ 2, "类型二 (STX/.../CHS/ETX)" },
	{ 0, NULL }
};

static const value_string zh_typ_vals[] = {
	{ ZH_PTYPE_RETURN,         "PTYPE_RETURN 响应" },
	{ ZH_PTYPE_TIME,           "PTYPE_TIME 设置时钟" },
	{ ZH_PTYPE_PACKETSIZE,     "PTYPE_PACKETSIZE 分包大小" },
	{ ZH_PTYPE_FRAMEDELAY,     "PTYPE_FRAMEDELAY 帧间隔" },
	{ ZH_PTYPE_FILE_INFO,      "PTYPE_FILE_INFO 文件信息" },
	{ ZH_PTYPE_FILE_DATA,      "PTYPE_FILE_DATA 文件数据" },
	{ ZH_PTYPE_FILE_GET,       "PTYPE_FILE_GET 召唤文件" },
	{ ZH_PTYPE_FILE_PUT,       "PTYPE_FILE_PUT 要求接收文件" },
	{ ZH_PTYPE_FILE_VER,       "PTYPE_FILE_VER 文件版本" },
	{ ZH_PTYPE_DIR_GET,        "PTYPE_DIR_GET 召唤目录" },
	{ ZH_PTYPE_WORK_PATH,      "PTYPE_WORK_PATH 工作目录" },
	{ ZH_PTYPE_DATA_PATH,      "PTYPE_DATA_PATH 数据目录" },
	{ ZH_PTYPE_CANCEL,         "PTYPE_CANCEL 中止传输" },
	{ ZH_PTYPE_RECORD,         "PTYPE_RECORD 遥控录波" },
	{ ZH_PTYPE_RECORDERINFO,   "PTYPE_RECORDERINFO 录波器信息" },
	{ ZH_PTYPE_GETMODEL,       "PTYPE_GETMODEL 录波器型号" },
	{ ZH_PTYPE_GETNEWSTATUS,   "PTYPE_GETNEWSTATUS 新状态" },
	{ ZH_PTYPE_RESETNEWSTATUS, "PTYPE_RESETNEWSTATUS 复归新状态" },
	{ ZH_PTYPE_YC,             "PTYPE_YC 基本遥测量" },
	{ ZH_PTYPE_YX,             "PTYPE_YX 遥信量" },
	{ ZH_PTYPE_YCEX,           "PTYPE_YCEX 扩展遥测量" },
	{ ZH_PTYPE_CHKFRMFMT,      "PTYPE_CHKFRMFMT 检查帧格式" },
	{ 0, NULL }
};

static const value_string zh_sender_vals[] = {
	{ 0, "未知" },
	{ 1, "录波装置" },
	{ 2, "分站节点" },
	{ 3, "主站节点" },
	{ 0, NULL }
};

static const value_string zh_ret_code_vals[] = {
	{ 71000, "远方已经关闭" },
	{ 71001, "连接太多" },
	{ 71002, "远方没有应答" },
	{ 71003, "数据包类型错误" },
	{ 71004, "远方取消了当前操作" },
	{ 71005, "本地取消了当前操作" },
	{ 71006, "没有找到指定的设备" },
	{ 71200, "创建文件失败" },
	{ 71201, "打开文件失败" },
	{ 71202, "内存分配失败" },
	{ 71250, "连接数据库失败" },
	{ 71300, "动态库中无函数" },
	{ 71301, "无效的命令" },
	{ 71302, "没有所请求的数据" },
	{ 71303, "数据库异常" },
	{ 71304, "系统繁忙" },
	{ 71305, "参数错误或无效" },
	{ 0,     "成功" },
	{ 0, NULL }
};

static const value_string zh_file_attr_vals[] = {
	{ 0x001, "只读" },
	{ 0x002, "隐藏" },
	{ 0x004, "系统" },
	{ 0x010, "文件夹" },
	{ 0x020, "存档" },
	{ 0x080, "一般" },
	{ 0x100, "临时" },
	{ 0, NULL }
};

static const value_string zh_file_flag_vals[] = {
	{ 0x01, "传送前压缩文件" },
	{ 0x02, "传送后删除文件" },
	{ 0, NULL }
};

static const value_string zh_faulttype_vals[] = {
	{ 0x0000, "无故障" },
	{ 0x0001, "A 相接地故障" },
	{ 0x0002, "B 相接地故障" },
	{ 0x0004, "C 相接地故障" },
	{ 0x0008, "AB 短路故障" },
	{ 0x0010, "BC 短路故障" },
	{ 0x0020, "CA 短路故障" },
	{ 0x0040, "AB 短路接地故障" },
	{ 0x0080, "BC 短路接地故障" },
	{ 0x0100, "CA 短路接地故障" },
	{ 0x0200, "三相短路故障" },
	{ 0x0400, "三相短路接地故障" },
	{ 0x0800, "其他类型故障" },
	{ 0x1000, "母线故障" },
	{ 0x2000, "区外故障" },
	{ 0x2001, "变压器内部故障" },
	{ 0x7FFF, "尚未分析" },
	{ 0, NULL }
};

static const value_string zh_model_vals[] = {
	{ 0x0002, "ZH-2 型电力故障录波分析装置" },
	{ 0x002A, "ZH-2A 型电力故障录波分析装置" },
	{ 0x002B, "ZH-2B 型发变组故障录波分析装置" },
	{ 0x02BA, "ZH-2B+ 型抽水蓄能发变组故障录波分析装置" },
	{ 0x0101, "ZH-101 型便携式故障录波分析装置" },
	{ 0, NULL }
};

static const value_string zh_newstatus_bit_vals[] = {
	{ 0x01, "有新录波" },
	{ 0x02, "定值改变" },
	{ 0x04, "配置改变" },
	{ 0, NULL }
};

/* Per-conversation "current file" so FILE_DATA chunks can be attributed.
 * Only the name and total size are remembered; chunk offsets are accumulated
 * by the exporter in packet order, so re-dissection cannot skew them. */
typedef struct zh_conv_info {
	char     name[ZH_RECORDER_NAME_LEN];
	uint32_t total_size;
} zh_conv_info_t;

static zh_conv_info_t *
zh_get_conv_info(packet_info *pinfo)
{
	conversation_t *conv = find_or_create_conversation(pinfo);

	zh_conv_info_t *info = (zh_conv_info_t *)conversation_get_proto_data(
		conv, proto_zh_recorder);
	if (info == NULL) {
		info = wmem_new0(wmem_file_scope(), zh_conv_info_t);
		conversation_add_proto_data(conv, proto_zh_recorder, info);
	}
	return info;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/*                                                                     */
/* Only used inside the dissector.                                     */
/* ------------------------------------------------------------------ */

/* Add a NUL-terminated ASCII string of at most @p maxlen bytes. */
static void
zh_add_string(proto_tree *tree, int hf, tvbuff_t *tvb, int offset, int maxlen, int end)
{
	int avail = end - offset;
	int len = 0;

	if (avail <= 0 || maxlen <= 0)
		return;
	if (maxlen > avail)
		maxlen = avail;

	while (len < maxlen && tvb_get_uint8(tvb, offset + len) != 0)
		len++;

	proto_tree_add_item(tree, hf, tvb, offset, len, ENC_ASCII | ENC_NA);
}

/* Copy a NUL-terminated name for the tap payload. */
static void
zh_copy_name(char *dst, size_t dst_len, tvbuff_t *tvb, int offset, int maxlen, int end)
{
	int avail = end - offset;
	int len = 0;

	if (dst_len == 0)
		return;
	dst[0] = '\0';
	if (avail <= 0 || maxlen <= 0)
		return;
	if (maxlen > avail)
		maxlen = avail;

	while (len < maxlen && tvb_get_uint8(tvb, offset + len) != 0)
		len++;
	if (len >= (int)dst_len)
		len = (int)dst_len - 1;
	if (len > 0)
		tvb_memcpy(tvb, dst, offset, (size_t)len);
	dst[len] = '\0';
}

static void
zh_dissect_date_time(tvbuff_t *tvb, proto_tree *tree, int offset, int end)
{
	if (end - offset < ZH_SZ_DATE_TIME)
		return;

	proto_tree_add_item(tree, hf_zh_dt_year, tvb, offset + 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_zh_dt_month, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_zh_dt_day, tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_zh_dt_hour, tvb, offset + 6, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_zh_dt_minute, tvb, offset + 8, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_zh_dt_second, tvb, offset + 10, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_zh_dt_ms, tvb, offset + 12, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_zh_dt_us, tvb, offset + 14, 2, ENC_LITTLE_ENDIAN);
}

static void
zh_dissect_system_time(tvbuff_t *tvb, proto_tree *tree, int offset, int end)
{
	if (end - offset < ZH_SZ_SYSTEM_TIME)
		return;

	proto_tree_add_item(tree, hf_zh_dt_year, tvb, offset + 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_zh_dt_month, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_zh_st_dow, tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_zh_st_dom, tvb, offset + 6, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_zh_dt_hour, tvb, offset + 8, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_zh_dt_minute, tvb, offset + 10, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_zh_dt_second, tvb, offset + 12, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_zh_dt_ms, tvb, offset + 14, 2, ENC_LITTLE_ENDIAN);
}

static void
zh_dissect_file_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset,
		     int end, zh_recorder_tap_data_t *tap)
{
	if (end - offset < ZH_SZ_FILE_INFO) {
		proto_tree_add_expert_format(tree, pinfo, &ei_zh_truncated, tvb, offset,
					    end - offset, "FILE_INFO 不足 292 字节");
		return;
	}

	proto_item *fi = proto_tree_add_none_format(tree, hf_zh_struct_item, tvb, offset,
						    ZH_SZ_FILE_INFO, "FILE_INFO 文件信息");
	proto_tree *ft = proto_item_add_subtree(fi, ett_zh_file_info);

	proto_tree_add_item(ft, hf_zh_fi_from, tvb, offset + 0, 4, ENC_LITTLE_ENDIAN);
	zh_dissect_date_time(tvb, ft, offset + 4, end);
	proto_tree_add_item(ft, hf_zh_fi_size, tvb, offset + 20, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ft, hf_zh_fi_attr, tvb, offset + 24, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ft, hf_zh_fi_offset, tvb, offset + 28, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ft, hf_zh_fi_length, tvb, offset + 32, 4, ENC_LITTLE_ENDIAN);
	zh_add_string(ft, hf_zh_fi_name, tvb, offset + 36, 256, end);

	if (tap != NULL) {
		zh_copy_name(tap->name, sizeof(tap->name), tvb, offset + 36, 256, end);
		tap->total_size = tvb_get_letohl(tvb, offset + 20);
		tap->offset = tvb_get_letohl(tvb, offset + 28);

		/* Remember the file for the FILE_DATA chunks that follow on this
		 * connection so the exporter can name the reassembled file. */
		zh_conv_info_t *conv = zh_get_conv_info(pinfo);
		(void)g_strlcpy(conv->name, tap->name, sizeof(conv->name));
		conv->total_size = tap->total_size;
	}
}

static void
zh_dissect_file_get(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset,
		    int end)
{
	if (end - offset < ZH_SZ_FILE_GET) {
		proto_tree_add_expert_format(tree, pinfo, &ei_zh_truncated, tvb, offset,
					    end - offset, "FILE_GET 不足 268 字节");
		return;
	}

	proto_item *fg = proto_tree_add_none_format(tree, hf_zh_struct_item, tvb, offset,
						    ZH_SZ_FILE_GET, "FILE_GET 请求结构");
	proto_tree *ft = proto_item_add_subtree(fg, ett_zh_file_get);

	proto_tree_add_item(ft, hf_zh_fg_from, tvb, offset + 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ft, hf_zh_fg_flag, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ft, hf_zh_fg_offset, tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ft, hf_zh_fg_fid, tvb, offset + 8, 4, ENC_LITTLE_ENDIAN);
	zh_add_string(ft, hf_zh_fg_name, tvb, offset + 12, 256, end);
}

static void
zh_dissect_packet_return(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset,
			 int end)
{
	uint32_t code;

	if (end - offset < 8) {
		proto_tree_add_expert_format(tree, pinfo, &ei_zh_truncated, tvb, offset,
					    end - offset, "PACKET_RETURN 不足 8 字节");
		return;
	}

	proto_item *ri = proto_tree_add_none_format(tree, hf_zh_struct_item, tvb, offset, end - offset,
						    "PACKET_RETURN 响应");
	proto_tree *rt = proto_item_add_subtree(ri, ett_zh_return);

	code = tvb_get_letohl(tvb, offset);
	proto_item *ci = proto_tree_add_item(rt, hf_zh_ret_code, tvb, offset, 4,
					     ENC_LITTLE_ENDIAN);
	proto_item_append_text(ci, " %s", val_to_str_const(code, zh_ret_code_vals, "未知错误码"));
	proto_tree_add_item(rt, hf_zh_ret_sender, tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
	zh_add_string(rt, hf_zh_ret_message, tvb, offset + 8, 256, end);

	col_add_fstr(pinfo->cinfo, COL_INFO, "RETURN code=%u (%s)", code,
		     val_to_str_const(code, zh_ret_code_vals, "未知"));
}

static void
zh_dissect_fault_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset,
		      int end)
{
	if (end - offset < ZH_SZ_FAULT_INFO) {
		proto_tree_add_expert_format(tree, pinfo, &ei_zh_truncated, tvb, offset,
					    end - offset, "FAULT_INFO 不足 502 字节");
		return;
	}

	proto_item *fi = proto_tree_add_none_format(tree, hf_zh_struct_item, tvb, offset,
						    ZH_SZ_FAULT_INFO, "FAULT_INFO 故障信息");
	proto_tree *ft = proto_item_add_subtree(fi, ett_zh_fault);

	proto_tree_add_item(ft, hf_zh_fault_type, tvb, offset + 0, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ft, hf_zh_fault_datnum, tvb, offset + 2, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ft, hf_zh_fault_jmp, tvb, offset + 4, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ft, hf_zh_fault_id, tvb, offset + 6, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ft, hf_zh_fault_size, tvb, offset + 10, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ft, hf_zh_fault_devid, tvb, offset + 14, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ft, hf_zh_fault_code, tvb, offset + 18, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ft, hf_zh_fault_staid, tvb, offset + 22, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ft, hf_zh_fault_type_id, tvb, offset + 26, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(ft, hf_zh_fault_dist, tvb, offset + 30, 8, ENC_LITTLE_ENDIAN);
	zh_dissect_date_time(tvb, ft, offset + 38, end);
	zh_add_string(ft, hf_zh_fault_linename, tvb, offset + 54, 64, end);
	zh_add_string(ft, hf_zh_fault_filename, tvb, offset + 118, 256, end);
	zh_add_string(ft, hf_zh_fault_sti, tvb, offset + 374, 128, end);
}

static void
zh_dissect_yc_array(tvbuff_t *tvb, proto_tree *tree, int offset, int end)
{
	while (end - offset >= ZH_SZ_ZHREC_YC) {
		proto_item *yi = proto_tree_add_none_format(tree, hf_zh_struct_item, tvb, offset,
							   ZH_SZ_ZHREC_YC, "ZHREC_YC 遥测");
		proto_tree *yt = proto_item_add_subtree(yi, ett_zh_yc);

		proto_tree_add_item(yt, hf_zh_yc_gno, tvb, offset + 0, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(yt, hf_zh_yc_ino, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(yt, hf_zh_yc_fv, tvb, offset + 2, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(yt, hf_zh_yc_fa2, tvb, offset + 6, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(yt, hf_zh_yc_fa1, tvb, offset + 10, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(yt, hf_zh_yc_fb1, tvb, offset + 14, 4, ENC_LITTLE_ENDIAN);
		zh_add_string(yt, hf_zh_yc_name, tvb, offset + 18, 48, end);
		zh_add_string(yt, hf_zh_yc_unit1, tvb, offset + 66, 8, end);
		zh_add_string(yt, hf_zh_yc_unit2, tvb, offset + 74, 8, end);

		offset += ZH_SZ_ZHREC_YC;
	}
}

static void
zh_dissect_yx_array(tvbuff_t *tvb, proto_tree *tree, int offset, int end)
{
	while (end - offset >= ZH_SZ_ZHREC_YX) {
		proto_item *yi = proto_tree_add_none_format(tree, hf_zh_struct_item, tvb, offset,
							   ZH_SZ_ZHREC_YX, "ZHREC_YX 遥信");
		proto_tree *yt = proto_item_add_subtree(yi, ett_zh_yx);

		proto_tree_add_item(yt, hf_zh_yx_gno, tvb, offset + 0, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(yt, hf_zh_yx_ino, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(yt, hf_zh_yx_fv, tvb, offset + 2, 4, ENC_LITTLE_ENDIAN);
		zh_add_string(yt, hf_zh_yx_name, tvb, offset + 18, 48, end);

		offset += ZH_SZ_ZHREC_YX;
	}
}

/* ------------------------------------------------------------------ */
/* Frame dissection                                                    */
/* ------------------------------------------------------------------ */

static void
zh_dissect_dat(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t typ,
	       int dat_off, int dat_end, zh_recorder_tap_data_t *tap)
{
	int len = dat_end - dat_off;

	switch (typ) {
	case ZH_PTYPE_RETURN:
		zh_dissect_packet_return(tvb, tree, pinfo, dat_off, dat_end);
		break;

	case ZH_PTYPE_TIME:
		zh_dissect_system_time(tvb, tree, dat_off, dat_end);
		break;

	case ZH_PTYPE_PACKETSIZE:
	case ZH_PTYPE_FRAMEDELAY:
	case ZH_PTYPE_CHKFRMFMT:
		if (len >= 2) {
			uint16_t v = tvb_get_letohs(tvb, dat_off);
			proto_item *wi = proto_tree_add_item(tree, hf_zh_word_value, tvb,
							     dat_off, 2, ENC_LITTLE_ENDIAN);
			proto_item_append_text(wi, v == 0xFFFF ? " (查询当前值)" : " ms/字节");
		}
		break;

	case ZH_PTYPE_FILE_INFO:
	case ZH_PTYPE_FILE_PUT:
		zh_dissect_file_info(tvb, tree, pinfo, dat_off, dat_end, tap);
		break;

	case ZH_PTYPE_FILE_DATA: {
		zh_conv_info_t *conv = zh_get_conv_info(pinfo);

		if (len > 0)
			proto_tree_add_item(tree, hf_zh_data, tvb, dat_off, len, ENC_NA);
		col_add_fstr(pinfo->cinfo, COL_INFO, "文件数据 %d 字节", len);

		if (tap != NULL) {
			/* Attribute the chunk to the file announced on this connection. */
			(void)g_strlcpy(tap->name, conv->name, sizeof(tap->name));
			tap->total_size = conv->total_size;
			tap->offset = 0;   /* exporter accumulates in packet order */
			tap->length = (uint32_t)len;
			tap->data = tvb_get_ptr(tvb, dat_off, len);
		}
		if (conv->name[0] != '\0')
			proto_item_append_text(tree, " [%s]", conv->name);
		break;
	}

	case ZH_PTYPE_FILE_GET:
	case ZH_PTYPE_DIR_GET:
	case ZH_PTYPE_FILE_VER:
		if (typ == ZH_PTYPE_FILE_VER && len >= ZH_SZ_FILE_VER) {
			proto_item *vi = proto_tree_add_none_format(tree, hf_zh_struct_item, tvb,
								   dat_off, ZH_SZ_FILE_VER,
								   "FILE_VER 版本");
			proto_tree *vt = proto_item_add_subtree(vi, ett_zh_file_info);
			zh_add_string(vt, hf_zh_fv_ver, tvb, dat_off, 32, dat_end);
			zh_dissect_file_info(tvb, vt, pinfo, dat_off + 32, dat_end, NULL);
		} else {
			zh_dissect_file_get(tvb, tree, pinfo, dat_off, dat_end);
		}
		break;

	case ZH_PTYPE_WORK_PATH:
	case ZH_PTYPE_DATA_PATH:
		if (len > 0)
			zh_add_string(tree, hf_zh_path, tvb, dat_off, len, dat_end);
		break;

	case ZH_PTYPE_RECORDERINFO:
		if (len > 0)
			proto_tree_add_item(tree, hf_zh_data, tvb, dat_off, len, ENC_NA);
		break;

	case ZH_PTYPE_GETMODEL:
		if (len >= 4) {
			uint32_t model = tvb_get_letohl(tvb, dat_off);
			proto_item *mi = proto_tree_add_item(tree, hf_zh_dword_value, tvb,
							     dat_off, 4, ENC_LITTLE_ENDIAN);
			proto_item_append_text(mi, " %s",
					       val_to_str_const(model, zh_model_vals, "未知型号"));
		}
		break;

	case ZH_PTYPE_GETNEWSTATUS:
	case ZH_PTYPE_RESETNEWSTATUS:
		if (len >= 4) {
			uint32_t status = tvb_get_letohl(tvb, dat_off);
			proto_item *si = proto_tree_add_item(tree, hf_zh_dword_value, tvb,
							     dat_off, 4, ENC_LITTLE_ENDIAN);
			proto_item_append_text(si, " 新录波=%s 定值改变=%s 配置改变=%s",
					       (status & 0x01) ? "是" : "否",
					       (status & 0x02) ? "是" : "否",
					       (status & 0x04) ? "是" : "否");
		}
		break;

	case ZH_PTYPE_YC:
	case ZH_PTYPE_YCEX:
		zh_dissect_yc_array(tvb, tree, dat_off, dat_end);
		break;

	case ZH_PTYPE_YX:
		zh_dissect_yx_array(tvb, tree, dat_off, dat_end);
		break;

	case ZH_PTYPE_CANCEL:
	case ZH_PTYPE_RECORD:
		break;

	default:
		if (len > 0)
			proto_tree_add_item(tree, hf_zh_data, tvb, dat_off, len, ENC_NA);
		break;
	}
}

/* Work out the whole PDU length (header + DAT + trailer). */
static unsigned
zh_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	uint32_t len;
	bool type2;
	int avail;

	avail = tvb_reported_length_remaining(tvb, offset);
	if (avail < ZH_HDR_TYPE1)
		return (unsigned)(avail > 0 ? avail : 0);

	type2 = (tvb_get_letohl(tvb, offset) == ZH_STX &&
		 avail >= ZH_HDR_TYPE2 &&
		 tvb_get_letohl(tvb, offset + 4) == ZH_STX);

	len = tvb_get_letohl(tvb, offset + (type2 ? 12 : 4));
	if (len > ZH_MAX_LEN)
		return (unsigned)avail;   /* bogus length: consume rest */

	int total = (int)len + (type2 ? ZH_HDR_TYPE2 + ZH_TRAILER_TYPE2 : ZH_HDR_TYPE1);
	if (total > avail)
		return (unsigned)avail;
	return (unsigned)total;
}

static int
dissect_zh_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	int total = (int)tvb_reported_length(tvb);
	int offset = 0;
	bool type2;
	uint32_t typ, len;
	int hdr_len, dat_off, dat_end;
	zh_recorder_tap_data_t tap;
	bool have_tap = false;

	if (total < ZH_HDR_TYPE1)
		return total;

	type2 = (tvb_get_letohl(tvb, 0) == ZH_STX && total >= ZH_HDR_TYPE2 &&
		 tvb_get_letohl(tvb, 4) == ZH_STX);

	hdr_len = type2 ? ZH_HDR_TYPE2 : ZH_HDR_TYPE1;
	typ = tvb_get_letohl(tvb, type2 ? 8 : 0);
	len = tvb_get_letohl(tvb, type2 ? 12 : 4);

	proto_item *ti = proto_tree_add_item(tree, proto_zh_recorder, tvb, 0, total, ENC_NA);
	proto_tree *root = proto_item_add_subtree(ti, ett_zh);
	proto_item_append_text(ti, " %s", val_to_str_const(type2 ? 2 : 1,
							   zh_frame_type_vals, ""));

	proto_tree_add_uint(root, hf_zh_frame_type, tvb, 0, 1, type2 ? 2 : 1);

	if (type2) {
		offset = 0;
		proto_tree_add_item(root, hf_zh_stx, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(root, hf_zh_stx, tvb, offset + 4, 4, ENC_LITTLE_ENDIAN);
		offset += 8;
	}

	proto_item *typi = proto_tree_add_item(root, hf_zh_typ, tvb, offset, 4,
					       ENC_LITTLE_ENDIAN);
	proto_item_append_text(typi, " %s", val_to_str_const(typ, zh_typ_vals, "未知类型"));
	offset += 4;

	proto_item *leni = proto_tree_add_item(root, hf_zh_len, tvb, offset, 4,
					       ENC_LITTLE_ENDIAN);
	offset += 4;

	if (len > ZH_MAX_LEN) {
		proto_tree_add_expert_format(root, pinfo, &ei_zh_len_invalid, tvb,
					    offset - 4, 4,
					    "LEN=%u 超过上限 %d，报文按截断处理",
					    len, ZH_MAX_LEN);
		len = (uint32_t)(total - hdr_len);
	} else if ((int)len > total - hdr_len) {
		proto_tree_add_expert_format(root, pinfo, &ei_zh_truncated, tvb,
					    offset - 4, 4,
					    "LEN=%u 超出实际报文长度（剩余 %d 字节）",
					    len, total - hdr_len);
		len = (uint32_t)(total - hdr_len);
	}
	proto_item_append_text(leni, " (DAT %u 字节，整帧 %d 字节)", len, total);

	dat_off = offset;
	dat_end = offset + (int)len;
	if (dat_end > total)
		dat_end = total;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "武汉中原录波器");
	col_clear(pinfo->cinfo, COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "TYP=0x%08X %s", typ,
		     val_to_str_const(typ, zh_typ_vals, "未知类型"));

	memset(&tap, 0, sizeof(tap));
	tap.framenum = pinfo->num;
	tap.kind = ZH_RECORDER_TAP_FILE_BEGIN;

	zh_dissect_dat(tvb, root, pinfo, typ, dat_off, dat_end, &tap);

	/* Type 2 trailer: CHS + ETX + ETX. */
	if (type2 && dat_end + ZH_TRAILER_TYPE2 <= total) {
		uint32_t chs = tvb_get_letohl(tvb, dat_end);
		uint32_t calc = 0;
		int sum_off = 8;                      /* TYP starts here in type 2 */
		int sum_len = (dat_end - sum_off);     /* TYP + LEN + DAT */

		for (int i = 0; i < sum_len; i++)
			calc += tvb_get_uint8(tvb, sum_off + i);
		calc &= 0xFFFFFFFFu;

		proto_item *csi = proto_tree_add_item(root, hf_zh_chs, tvb, dat_end, 4,
						      ENC_LITTLE_ENDIAN);
		proto_tree_add_boolean(root, hf_zh_chs_ok, tvb, 0, 0, chs == calc);
		if (chs != calc) {
			proto_tree_add_expert_format(root, pinfo, &ei_zh_chs_bad, tvb, dat_end, 4,
						    "校验和错误：报文 0x%08X，计算 0x%08X",
						    chs, calc);
			proto_item_append_text(csi, " (校验和错误，应为 0x%08X)", calc);
		} else {
			proto_item_append_text(csi, " (校验正确)");
		}
		proto_tree_add_item(root, hf_zh_etx, tvb, dat_end + 4, 4, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(root, hf_zh_etx, tvb, dat_end + 8, 4, ENC_LITTLE_ENDIAN);
	}

	/* Tap for the GUI exporter: file start carries the name/size, data the bytes. */
	if (typ == ZH_PTYPE_FILE_INFO || typ == ZH_PTYPE_FILE_PUT) {
		have_tap = tap.name[0] != '\0';
		tap.kind = ZH_RECORDER_TAP_FILE_BEGIN;
	} else if (typ == ZH_PTYPE_FILE_DATA) {
		have_tap = tap.data != NULL && tap.length > 0;
		tap.kind = ZH_RECORDER_TAP_FILE_DATA;
	}

	if (have_tap && have_tap_listener(zh_tap))
		tap_queue_packet(zh_tap, pinfo, &tap);

	return total;
}

static int
dissect_zh_recorder_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	int total = (int)tvb_reported_length(tvb);

	if (total < ZH_HDR_TYPE1)
		return 0;

	/* Only claim the stream when it starts with a known frame marker. */
	if (tvb_get_letohl(tvb, 0) != ZH_STX) {
		static const uint32_t known[] = {
			ZH_PTYPE_RETURN, ZH_PTYPE_TIME, ZH_PTYPE_PACKETSIZE,
			ZH_PTYPE_FRAMEDELAY, ZH_PTYPE_FILE_INFO, ZH_PTYPE_FILE_DATA,
			ZH_PTYPE_FILE_GET, ZH_PTYPE_FILE_PUT, ZH_PTYPE_FILE_VER,
			ZH_PTYPE_DIR_GET, ZH_PTYPE_WORK_PATH, ZH_PTYPE_DATA_PATH,
			ZH_PTYPE_CANCEL, ZH_PTYPE_RECORD, ZH_PTYPE_RECORDERINFO,
			ZH_PTYPE_GETMODEL, ZH_PTYPE_GETNEWSTATUS, ZH_PTYPE_RESETNEWSTATUS,
			ZH_PTYPE_YC, ZH_PTYPE_YX, ZH_PTYPE_YCEX,
		};
		uint32_t typ = tvb_get_letohl(tvb, 0);
		bool found = false;

		for (size_t i = 0; i < array_length(known); i++) {
			if (known[i] == typ) {
				found = true;
				break;
			}
		}
		if (!found)
			return 0;
	}

	tcp_dissect_pdus(tvb, pinfo, tree, true, ZH_HDR_TYPE1, zh_pdu_len, dissect_zh_pdu, data);
	return total;
}

/* ------------------------------------------------------------------ */
/* Registration                                                        */
/* ------------------------------------------------------------------ */

void
proto_register_zh_recorder(void)
{
	static hf_register_info hf[] = {
		{ &hf_zh_frame_type,
		  { "帧格式", "zh_recorder.frame_type", FT_UINT8, BASE_DEC,
		    VALS(zh_frame_type_vals), 0, NULL, HFILL }},
		{ &hf_zh_stx,
		  { "启动符 STX", "zh_recorder.stx", FT_UINT32, BASE_HEX, NULL, 0,
		    "76337692H", HFILL }},
		{ &hf_zh_typ,
		  { "报文类型 TYP", "zh_recorder.typ", FT_UINT32, BASE_HEX,
		    VALS(zh_typ_vals), 0, NULL, HFILL }},
		{ &hf_zh_len,
		  { "DAT 长度 LEN", "zh_recorder.len", FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_chs,
		  { "校验和 CHS", "zh_recorder.chs", FT_UINT32, BASE_HEX, NULL, 0,
		    "TYP+LEN+DAT 字节累加和", HFILL }},
		{ &hf_zh_chs_ok,
		  { "校验和正确", "zh_recorder.chs_ok", FT_BOOLEAN, BASE_NONE,
		    TFS(&tfs_yes_no), 0, NULL, HFILL }},
		{ &hf_zh_etx,
		  { "结束符 ETX", "zh_recorder.etx", FT_UINT32, BASE_HEX, NULL, 0,
		    "76927633H", HFILL }},

		{ &hf_zh_ret_code,
		  { "错误码", "zh_recorder.return.code", FT_UINT32, BASE_DEC,
		    VALS(zh_ret_code_vals), 0, NULL, HFILL }},
		{ &hf_zh_ret_sender,
		  { "发送者", "zh_recorder.return.sender", FT_UINT32, BASE_DEC,
		    VALS(zh_sender_vals), 0, NULL, HFILL }},
		{ &hf_zh_ret_message,
		  { "错误描述", "zh_recorder.return.message", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},

		{ &hf_zh_dt_year,
		  { "年", "zh_recorder.time.year", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_dt_month,
		  { "月", "zh_recorder.time.month", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_dt_day,
		  { "日", "zh_recorder.time.day", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_dt_hour,
		  { "时", "zh_recorder.time.hour", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_dt_minute,
		  { "分", "zh_recorder.time.minute", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_dt_second,
		  { "秒", "zh_recorder.time.second", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_dt_ms,
		  { "毫秒", "zh_recorder.time.ms", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_dt_us,
		  { "微秒", "zh_recorder.time.us", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_st_dow,
		  { "星期", "zh_recorder.systime.day_of_week", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_st_dom,
		  { "日期", "zh_recorder.systime.day_of_month", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},

		{ &hf_zh_fi_from,
		  { "文件来源", "zh_recorder.file_info.from", FT_UINT32, BASE_DEC, NULL, 0,
		    "0 = 来源于磁盘", HFILL }},
		{ &hf_zh_fi_size,
		  { "文件大小", "zh_recorder.file_info.size", FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_fi_attr,
		  { "文件属性", "zh_recorder.file_info.attr", FT_UINT32, BASE_HEX,
		    VALS(zh_file_attr_vals), 0, NULL, HFILL }},
		{ &hf_zh_fi_offset,
		  { "发送偏移", "zh_recorder.file_info.offset", FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_fi_length,
		  { "发送长度", "zh_recorder.file_info.length", FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_fi_name,
		  { "文件名", "zh_recorder.file_info.name", FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_fg_from,
		  { "文件来源", "zh_recorder.file_get.from", FT_UINT16, BASE_DEC, NULL, 0,
		    "0 = 来源于磁盘", HFILL }},
		{ &hf_zh_fg_flag,
		  { "标记", "zh_recorder.file_get.flag", FT_UINT16, BASE_HEX,
		    VALS(zh_file_flag_vals), 0, NULL, HFILL }},
		{ &hf_zh_fg_offset,
		  { "文件偏移", "zh_recorder.file_get.offset", FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_fg_fid,
		  { "FID", "zh_recorder.file_get.fid", FT_INT32, BASE_DEC, NULL, 0,
		    "flag=0 时也为 0", HFILL }},
		{ &hf_zh_fg_name,
		  { "文件名/过滤串", "zh_recorder.file_get.name", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},

		{ &hf_zh_fv_ver,
		  { "文件版本", "zh_recorder.file_ver.ver", FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }},

		{ &hf_zh_fault_type,
		  { "文件类型", "zh_recorder.fault.type", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_fault_datnum,
		  { "数据文件数目", "zh_recorder.fault.datnum", FT_INT16, BASE_DEC, NULL, 0,
		    "总为 1", HFILL }},
		{ &hf_zh_fault_jmp,
		  { "跳闸相别", "zh_recorder.fault.jmp", FT_UINT16, BASE_HEX, NULL, 0,
		    "0x0008=A 0x0004=B 0x0002=C", HFILL }},
		{ &hf_zh_fault_id,
		  { "故障编号", "zh_recorder.fault.faultid", FT_INT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_fault_size,
		  { "文件大小", "zh_recorder.fault.filesize", FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_fault_devid,
		  { "设备节点 ID", "zh_recorder.fault.devid", FT_INT32, BASE_DEC, NULL, 0,
		    "总为 0", HFILL }},
		{ &hf_zh_fault_code,
		  { "启动码", "zh_recorder.fault.code", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_fault_staid,
		  { "子站节点 ID", "zh_recorder.fault.staid", FT_INT32, BASE_DEC, NULL, 0,
		    "总为 0", HFILL }},
		{ &hf_zh_fault_type_id,
		  { "故障类型", "zh_recorder.fault.faulttype", FT_UINT32, BASE_HEX,
		    VALS(zh_faulttype_vals), 0, NULL, HFILL }},
		{ &hf_zh_fault_dist,
		  { "故障距离", "zh_recorder.fault.fdist", FT_DOUBLE, BASE_NONE, NULL, 0,
		    "km", HFILL }},
		{ &hf_zh_fault_linename,
		  { "故障元件名称", "zh_recorder.fault.linename", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_zh_fault_filename,
		  { "故障文件名称", "zh_recorder.fault.filename", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_zh_fault_sti,
		  { "启动信息", "zh_recorder.fault.sti", FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }},

		{ &hf_zh_yc_gno,
		  { "组号", "zh_recorder.yc.gno", FT_UINT8, BASE_DEC, NULL, 0,
		    "20 基本遥测 / 21 扩展遥测", HFILL }},
		{ &hf_zh_yc_ino,
		  { "条目号", "zh_recorder.yc.ino", FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_yc_fv,
		  { "标准值", "zh_recorder.yc.fv", FT_FLOAT, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_yc_fa2,
		  { "二次侧系数", "zh_recorder.yc.fa2", FT_FLOAT, BASE_NONE, NULL, 0,
		    "S2 = fv * fa2", HFILL }},
		{ &hf_zh_yc_fa1,
		  { "一次侧斜率", "zh_recorder.yc.fa1", FT_FLOAT, BASE_NONE, NULL, 0,
		    "S1 = fv * fa1 + fb1", HFILL }},
		{ &hf_zh_yc_fb1,
		  { "一次侧截距", "zh_recorder.yc.fb1", FT_FLOAT, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_yc_name,
		  { "描述", "zh_recorder.yc.name", FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_yc_unit1,
		  { "一次侧量纲", "zh_recorder.yc.unit1", FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_yc_unit2,
		  { "二次侧量纲", "zh_recorder.yc.unit2", FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }},

		{ &hf_zh_yx_gno,
		  { "组号", "zh_recorder.yx.gno", FT_UINT8, BASE_DEC, NULL, 0,
		    "30 = 遥信组", HFILL }},
		{ &hf_zh_yx_ino,
		  { "条目号", "zh_recorder.yx.ino", FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_yx_fv,
		  { "标准值", "zh_recorder.yx.fv", FT_FLOAT, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_yx_name,
		  { "描述", "zh_recorder.yx.name", FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }},

		{ &hf_zh_word_value,
		  { "WORD 值", "zh_recorder.word_value", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_dword_value,
		  { "DWORD 值", "zh_recorder.dword_value", FT_UINT32, BASE_HEX, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_path,
		  { "路径", "zh_recorder.path", FT_STRING, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_data,
		  { "数据", "zh_recorder.data", FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_zh_struct_item,
		  { "结构", "zh_recorder.struct", FT_NONE, BASE_NONE, NULL, 0,
		    "协议结构体容器", HFILL }},
	};

	static int *ett[] = {
		&ett_zh, &ett_zh_frame, &ett_zh_return, &ett_zh_time,
		&ett_zh_file_info, &ett_zh_file_get, &ett_zh_fault,
		&ett_zh_yc, &ett_zh_yx,
	};

	static ei_register_info ei[] = {
		{ &ei_zh_len_invalid,
		  { "zh_recorder.len.invalid", PI_MALFORMED, PI_ERROR,
		    "LEN 超过协议上限", EXPFILL }},
		{ &ei_zh_chs_bad,
		  { "zh_recorder.chs.bad", PI_CHECKSUM, PI_WARN,
		    "类型二帧校验和错误", EXPFILL }},
		{ &ei_zh_truncated,
		  { "zh_recorder.truncated", PI_MALFORMED, PI_WARN,
		    "报文长度不足", EXPFILL }},
	};

	proto_zh_recorder = proto_register_protocol(
		"武汉中原录波器规约",
		"武汉中原录波器",
		"zh_recorder");

	proto_register_field_array(proto_zh_recorder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_module_t *expert = expert_register_protocol(proto_zh_recorder);
	expert_register_field_array(expert, ei, array_length(ei));

	zh_recorder_handle = register_dissector("zh_recorder", dissect_zh_recorder_tcp,
						proto_zh_recorder);
	zh_tap = register_tap(ZH_RECORDER_TAP_NAME);
}

void
proto_reg_handoff_zh_recorder(void)
{
	/* Neutral capture policy: TCP 30282 is decoded only after the user picks
	 * 录波器规约 → 武汉中原录波器规约解析, which applies Decode As. */
	dissector_add_for_decode_as("tcp.port", zh_recorder_handle);
}
