/* packet-jicheng-net-iec103.c
 *
 * 积成电子 IES-N103 以太网 IEC 60870-5-103.
 *
 * APDU: 68H | length (1 byte) | control (4 bytes, IEC 60870-5-104 I/S/U) | ASDU
 * Length counts control + ASDU; APDU max 253, ASDU max 249.
 *
 * Master is the TCP client, the IED is the server. Broadcast commands use UDP
 * on the same port with an unspecified control field.
 *
 * Basis: 积成IES-N103以太网通讯规约说明 V1.00. See tools/iec103-docs/jicheng.md.
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

void proto_register_jicheng_net_iec103(void);
void proto_reg_handoff_jicheng_net_iec103(void);

#define JC_START    0x68
#define JC_HDR_LEN  6            /* 68H + length + 4 control bytes */
#define JC_CTRL_LEN 4
#define JC_MAX_LEN  253
#define JC_MIN_APDU (JC_HDR_LEN + IEC103_ASDU_HDR_LEN)

static int proto_jicheng_net_iec103;
static int ett_jicheng;
static int ett_jc_apci;
static int ett_jc_ctrl;

static int hf_jc_start;
static int hf_jc_length;
static int hf_jc_ctrl;
static int hf_jc_frame_type;
static int hf_jc_tx;
static int hf_jc_rx;
static int hf_jc_u_func;
static int hf_jc_apdu_item;
static int hf_jc_raw;

static dissector_handle_t jicheng_tcp_handle;
static dissector_handle_t jicheng_udp_handle;

static const value_string jc_frame_type_vals[] = {
	{ 0, "I 格式(信息传输)" },
	{ 1, "S 格式(监视)" },
	{ 2, "U 格式(控制)" },
	{ 0, NULL }
};

static const value_string jc_u_func_vals[] = {
	{ 0x07, "STARTDT 生效" },
	{ 0x0B, "STARTDT 确认" },
	{ 0x13, "STOPDT 生效" },
	{ 0x23, "STOPDT 确认" },
	{ 0x43, "TESTFR 生效" },
	{ 0x83, "TESTFR 确认" },
	{ 0, NULL }
};

/* Vendor COT values (application layer rules). */
static const value_string jc_extra_cot_vals[] = {
	{ 40, "通用分类写命令" },
	{ 41, "通用分类写否定认可" },
	{ 42, "通用分类读命令" },
	{ 43, "通用分类读无效数据响应" },
	{ 44, "通用分类写确认" },
	{ 0, NULL }
};

static iec103_vendor_profile_t jc_profile = {
	0,
	"积成网络103",
	NULL,
	"积成网络103",
	IEC103_POINTS_JICHENG,
	NULL,               /* only compatible-range TYPs are used */
	jc_extra_cot_vals,
	NULL
};

/* ------------------------------------------------------------------ */

static int
jc_frame_type(uint8_t ctrl0)
{
	if ((ctrl0 & 0x01) == 0)
		return 0;
	if ((ctrl0 & 0x02) == 0)
		return 1;
	return 2;
}

static void
jc_dissect_ctrl(tvbuff_t *tvb, int offset, proto_tree *tree, packet_info *pinfo)
{
	uint8_t c0 = tvb_get_uint8(tvb, offset);
	int ftype = jc_frame_type(c0);

	proto_item *ci = proto_tree_add_item(tree, hf_jc_ctrl, tvb, offset, JC_CTRL_LEN, ENC_NA);
	proto_tree *ct = proto_item_add_subtree(ci, ett_jc_ctrl);
	proto_item_append_text(ci, " %s", val_to_str_const(ftype, jc_frame_type_vals, "未知"));
	proto_tree_add_uint(ct, hf_jc_frame_type, tvb, offset, 1, (uint32_t)ftype);

	if (ftype == 0) {
		uint16_t ns = (uint16_t)(((c0 & 0xFE) >> 1) |
					 (tvb_get_uint8(tvb, offset + 1) << 7));
		uint16_t nr = (uint16_t)(((tvb_get_uint8(tvb, offset + 2) & 0xFE) >> 1) |
					 (tvb_get_uint8(tvb, offset + 3) << 7));
		proto_tree_add_uint(ct, hf_jc_tx, tvb, offset, 2, ns);
		proto_tree_add_uint(ct, hf_jc_rx, tvb, offset + 2, 2, nr);
		col_append_fstr(pinfo->cinfo, COL_INFO, "I N(S)=%u N(R)=%u", ns, nr);
	} else if (ftype == 1) {
		uint16_t nr = (uint16_t)(((tvb_get_uint8(tvb, offset + 2) & 0xFE) >> 1) |
					 (tvb_get_uint8(tvb, offset + 3) << 7));
		proto_tree_add_uint(ct, hf_jc_rx, tvb, offset + 2, 2, nr);
		col_append_fstr(pinfo->cinfo, COL_INFO, "S N(R)=%u", nr);
	} else {
		proto_item *uf = proto_tree_add_item(ct, hf_jc_u_func, tvb, offset, 1, ENC_NA);
		proto_item_append_text(uf, " (%s)",
				       val_to_str_const(c0, jc_u_func_vals, "未定义"));
		col_append_fstr(pinfo->cinfo, COL_INFO, "U %s",
				val_to_str_const(c0, jc_u_func_vals, "未定义"));
	}
}

/* Walk a TCP segment holding one or more APDUs. */
static int
jc_dissect_stream(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int total = (int)tvb_reported_length(tvb);
	int offset = 0;

	proto_item *ti = proto_tree_add_item(tree, proto_jicheng_net_iec103, tvb, 0, total,
					     ENC_NA);
	proto_item_set_text(ti, "积成网络103/TCP");
	proto_tree *root = proto_item_add_subtree(ti, ett_jicheng);

	while (offset + JC_MIN_APDU <= total) {
		if (tvb_get_uint8(tvb, offset) != JC_START)
			break;

		int body_len = tvb_get_uint8(tvb, offset + 1);   /* control + ASDU */
		int apdu_len = body_len + 2;
		if (body_len < JC_CTRL_LEN + IEC103_ASDU_HDR_LEN || apdu_len > JC_MAX_LEN)
			break;
		if (apdu_len > total - offset)
			apdu_len = total - offset;      /* truncated capture */

		int asdu_off = offset + JC_HDR_LEN;
		int asdu_len = body_len - JC_CTRL_LEN;
		if (asdu_len > apdu_len - JC_HDR_LEN)
			asdu_len = apdu_len - JC_HDR_LEN;
		bool asdu_ok = asdu_len >= IEC103_ASDU_HDR_LEN &&
			iec103_vendor_looks_like_asdu_ext(tvb, asdu_off, asdu_len, &jc_profile);

		proto_item *ape = proto_tree_add_none_format(root, hf_jc_apdu_item, tvb, offset,
							     apdu_len, "APDU");
		proto_tree *apci = proto_item_add_subtree(ape, ett_jc_apci);

		proto_tree_add_item(apci, hf_jc_start, tvb, offset, 1, ENC_NA);
		proto_item *li = proto_tree_add_item(apci, hf_jc_length, tvb, offset + 1, 1,
						     ENC_LITTLE_ENDIAN);
		proto_item_append_text(li, " (APDU 共 %d 字节)", apdu_len);

		jc_dissect_ctrl(tvb, offset + 2, apci, pinfo);
		col_append_str(pinfo->cinfo, COL_INFO, " ");

		if (asdu_ok) {
			iec103_vendor_dissect_one_asdu(tvb, asdu_off, asdu_len, pinfo, apci,
						       &jc_profile);
		} else if (asdu_len > 0) {
			proto_tree_add_item(apci, hf_jc_raw, tvb, asdu_off, asdu_len, ENC_NA);
			proto_item_append_text(ape, " (ASDU 头无效)");
		}

		offset += apdu_len;
	}

	if (offset < total)
		proto_tree_add_item(root, hf_jc_raw, tvb, offset, total - offset, ENC_NA);

	return total;
}

static int
dissect_jicheng_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	int total = (int)tvb_reported_length(tvb);

	if (total < JC_MIN_APDU || tvb_get_uint8(tvb, 0) != JC_START)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, jc_profile.col_protocol);
	col_clear(pinfo->cinfo, COL_INFO);
	return jc_dissect_stream(tvb, pinfo, tree);
}

/* UDP 6185: same frame layout, control field carries no meaning. */
static int
dissect_jicheng_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	int total = (int)tvb_reported_length(tvb);

	if (total < JC_MIN_APDU || tvb_get_uint8(tvb, 0) != JC_START)
		return 0;

    int len = tvb_get_uint8(tvb, 1);
	if (len < JC_CTRL_LEN + IEC103_ASDU_HDR_LEN || len + 2 > total)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, jc_profile.col_protocol);
	col_clear(pinfo->cinfo, COL_INFO);
	col_append_str(pinfo->cinfo, COL_INFO, "UDP 广播 ");
	return jc_dissect_stream(tvb, pinfo, tree);
}

void
proto_register_jicheng_net_iec103(void)
{
	static hf_register_info hf[] = {
		{ &hf_jc_start,
		  { "启动字符", "jicheng_net_iec103.start", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},
		{ &hf_jc_length,
		  { "APDU长度", "jicheng_net_iec103.length", FT_UINT8, BASE_DEC, NULL, 0,
		    "包含控制域与 ASDU 的字节数", HFILL }},
		{ &hf_jc_ctrl,
		  { "控制域", "jicheng_net_iec103.apci.ctrl", FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_jc_frame_type,
		  { "帧格式", "jicheng_net_iec103.apci.frame_type", FT_UINT8, BASE_DEC,
		    VALS(jc_frame_type_vals), 0, NULL, HFILL }},
		{ &hf_jc_tx,
		  { "发送序号 N(S)", "jicheng_net_iec103.apci.tx", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_jc_rx,
		  { "接收序号 N(R)", "jicheng_net_iec103.apci.rx", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_jc_u_func,
		  { "U 帧功能", "jicheng_net_iec103.apci.u_func", FT_UINT8, BASE_HEX,
		    VALS(jc_u_func_vals), 0, NULL, HFILL }},
		{ &hf_jc_raw,
		  { "数据", "jicheng_net_iec103.data", FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
		{ &hf_jc_apdu_item,
		  { "APDU", "jicheng_net_iec103.apdu", FT_NONE, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
	};

	static int *ett[] = { &ett_jicheng, &ett_jc_apci, &ett_jc_ctrl };

	proto_jicheng_net_iec103 = proto_register_protocol(
		"积成网络103",
		"积成网络103",
		"jicheng_net_iec103");

	proto_register_field_array(proto_jicheng_net_iec103, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	jc_profile.proto = proto_jicheng_net_iec103;

	jicheng_tcp_handle = register_dissector("jicheng_net_iec103", dissect_jicheng_tcp,
						proto_jicheng_net_iec103);
	jicheng_udp_handle = register_dissector("jicheng_net_iec103_udp", dissect_jicheng_udp,
						proto_jicheng_net_iec103);

	iec103_vendor_register(&jc_profile);
	iec103_vendor_register_prefs(
		prefs_register_protocol(proto_jicheng_net_iec103, NULL), "积成网络103");
}

void
proto_reg_handoff_jicheng_net_iec103(void)
{
	/* Neutral capture policy: no port binding; the 网络103 menu applies
	 * Decode As for TCP/UDP 6185 when this protocol is selected. */
	dissector_add_for_decode_as("tcp.port", jicheng_tcp_handle);
	dissector_add_for_decode_as("udp.port", jicheng_udp_handle);
	iec103_points_init();
}
