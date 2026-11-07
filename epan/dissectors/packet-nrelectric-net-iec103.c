/* packet-nrelectric-net-iec103.c
 *
 * 南瑞（继保南瑞）以太网 IEC 60870-5-103.
 *
 * Client/server model: master is the TCP server on 1048 (418H), devices are
 * TCP clients. ASDUs travel on the TCP stream with no APCI and no 68H header.
 * UDP 1032 (408H) carries the 41-byte master-on-line broadcast used for master
 * discovery and time sync.
 *
 * See tools/iec103-docs/nrelectric-net.md.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tfs.h>
#include <wsutil/array.h>

#include "packet-iec103-vendor-common.h"

void proto_register_nrelectric_net_iec103(void);
void proto_reg_handoff_nrelectric_net_iec103(void);

#define NR_ASDU_TCP_PORT   1048
#define NR_BCAST_UDP_PORT  1032
#define NR_BCAST_LEN       41
#define NR_BCAST_MARK      0xFF

static int proto_nrelectric_net_iec103;
static int ett_nrelectric_udp;
static int ett_nrelectric_udp_time;

static int hf_nrelectric_udp_mark;
static int hf_nrelectric_udp_time_flag;
static int hf_nrelectric_udp_ms;
static int hf_nrelectric_udp_min;
static int hf_nrelectric_udp_hour;
static int hf_nrelectric_udp_day;
static int hf_nrelectric_udp_dow;
static int hf_nrelectric_udp_month;
static int hf_nrelectric_udp_year;
static int hf_nrelectric_udp_payload;

static dissector_handle_t nrelectric_tcp_handle;
static dissector_handle_t nrelectric_udp_handle;

static iec103_vendor_profile_t nrelectric_profile = {
	0,
	"南瑞网络103",
	NULL,
	"南瑞网络103",
	IEC103_POINTS_NRELECTRIC
};

static int
dissect_nrelectric_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return iec103_vendor_dissect_asdu_stream(tvb, pinfo, tree, &nrelectric_profile);
}

/* 41-byte master on-line broadcast: FF 01 <CP56> <free 16> <zero 16> */
static int
dissect_nrelectric_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	int total = (int)tvb_reported_length(tvb);

	if (total != NR_BCAST_LEN || tvb_get_uint8(tvb, 0) != NR_BCAST_MARK)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "南瑞网络103");
	col_set_str(pinfo->cinfo, COL_INFO, "主站在线广播");

	proto_item *ti = proto_tree_add_item(tree, proto_nrelectric_net_iec103, tvb, 0, total,
					     ENC_NA);
	proto_item_set_text(ti, "南瑞网络103 UDP 主站在线广播");
	proto_tree *root = proto_item_add_subtree(ti, ett_nrelectric_udp);

	proto_tree_add_item(root, hf_nrelectric_udp_mark, tvb, 0, 1, ENC_LITTLE_ENDIAN);

	uint8_t time_flag = tvb_get_uint8(tvb, 1);
	proto_tree_add_item(root, hf_nrelectric_udp_time_flag, tvb, 1, 1, ENC_LITTLE_ENDIAN);

	if (time_flag != 0) {
		int offset = 2;
		proto_item *tmi = proto_tree_add_none_format(root, hf_nrelectric_udp_payload,
							    tvb, offset, 7, "对时信息");
		proto_tree *tm = tmi ? proto_item_add_subtree(tmi, ett_nrelectric_udp_time) : root;
		proto_tree_add_item(tm, hf_nrelectric_udp_ms, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tm, hf_nrelectric_udp_min, tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tm, hf_nrelectric_udp_hour, tvb, offset + 3, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tm, hf_nrelectric_udp_day, tvb, offset + 4, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tm, hf_nrelectric_udp_dow, tvb, offset + 4, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tm, hf_nrelectric_udp_month, tvb, offset + 5, 1,
				    ENC_LITTLE_ENDIAN);
		proto_tree_add_item(tm, hf_nrelectric_udp_year, tvb, offset + 6, 1,
				    ENC_LITTLE_ENDIAN);
		col_append_fstr(pinfo->cinfo, COL_INFO, " %02u:%02u:%02u.%03u",
				tvb_get_uint8(tvb, offset + 3),
				tvb_get_uint8(tvb, offset + 2) & 0x3F,
				tvb_get_letohs(tvb, offset) / 1000,
				tvb_get_letohs(tvb, offset) % 1000);
	}

	/* Free-form tail (bytes 9..24) and zero padding (25..40). */
	proto_tree_add_item(root, hf_nrelectric_udp_payload, tvb, 9, total - 9, ENC_NA);
	return total;
}

void
proto_register_nrelectric_net_iec103(void)
{
	static hf_register_info hf[] = {
		{ &hf_nrelectric_udp_mark,
		  { "标记(FFH=主站)", "nrelectric_net_iec103.udp.mark", FT_UINT8, BASE_HEX,
		    NULL, 0, NULL, HFILL }},
		{ &hf_nrelectric_udp_time_flag,
		  { "对时标志", "nrelectric_net_iec103.udp.time_flag", FT_UINT8, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_nrelectric_udp_ms,
		  { "毫秒", "nrelectric_net_iec103.udp.ms", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},
		{ &hf_nrelectric_udp_min,
		  { "分", "nrelectric_net_iec103.udp.min", FT_UINT8, BASE_DEC, NULL, 0x3F,
		    NULL, HFILL }},
		{ &hf_nrelectric_udp_hour,
		  { "时", "nrelectric_net_iec103.udp.hour", FT_UINT8, BASE_DEC, NULL, 0x1F,
		    NULL, HFILL }},
		{ &hf_nrelectric_udp_day,
		  { "日", "nrelectric_net_iec103.udp.day", FT_UINT8, BASE_DEC, NULL, 0x1F,
		    NULL, HFILL }},
		{ &hf_nrelectric_udp_dow,
		  { "星期", "nrelectric_net_iec103.udp.dow", FT_UINT8, BASE_DEC, NULL, 0xE0,
		    NULL, HFILL }},
		{ &hf_nrelectric_udp_month,
		  { "月", "nrelectric_net_iec103.udp.month", FT_UINT8, BASE_DEC, NULL, 0x0F,
		    NULL, HFILL }},
		{ &hf_nrelectric_udp_year,
		  { "年", "nrelectric_net_iec103.udp.year", FT_UINT8, BASE_DEC, NULL, 0x7F,
		    NULL, HFILL }},
		{ &hf_nrelectric_udp_payload,
		  { "广播数据", "nrelectric_net_iec103.udp.data", FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
	};

	static int *ett[] = { &ett_nrelectric_udp, &ett_nrelectric_udp_time };

	proto_nrelectric_net_iec103 = proto_register_protocol(
		"南瑞网络103/TCP",
		"南瑞网络103",
		"nrelectric_net_iec103");

	proto_register_field_array(proto_nrelectric_net_iec103, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	nrelectric_profile.proto = proto_nrelectric_net_iec103;

	nrelectric_tcp_handle = register_dissector("nrelectric_net_iec103",
						   dissect_nrelectric_tcp,
						   proto_nrelectric_net_iec103);
	nrelectric_udp_handle = register_dissector("nrelectric_net_iec103_udp",
						   dissect_nrelectric_udp,
						   proto_nrelectric_net_iec103);

	iec103_vendor_register(&nrelectric_profile);
	iec103_vendor_register_prefs(
		prefs_register_protocol(proto_nrelectric_net_iec103, NULL), "南瑞网络103");
}

void
proto_reg_handoff_nrelectric_net_iec103(void)
{
	/* Neutral capture policy: TCP 1048 is shared with 南自 and UDP 1032 is
	 * shared with the 南自 broadcast, so neither port is bound here. The
	 * 网络103 → 南瑞网络103规约解析 menu applies Decode As at runtime. */
	dissector_add_for_decode_as("tcp.port", nrelectric_tcp_handle);
	dissector_add_for_decode_as("udp.port", nrelectric_udp_handle);
	iec103_points_init();
}
