/* packet-sifang-net-iec103.c
 *
 * 四方（北京四方 CSC2000）网络 IEC 60870-5-103 over UDP.
 *
 * Per CSC2000 网络规约 V2.0: the device multicasts 103 ASDUs (no FT1.2 header,
 * no APCI) to 236.8.8.8, device TX port 1888, master RX 1888 / TX 1889.
 * See tools/iec103-docs/sifang-net.md.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-iec103-vendor-common.h"

void proto_register_sifang_net_iec103(void);
void proto_reg_handoff_sifang_net_iec103(void);

static int proto_sifang_net_iec103;
static dissector_handle_t sifang_net_iec103_handle;
static int hf_sifang_priv;
static int ett_sifang_priv;

/* Documented CSC2000 ports; used by the menu/simulator, not bound by default. */
#define SIFANG_NET_UDP_DEV_PORT    1888
#define SIFANG_NET_UDP_MASTER_PORT 1889

static iec103_vendor_profile_t sifang_net_profile = {
	0,
	"四方网络103",
	NULL,
	"四方网络103",
	IEC103_POINTS_SIFANG
};

/* 四方网络 103 的私有 APCI（参考实现 SF_NET103 / SF_UDP103 的 Rtu.cpp）：
 * ASDU 从偏移 28 开始，前 28 字节为厂商自定的传输头。见
 * tools/protocol-audit/audit/APCI.md。 */
#define SIFANG_PRIV_APCI_LEN 28

static void
dissect_sifang_priv_apci(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int end = (int)tvb_reported_length(tvb);
	int asdu_off = SIFANG_PRIV_APCI_LEN;

	proto_item *ti = proto_tree_add_item(tree, proto_sifang_net_iec103, tvb, 0, end, ENC_NA);
	proto_item_set_text(ti, "四方网络103规约（28 字节传输头）");
	proto_tree *root = proto_item_add_subtree(ti, ett_sifang_priv);

	proto_tree_add_none_format(root, hf_sifang_priv, tvb, 0, SIFANG_PRIV_APCI_LEN,
				   "传输头 %d 字节（ASDU 从 %d 开始）",
				   SIFANG_PRIV_APCI_LEN, asdu_off);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, sifang_net_profile.col_protocol);
	col_clear(pinfo->cinfo, COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "四方网络103 (ASDU @%d)", asdu_off);

	if (end - asdu_off >= IEC103_ASDU_HDR_LEN)
		iec103_vendor_dissect_one_asdu(tvb, asdu_off, end - asdu_off, pinfo, root,
					       &sifang_net_profile);
	(void)asdu_off;
}

static int
dissect_sifang_net_iec103(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	int total = (int)tvb_reported_length(tvb);

	/* Reference implementations put a 28-byte transport header in front of the
	 * ASDU. Accept both that and a bare ASDU so old captures keep working. */
	if (total >= SIFANG_PRIV_APCI_LEN + IEC103_ASDU_HDR_LEN &&
	    !iec103_vendor_looks_like_asdu_ext(tvb, 0, total, &sifang_net_profile)) {
		dissect_sifang_priv_apci(tvb, pinfo, tree);
		return total;
	}

	return iec103_vendor_dissect_asdu_datagram(tvb, pinfo, tree, &sifang_net_profile);
}

void
proto_register_sifang_net_iec103(void)
{
	proto_sifang_net_iec103 = proto_register_protocol(
		"四方网络103/UDP",
		"四方网络103",
		"sifang_net_iec103");

	sifang_net_profile.proto = proto_sifang_net_iec103;

	sifang_net_iec103_handle = register_dissector("sifang_net_iec103",
						      dissect_sifang_net_iec103,
						      proto_sifang_net_iec103);

	iec103_vendor_register(&sifang_net_profile);
	iec103_vendor_register_prefs(
		prefs_register_protocol(proto_sifang_net_iec103, NULL), "四方网络103");

	static hf_register_info hf[] = {
		{ &hf_sifang_priv,
		  { "传输头", "sifang_net_iec103.transport_header", FT_NONE, BASE_NONE,
		    NULL, 0, "28 字节厂商传输头", HFILL }},
	};
	static int *ett[] = { &ett_sifang_priv };

	proto_register_field_array(proto_sifang_net_iec103, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_sifang_net_iec103(void)
{
	/* Neutral capture policy: no port binding, so a UDP 1888/1889 stream is
	 * shown as plain UDP until the user picks it from 网络103 →
	 * 四方网络103规约解析. That menu applies Decode As at runtime. */
	dissector_add_for_decode_as("udp.port", sifang_net_iec103_handle);
	iec103_points_init();
}
