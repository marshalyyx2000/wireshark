/* packet-minimal-stubs.c
 *
 * ENABLE_MINIMAL_BUILD helpers:
 * 1) dns/tls/dtls symbols without registering those protocols (§7.3)
 * 2) empty dissector / heur / capture tables so keep-list handoffs
 *    do not emit "dissector table ... doesn't exist" OOPS
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>

#include "packet-dns.h"
#include "packet-tls.h"
#include "packet-dtls.h"
#include "packet-ros.h"
#include "packet-pkixalgs.h"
#include "packet-dap.h"
#include "packet-p1.h"
#include "packet-wccp.h"

void proto_register_minimal_stubs(void);
void proto_reg_handoff_minimal_stubs(void);

/* GRE references WCCP's value_string; provide a tiny stub table. */
const value_string service_id_vals[] = {
	{ 0, NULL }
};

void
register_ros_oid_dissector_handle(const char *oid _U_, dissector_handle_t dissector _U_,
	int proto _U_, const char *name _U_, bool uses_rtse _U_)
{
}

#define MINIMAL_BER_STUB(fn) \
unsigned fn(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset, \
	asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) \
{ \
	return offset; \
}

MINIMAL_BER_STUB(dissect_pkixalgs_RSAPublicKey)
MINIMAL_BER_STUB(dissect_pkixalgs_DSAPublicKey)
MINIMAL_BER_STUB(dissect_pkixalgs_DHPublicKey)
MINIMAL_BER_STUB(dissect_dap_FamilyGrouping)
MINIMAL_BER_STUB(dissect_dap_ServiceControlOptions)
MINIMAL_BER_STUB(dissect_dap_FamilyReturn)
MINIMAL_BER_STUB(dissect_dap_HierarchySelections)
MINIMAL_BER_STUB(dissect_dap_SearchControlOptions)
MINIMAL_BER_STUB(dissect_p1_ORAddress)
MINIMAL_BER_STUB(dissect_p1_G3FacsimileNonBasicParameters)

int
get_dns_name(wmem_allocator_t *scope _U_, tvbuff_t *tvb _U_, int offset _U_,
	int max_len _U_, int dns_data_offset _U_, const char **name, int *name_len)
{
	if (name) {
		*name = "";
	}
	if (name_len) {
		*name_len = 0;
	}
	return 0;
}

void
ssl_dissector_add(unsigned port _U_, dissector_handle_t handle _U_)
{
}

void
ssl_dissector_delete(unsigned port _U_, dissector_handle_t handle _U_)
{
}

void
dtls_dissector_add(unsigned port _U_, dissector_handle_t handle _U_)
{
}

void
dtls_dissector_delete(unsigned port _U_, dissector_handle_t handle _U_)
{
}

static int
dissect_minimal_ppp_hdlc_stub(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return call_data_dissector(tvb, pinfo, tree);
}

void
proto_register_minimal_stubs(void)
{
	/* String dissector tables */
	register_dissector_table("media_type", "Internet media type (stub)",
		-1, FT_STRING, STRING_CASE_INSENSITIVE);
	register_dissector_table("media_type.suffix", "Internet media type suffix (stub)",
		-1, FT_STRING, STRING_CASE_INSENSITIVE);
	register_dissector_table("ldap.name", "LDAP Attribute Type (stub)",
		-1, FT_STRING, STRING_CASE_INSENSITIVE);
	register_dissector_table("rfc7468.preeb_label", "RFC7468 preeb label (stub)",
		-1, FT_STRING, STRING_CASE_SENSITIVE);

	/* Integer dissector tables referenced by keep-list handoffs */
	register_dissector_table("arcnet.protocol_id", "ARCNET Protocol ID (stub)", -1, FT_UINT8, BASE_HEX);
	register_dissector_table("atm.aal5.type", "ATM AAL_5 type (stub)", -1, FT_UINT32, BASE_DEC);
	register_dissector_table("atm_lane", "ATM LAN Emulation (stub)", -1, FT_UINT16, BASE_HEX);
	register_dissector_table("ax25.pid", "AX.25 PID (stub)", -1, FT_UINT8, BASE_HEX);
	register_dissector_table("chdlc.protocol", "Cisco HDLC protocol (stub)", -1, FT_UINT16, BASE_HEX);
	register_dissector_table("dtls.port", "DTLS Port (stub)", -1, FT_UINT16, BASE_DEC);
	register_dissector_table("enc", "OpenBSD Encapsulating device (stub)", -1, FT_UINT32, BASE_DEC);
	register_dissector_table("erf.types.type", "ERF Type (stub)", -1, FT_UINT8, BASE_DEC);
	register_dissector_table("fc.ftype", "FC Frame Type (stub)", -1, FT_UINT8, BASE_HEX);
	register_dissector_table("fr.nlpid", "Frame Relay NLPID (stub)", -1, FT_UINT8, BASE_HEX);
	register_dissector_table("juniper.proto", "Juniper payload (stub)", -1, FT_UINT32, BASE_HEX);
	register_dissector_table("l2tp.pw_type", "L2TPv3 PW type (stub)", -1, FT_UINT32, BASE_DEC);
	register_dissector_table("mcc.proto", "PW ACH MCC proto (stub)", -1, FT_UINT16, BASE_HEX);
	register_dissector_table("mctp.encap-type", "MCTP encap type (stub)", -1, FT_UINT32, BASE_HEX);
	register_dissector_table("nsh.next_proto", "NSH Next Protocol (stub)", -1, FT_UINT32, BASE_DEC);
	register_dissector_table("pcli.payload", "PCLI payload (stub)", -1, FT_UINT32, BASE_DEC);
	register_dissector_table("ppi", "PPI (stub)", -1, FT_UINT32, BASE_DEC);
	register_dissector_table("ppp.protocol", "PPP protocol (stub)", -1, FT_UINT16, BASE_HEX);
	register_dissector_table("pwach.channel_type", "PW ACH channel type (stub)", -1, FT_UINT16, BASE_HEX);
	register_dissector_table("sflow_245.header_protocol", "sFlow header protocol (stub)", -1, FT_UINT32, BASE_DEC);
	register_dissector_table("vxlan.next_proto", "VXLAN Next Protocol (stub)", -1, FT_UINT8, BASE_DEC);
	register_dissector_table("x.25.spi", "X.25 SPI (stub)", -1, FT_UINT8, BASE_HEX);
	register_dissector_table("acdr.media_type", "AC DR Media Type (stub)", -1, FT_UINT32, BASE_DEC);
	register_dissector_table("btl2cap.psm", "Bluetooth L2CAP PSM (stub)", -1, FT_UINT16, BASE_HEX);
	register_dissector_table("btl2cap.cid", "Bluetooth L2CAP CID (stub)", -1, FT_UINT16, BASE_HEX);
	register_dissector_table("wpan.panid", "IEEE 802.15.4 PAN ID (stub)", -1, FT_UINT16, BASE_HEX);

	/* Heuristic dissector lists (must match how keep-list callers use them) */
	register_heur_dissector_list_with_description("tls", "TLS data (stub)", -1);
	register_heur_dissector_list_with_description("tipc", "TIPC data (stub)", -1);
	register_heur_dissector_list_with_description("http", "HTTP payload (stub)", -1);
	register_heur_dissector_list_with_description("wtap_file", "MIME/file (stub)", -1);
	register_heur_dissector_list_with_description("wpan", "IEEE 802.15.4 (stub)", -1);
	register_heur_dissector_list_with_description("gtp.tpdu", "GTP T-PDU (stub)", -1);
	register_heur_dissector_list_with_description("zbee_zcl_se.tun", "ZigBee ZCL SE TUN (stub)", -1);

	/* Named dissectors looked up by find_dissector / find_dissector_add_dependency */
	register_dissector("ppp_hdlc", dissect_minimal_ppp_hdlc_stub, -1);

	/* Capture dissector tables */
	register_capture_dissector_table("ax25.pid", "AX.25 (stub)");
	register_capture_dissector_table("atm.aal5.type", "ATM AAL_5 (stub)");
	register_capture_dissector_table("atm_lane", "ATM LAN Emulation (stub)");
	register_capture_dissector_table("ppp_hdlc", "PPP-HDLC (stub)");
	register_capture_dissector_table("enc", "ENC (stub)");
	register_capture_dissector_table("ppi", "PPI (stub)");
	register_capture_dissector_table("fr.nlpid", "Frame Relay NLPID (stub)");
}

void
proto_reg_handoff_minimal_stubs(void)
{
}
