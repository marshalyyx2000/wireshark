/* packet-modbus_vendor.c
 *
 * 厂家 Modbus 规约：ModBus / GE_Modbus / GE_MLINK_MODEM_MODBUS_COM。
 *
 * Basis: tools/现场运行的各种规约程序/PROTOCOL/{ModBus,GE_Modbus,
 * GE_MLINK_MODEM_MODBUS_COM} . 三家的共同点是标准 Modbus RTU（功能码
 * 0x03/0x04 读寄存器、0x10 写多寄存器、CRC16）。GE_MODEM 走的是 Modbus/TCP
 * 的 MBAP 头。
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-modbus-vendor-common.h"

void proto_register_modbus_vendor(void);
void proto_reg_handoff_modbus_vendor(void);

static int proto_modbus_protection;
static int proto_ge_modbus;
static int proto_ge_mlink_modbus;
static int proto_ge_modem_tcp;

static dissector_handle_t modbus_protection_handle;
static dissector_handle_t ge_modbus_handle;
static dissector_handle_t ge_mlink_modbus_handle;
static dissector_handle_t ge_modem_tcp_handle;

/* 参考实现里出现的寄存器地址（PROTOCOL/ModBus/Rtu.cpp 的 0x0000 起读）。 */
static const value_string modbus_reg_vals[] = {
	{ 0x0000, "模拟量区起始" },
	{ 0x0100, "开关量区起始" },
	{ 0x0200, "定值区起始" },
	{ 0x0300, "装置信息区" },
	{ 0, NULL }
};

static modbus_vendor_profile_t modbus_protection_profile = {
	0, "Modbus(RTU)", "Modbus", false, false, NULL, modbus_reg_vals
};

static modbus_vendor_profile_t ge_modbus_profile = {
	0, "GE Modbus(RTU)", "GE Modbus", false, false, NULL, modbus_reg_vals
};

static modbus_vendor_profile_t ge_mlink_profile = {
	0, "GE MLINK Modem Modbus", "GE MLINK Modbus", false, false, NULL, modbus_reg_vals
};

static modbus_vendor_profile_t ge_modem_profile = {
	0, "GE Modem Modbus/TCP", "GE Modem Modbus", true, false, NULL, modbus_reg_vals
};

static int
dissect_modbus_protection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return modbus_vendor_dissect_rtu(tvb, pinfo, tree, &modbus_protection_profile);
}

static int
dissect_ge_modbus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return modbus_vendor_dissect_rtu(tvb, pinfo, tree, &ge_modbus_profile);
}

static int
dissect_ge_mlink_modbus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return modbus_vendor_dissect_rtu(tvb, pinfo, tree, &ge_mlink_profile);
}

static int
dissect_ge_modem_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	return modbus_vendor_dissect_tcp(tvb, pinfo, tree, &ge_modem_profile);
}

void
proto_register_modbus_vendor(void)
{
	proto_modbus_protection = proto_register_protocol(
		"保护装置 Modbus(RTU)", "Modbus(RTU)", "modbus_protection");
	proto_ge_modbus = proto_register_protocol(
		"GE Modbus(RTU)", "GE Modbus", "ge_modbus_rtu");
	proto_ge_mlink_modbus = proto_register_protocol(
		"GE MLINK 调制解调器 Modbus", "GE MLINK Modbus", "ge_mlink_modbus");
	proto_ge_modem_tcp = proto_register_protocol(
		"GE 调制解调器 Modbus/TCP", "GE Modem Modbus/TCP", "ge_modem_modbus_tcp");

	modbus_protection_profile.proto = proto_modbus_protection;
	ge_modbus_profile.proto = proto_ge_modbus;
	ge_mlink_profile.proto = proto_ge_mlink_modbus;
	ge_modem_profile.proto = proto_ge_modem_tcp;

	modbus_protection_handle = register_dissector("modbus_protection",
		dissect_modbus_protection, proto_modbus_protection);
	ge_modbus_handle = register_dissector("ge_modbus_rtu", dissect_ge_modbus,
		proto_ge_modbus);
	ge_mlink_modbus_handle = register_dissector("ge_mlink_modbus",
		dissect_ge_mlink_modbus, proto_ge_mlink_modbus);
	ge_modem_tcp_handle = register_dissector("ge_modem_modbus_tcp", dissect_ge_modem_tcp,
		proto_ge_modem_tcp);

	modbus_vendor_register(&modbus_protection_profile,
		prefs_register_protocol(proto_modbus_protection, NULL));
	modbus_vendor_register(&ge_modbus_profile,
		prefs_register_protocol(proto_ge_modbus, NULL));
	modbus_vendor_register(&ge_mlink_profile,
		prefs_register_protocol(proto_ge_mlink_modbus, NULL));
	modbus_vendor_register(&ge_modem_profile,
		prefs_register_protocol(proto_ge_modem_tcp, NULL));
}

void
proto_reg_handoff_modbus_vendor(void)
{
	/* Neutral capture policy: no port binding. The MODBUS menu applies Decode As. */
	dissector_add_for_decode_as("tcp.port", ge_modem_tcp_handle);
	(void)modbus_protection_handle;
	(void)ge_modbus_handle;
	(void)ge_mlink_modbus_handle;
}
