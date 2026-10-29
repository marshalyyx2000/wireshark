/* packet-sznari-net-iec103.c
 *
 * Shenzhen NARI (深圳南瑞) IEC 60870-5-103 over TCP — shared APCI 2404 dissector.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tfs.h>
#include <wsutil/array.h>

#include "packet-sznari-net-iec103.h"
#include "packet-iec103-net-apci2404-common.h"

void proto_register_sznari_net_iec103(void);
void proto_reg_handoff_sznari_net_iec103(void);

static int proto_sznari_net_iec103;

static int ett_sznari;
static int ett_apci;
static int ett_apci_ctrl;
static int ett_asdu;
static int ett_cp56;
static int ett_sof;
static int ett_gen;
static int ett_gen_entry;

static int hf_start;
static int hf_apdulen;
static int hf_apci_ctrl;
static int hf_apci_tx;
static int hf_apci_rx;
static int hf_u_type;
static int hf_typeid;
static int hf_vsq;
static int hf_vsq_sq;
static int hf_vsq_num;
static int hf_cot;
static int hf_cot_hi;
static int hf_comaddr_unit;
static int hf_comaddr_dev;
static int hf_fun;
static int hf_inf;
static int hf_dpi;
static int hf_spi;
static int hf_sof;
static int hf_sof_tp;
static int hf_sof_tm;
static int hf_sof_test;
static int hf_sof_otev;
static int hf_fan;
static int hf_too;
static int hf_tov;
static int hf_acc;
static int hf_ndv;
static int hf_nfe;
static int hf_rpv;
static int hf_rdv;
static int hf_rfa;
static int hf_gen_group;
static int hf_gen_entry;
static int hf_gen_kod;
static int hf_rii;
static int hf_ngd;
static int hf_ngd_cont;
static int hf_ngd_count;
static int hf_nog;
static int hf_gen_datatype;
static int hf_gen_datasize;
static int hf_gen_datanumber;
static int hf_gen_gid;
static int hf_run;
static int hf_scn;
static int hf_raw;
static int hf_cp56time;
static int hf_cp56time_ms;
static int hf_cp56time_min;
static int hf_cp56time_iv;
static int hf_cp56time_hour;
static int hf_cp56time_su;
static int hf_cp56time_day;
static int hf_cp56time_dow;
static int hf_cp56time_month;
static int hf_cp56time_year;

static const value_string dpi_vals[] = {
	{ 0, "不确定" },
	{ 1, "分" },
	{ 2, "合" },
	{ 3, "无效" },
	{ 0, NULL }
};

static const value_string too_vals[] = {
	{ 1,  "选择故障" },
	{ 2,  "请求扰动数据" },
	{ 3,  "终止扰动数据" },
	{ 8,  "认可扰动数据" },
	{ 9,  "请求通道数据" },
	{ 16, "请求状态量" },
	{ 17, "终止状态量" },
	{ 24, "请求扰动表" },
	{ 0, NULL }
};

static const value_string u_type_vals[] = {
	{ 0x07, "STARTDT act" },
	{ 0x0B, "STARTDT con" },
	{ 0x13, "STOPDT act" },
	{ 0x23, "STOPDT con" },
	{ 0x43, "TESTFR act" },
	{ 0x83, "TESTFR con" },
	{ 0, NULL }
};

static iec103_apci2404_regs_t sznari_regs;

void
proto_register_sznari_net_iec103(void)
{
	static hf_register_info hf[] = {
		{ &hf_start, { "启动字符", "sznari_net_iec103.start", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_apdulen, { "APDU长度", "sznari_net_iec103.apdulen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_apci_ctrl, { "控制域", "sznari_net_iec103.apci.ctrl", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_apci_tx, { "发送序号", "sznari_net_iec103.apci.tx", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_apci_rx, { "接收序号", "sznari_net_iec103.apci.rx", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_u_type, { "U帧类型", "sznari_net_iec103.apci.u_type", FT_UINT8, BASE_HEX, VALS(u_type_vals), 0x0, NULL, HFILL }},
		{ &hf_typeid, { "类型标识", "sznari_net_iec103.typeid", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_vsq, { "VSQ", "sznari_net_iec103.vsq", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_vsq_sq, { "SQ", "sznari_net_iec103.vsq.sq", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
		{ &hf_vsq_num, { "NUM", "sznari_net_iec103.vsq.num", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }},
		{ &hf_cot, { "传送原因", "sznari_net_iec103.cot", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_cot_hi, { "COT高字节", "sznari_net_iec103.cot.hi", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_comaddr_unit, { "单元地址", "sznari_net_iec103.comaddr.unit", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_comaddr_dev, { "装置地址", "sznari_net_iec103.comaddr.dev", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_fun, { "FUN", "sznari_net_iec103.fun", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_inf, { "INF", "sznari_net_iec103.inf", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_dpi, { "DPI", "sznari_net_iec103.dpi", FT_UINT8, BASE_DEC, VALS(dpi_vals), 0x03, NULL, HFILL }},
		{ &hf_spi, { "SPI", "sznari_net_iec103.spi", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL }},
		{ &hf_sof, { "SOF", "sznari_net_iec103.sof", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_sof_tp, { "TP", "sznari_net_iec103.sof.tp", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x01, NULL, HFILL }},
		{ &hf_sof_tm, { "TM", "sznari_net_iec103.sof.tm", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x02, NULL, HFILL }},
		{ &hf_sof_test, { "TEST", "sznari_net_iec103.sof.test", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x04, NULL, HFILL }},
		{ &hf_sof_otev, { "OTEV", "sznari_net_iec103.sof.otev", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x08, NULL, HFILL }},
		{ &hf_fan, { "FAN", "sznari_net_iec103.fan", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_too, { "TOO", "sznari_net_iec103.too", FT_UINT8, BASE_DEC, VALS(too_vals), 0x0, NULL, HFILL }},
		{ &hf_tov, { "TOV", "sznari_net_iec103.tov", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_acc, { "ACC", "sznari_net_iec103.acc", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_ndv, { "NDV", "sznari_net_iec103.ndv", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_nfe, { "NFE", "sznari_net_iec103.nfe", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_rpv, { "RPV", "sznari_net_iec103.rpv", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_rdv, { "RDV", "sznari_net_iec103.rdv", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_rfa, { "RFA", "sznari_net_iec103.rfa", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_group, { "组号", "sznari_net_iec103.gen.group", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_entry, { "条目", "sznari_net_iec103.gen.entry", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_kod, { "KOD", "sznari_net_iec103.gen.kod", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_rii, { "RII", "sznari_net_iec103.rii", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_ngd, { "NGD", "sznari_net_iec103.ngd", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_ngd_cont, { "NGD后续", "sznari_net_iec103.ngd.cont", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80, NULL, HFILL }},
		{ &hf_ngd_count, { "NGD数目", "sznari_net_iec103.ngd.count", FT_UINT8, BASE_DEC, NULL, 0x3F, NULL, HFILL }},
		{ &hf_nog, { "NOG", "sznari_net_iec103.nog", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_datatype, { "数据类型", "sznari_net_iec103.gen.datatype", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_datasize, { "数据宽度", "sznari_net_iec103.gen.datasize", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_datanumber, { "数据数目", "sznari_net_iec103.gen.datanumber", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_gen_gid, { "GID", "sznari_net_iec103.gen.gid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_run, { "运行状态", "sznari_net_iec103.run", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_scn, { "扫描序号", "sznari_net_iec103.scn", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_raw, { "Data", "sznari_net_iec103.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_cp56time, { "CP56Time2a", "sznari_net_iec103.cp56time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }},
		{ &hf_cp56time_ms, { "毫秒", "sznari_net_iec103.cp56time.ms", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_cp56time_min, { "分", "sznari_net_iec103.cp56time.min", FT_UINT8, BASE_DEC, NULL, 0x3F, NULL, HFILL }},
		{ &hf_cp56time_iv, { "IV", "sznari_net_iec103.cp56time.iv", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80, NULL, HFILL }},
		{ &hf_cp56time_hour, { "时", "sznari_net_iec103.cp56time.hour", FT_UINT8, BASE_DEC, NULL, 0x1F, NULL, HFILL }},
		{ &hf_cp56time_su, { "SU", "sznari_net_iec103.cp56time.su", FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80, NULL, HFILL }},
		{ &hf_cp56time_day, { "日", "sznari_net_iec103.cp56time.day", FT_UINT8, BASE_DEC, NULL, 0x1F, NULL, HFILL }},
		{ &hf_cp56time_dow, { "星期", "sznari_net_iec103.cp56time.dow", FT_UINT8, BASE_DEC, NULL, 0xE0, NULL, HFILL }},
		{ &hf_cp56time_month, { "月", "sznari_net_iec103.cp56time.month", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
		{ &hf_cp56time_year, { "年", "sznari_net_iec103.cp56time.year", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL }},
	};

	static int *ett[] = {
		&ett_sznari, &ett_apci, &ett_apci_ctrl, &ett_asdu, &ett_cp56, &ett_sof, &ett_gen, &ett_gen_entry,
	};

	proto_sznari_net_iec103 = proto_register_protocol(
		"深圳南瑞网络103/TCP",
		"深圳南瑞网络103",
		"sznari_net_iec103");

	proto_register_field_array(proto_sznari_net_iec103, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	sznari_regs.proto = proto_sznari_net_iec103;
	sznari_regs.col_protocol = "深圳南瑞网络103";
	sznari_regs.tree_root_label = "深圳南瑞网络103/TCP";
	sznari_regs.apdu_invalid_info = "无有效深圳南瑞APCI";
	sznari_regs.ett_root = &ett_sznari;
	sznari_regs.ett_apci = ett_apci;
	sznari_regs.ett_apci_ctrl = ett_apci_ctrl;
	sznari_regs.ett_asdu = ett_asdu;
	sznari_regs.ett_cp56 = ett_cp56;
	sznari_regs.ett_sof = ett_sof;
	sznari_regs.ett_gen = ett_gen;
	sznari_regs.ett_gen_entry = ett_gen_entry;
	sznari_regs.hf_start = hf_start;
	sznari_regs.hf_apdulen = hf_apdulen;
	sznari_regs.hf_apci_ctrl = hf_apci_ctrl;
	sznari_regs.hf_apci_type = hf_u_type;
	sznari_regs.hf_apci_tx = hf_apci_tx;
	sznari_regs.hf_apci_rx = hf_apci_rx;
	sznari_regs.hf_u_type = hf_u_type;
	sznari_regs.hf_typeid = hf_typeid;
	sznari_regs.hf_vsq = hf_vsq;
	sznari_regs.hf_vsq_sq = hf_vsq_sq;
	sznari_regs.hf_vsq_num = hf_vsq_num;
	sznari_regs.hf_cot = hf_cot;
	sznari_regs.hf_cot_hi = hf_cot_hi;
	sznari_regs.hf_comaddr_unit = hf_comaddr_unit;
	sznari_regs.hf_comaddr_dev = hf_comaddr_dev;
	sznari_regs.hf_fun = hf_fun;
	sznari_regs.hf_inf = hf_inf;
	sznari_regs.hf_dpi = hf_dpi;
	sznari_regs.hf_spi = hf_spi;
	sznari_regs.hf_sof = hf_sof;
	sznari_regs.hf_sof_tp = hf_sof_tp;
	sznari_regs.hf_sof_tm = hf_sof_tm;
	sznari_regs.hf_sof_test = hf_sof_test;
	sznari_regs.hf_sof_otev = hf_sof_otev;
	sznari_regs.hf_fan = hf_fan;
	sznari_regs.hf_too = hf_too;
	sznari_regs.hf_tov = hf_tov;
	sznari_regs.hf_acc = hf_acc;
	sznari_regs.hf_ndv = hf_ndv;
	sznari_regs.hf_nfe = hf_nfe;
	sznari_regs.hf_rpv = hf_rpv;
	sznari_regs.hf_rdv = hf_rdv;
	sznari_regs.hf_rfa = hf_rfa;
	sznari_regs.hf_gen_group = hf_gen_group;
	sznari_regs.hf_gen_entry = hf_gen_entry;
	sznari_regs.hf_gen_kod = hf_gen_kod;
	sznari_regs.hf_rii = hf_rii;
	sznari_regs.hf_ngd = hf_ngd;
	sznari_regs.hf_ngd_cont = hf_ngd_cont;
	sznari_regs.hf_ngd_count = hf_ngd_count;
	sznari_regs.hf_nog = hf_nog;
	sznari_regs.hf_gen_datatype = hf_gen_datatype;
	sznari_regs.hf_gen_datasize = hf_gen_datasize;
	sznari_regs.hf_gen_datanumber = hf_gen_datanumber;
	sznari_regs.hf_gen_gid = hf_gen_gid;
	sznari_regs.hf_run = hf_run;
	sznari_regs.hf_scn = hf_scn;
	sznari_regs.hf_raw = hf_raw;
	sznari_regs.hf_cp56time = hf_cp56time;
	sznari_regs.hf_cp56time_ms = hf_cp56time_ms;
	sznari_regs.hf_cp56time_min = hf_cp56time_min;
	sznari_regs.hf_cp56time_iv = hf_cp56time_iv;
	sznari_regs.hf_cp56time_hour = hf_cp56time_hour;
	sznari_regs.hf_cp56time_su = hf_cp56time_su;
	sznari_regs.hf_cp56time_day = hf_cp56time_day;
	sznari_regs.hf_cp56time_dow = hf_cp56time_dow;
	sznari_regs.hf_cp56time_month = hf_cp56time_month;
	sznari_regs.hf_cp56time_year = hf_cp56time_year;

	iec103_net_apci2404_register_vendor(IEC103_APCI2404_VENDOR_SZNARI, &sznari_regs);
	iec103_net_apci2404_register_prefs(prefs_register_protocol(proto_sznari_net_iec103, NULL));
	proto_register_iec103_net_apci2404_common();
}

void
proto_reg_handoff_sznari_net_iec103(void)
{
	proto_reg_handoff_iec103_net_apci2404_common();
}
