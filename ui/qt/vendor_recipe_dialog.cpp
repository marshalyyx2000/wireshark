/* vendor_recipe_dialog.cpp
 *
 * 把剩下那批厂家的"承载 + 协议短名"集中在一张表里，用同一个对话框选择。
 * 这样每新增一家只需加一行，不用在菜单和槽函数里各改一处。
 *
 * 表内容与 tools/protocol-audit/{vendor-spec,dfr-spec,generic-spec}.json 一致。
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "vendor_recipe_dialog.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

namespace {

struct VendorRecipe {
    const char *carrier;      /* "serial" / "tcp" / "udp" */
    const char *protocol;     /* 协议短名，即 register_dissector 的名字 */
    const char *label;        /* 菜单里显示的中文名 */
};

/* 顺序按承载分组，方便在对话框里找。 */
const VendorRecipe g_recipes[] = {
    /* --- 串口 --- */
    { "serial", "abb103_serial_iec103",          "ABB 串口103" },
    { "serial", "bp103_serial_iec103",           "BP 串口103" },
    { "serial", "siemens103_serial_iec103",      "西门子串口103" },
    { "serial", "sj103_serial_iec103",           "SJ 串口103" },
    { "serial", "alstom103_serial_iec103",       "阿尔斯通串口103" },
    { "serial", "nz103_serial_iec103",           "南自串口103(NZ103)" },
    { "serial", "sf103_serial_iec103",           "四方串口103(SF103)" },
    { "serial", "abb_com101_serial_iec103",      "ABB 串口101(2 字节地址)" },
    { "serial", "gec_serial_iec103",             "GEC 串口103" },
    { "serial", "dgt801_serial",                 "DGT801 串口规约" },
    { "serial", "wxb_serial",                    "WXB 串口规约" },
    { "serial", "wxb11_serial",                  "WXB11 串口规约" },
    { "serial", "ys8_serial",                    "YS8 录波器" },
    { "serial", "ysosc_serial",                  "YS 录波器(YSOsc)" },
    { "serial", "nr_lfp_com",                    "南瑞 LFP 串口规约" },
    { "serial", "huaruit_fwk_com",               "华瑞泰 FWK 串口规约" },
    { "serial", "toshbia_com_rsm",               "东芝 COM RSM 规约" },
    { "serial", "ascii_meter_serial",            "ASCII 电表规约" },
    { "serial", "lfp_serial",                    "LFP 串口规约" },
    { "serial", "wds_serial",                    "WDS 录波器串口规约" },
    { "serial", "spabus_serial",                 "SpaBus 串口规约" },
    { "serial", "sddffr",                        "山东电研院录波器(SDDFR)" },
    { "serial", "modbus_protection",             "保护装置 Modbus(RTU)" },
    { "serial", "ge_modbus_rtu",                 "GE Modbus(RTU)" },
    { "serial", "ge_mlink_modbus",               "GE MLINK 调制解调器 Modbus" },

    /* --- TCP --- */
    { "tcp", "nr103_net_iec103",                 "南瑞网络103(NR_103_NET)" },
    { "tcp", "nr103_rcs9793_iec103",             "南瑞 RCS-9793 网络103" },
    { "tcp", "nz_net103_iec103",                 "南自网络103(NZ_NET103)" },
    { "tcp", "wgl3000_iec103",                   "WGL3000 网络103" },
    { "tcp", "sznr103_tcp_iec103",               "深圳南瑞网络103(TCP)" },
    { "tcp", "sf_csfm103_tcp_iec103",            "四方 CSFM103 网络103" },
    { "tcp", "xj_net103_tcp_iec103",             "许继网络103(XJ_NET103)" },
    { "tcp", "sh2000",                           "上海惠安 SH2000 录波器" },
    { "tcp", "netcsc2000_net",                   "南自 CSC2000 网络规约" },
    { "tcp", "wfbl_ftp103",                      "WFBL 网络103(FTP 承载)" },
    { "tcp", "fh_lr2000_net",                    "FH LR2000 网络录波器" },
    { "tcp", "fh3000_tcp",                       "FH-3000 网络103" },
    { "tcp", "sd_wgdlv_net",                     "山东 WGDLV 网络录波器" },
    { "tcp", "lbd_lubo_tcp",                     "LBD 录波器网络规约" },
    { "tcp", "ge_modem_modbus_tcp",              "GE 调制解调器 Modbus/TCP" },
    { "tcp", "nfdfr",                            "南自录波器(NFDFR)" },
    { "tcp", "nfdfr200",                         "南自录波器200(NFDFR200)" },
    { "tcp", "nf_rfw200_net",                    "南瑞 RFW200 录波器" },
    { "tcp", "ys88a",                            "YS88A 录波器" },
    { "tcp", "ys_89_net",                        "YS-89 网络录波器" },
    { "tcp", "ys_89a_net",                       "YS-89A 网络录波器" },

    /* --- UDP --- */
    { "udp", "sf_udp103_iec103",                 "四方网络103(UDP)" },
    { "udp", "nrcs9785_net",                     "南瑞 RCS-9785 网络对时" },
    { "udp", "netcsc2000l_net",                  "南自 CSC2000L 网络规约" },
};

constexpr int kRecipeCount = sizeof(g_recipes) / sizeof(g_recipes[0]);

} // namespace

VendorRecipeDialog::VendorRecipeDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle(tr("更多厂家规约解析"));

    carrier_combo_ = new QComboBox(this);
    carrier_combo_->addItem(tr("串口（serial_raw 承载）"), QStringLiteral("serial"));
    carrier_combo_->addItem(tr("TCP"), QStringLiteral("tcp"));
    carrier_combo_->addItem(tr("UDP"), QStringLiteral("udp"));

    vendor_combo_ = new QComboBox(this);
    vendor_combo_->setSizeAdjustPolicy(QComboBox::AdjustToContents);

    filter_edit_ = new QLineEdit(this);
    filter_edit_->setPlaceholderText(tr("显示过滤器，留空则使用协议名"));

    hint_label_ = new QLabel(this);
    hint_label_->setWordWrap(true);

    auto *form = new QFormLayout;
    form->addRow(tr("承载"), carrier_combo_);
    form->addRow(tr("厂家规约"), vendor_combo_);
    form->addRow(tr("过滤器"), filter_edit_);

    button_box_ = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);

    auto *layout = new QVBoxLayout(this);
    layout->addLayout(form);
    layout->addWidget(hint_label_);
    layout->addWidget(button_box_);

    connect(carrier_combo_, &QComboBox::currentIndexChanged, this, [this] { rebuild(); });
    connect(vendor_combo_, &QComboBox::currentIndexChanged, this, [this] {
        const QString proto = protocolName();
        if (!filter_edit_->text().trimmed().isEmpty())
            return;
        hint_label_->setText(proto.isEmpty()
                             ? QString()
                             : tr("将按 Decode As 试解为 %1，并过滤显示 %1 报文。").arg(proto));
    });
    connect(button_box_, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(button_box_, &QDialogButtonBox::rejected, this, &QDialog::reject);

    rebuild();
}

void VendorRecipeDialog::rebuild()
{
    const QString carrier = carrier_combo_->currentData().toString();
    vendor_combo_->clear();
    for (int i = 0; i < kRecipeCount; i++) {
        if (carrier != QLatin1String(g_recipes[i].carrier))
            continue;
        vendor_combo_->addItem(QString::fromUtf8(g_recipes[i].label),
                               QString::fromUtf8(g_recipes[i].protocol));
    }
    hint_label_->setText(vendor_combo_->count() == 0
                         ? tr("该承载下暂无厂家规约。")
                         : tr("将按 Decode As 试解为 %1。").arg(protocolName()));
}

QString VendorRecipeDialog::protocolName() const
{
    return vendor_combo_->currentData().toString();
}

QString VendorRecipeDialog::carrier() const
{
    return carrier_combo_->currentData().toString();
}
