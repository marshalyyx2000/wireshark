/** @file
 *
 * Smart-substation protocol classification tree (dock content).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "industrial_protocol_classify_panel.h"
#include <ui_industrial_protocol_classify_panel.h>

#include "mms_general_filter_widget.h"
#include "mms_report_filter_widget.h"
#include "wireshark_main_window.h"

#include "ui/qt/utils/qt_ui_utils.h"

#include <epan/addr_resolv.h>
#include <epan/address.h>
#include <epan/packet_info.h>
#include <epan/proto.h>

#include <algorithm>

#include <QAbstractSocket>
#include <QHostAddress>
#include <QTimer>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

namespace {

enum {
    kRoleKind = Qt::UserRole,       /* 0=root, 1=proto, 2=addr */
    kRoleProtoKey = Qt::UserRole + 1,
    kRoleAddr = Qt::UserRole + 2,
    kRoleAddrKind = Qt::UserRole + 3
};

enum ItemKind {
    kKindRoot = 0,
    kKindProto = 1,
    kKindAddr = 2
};

constexpr char kCombinedTapFilter[] =
    "mms || goose || r-goose || sv || mbtcp || yushun_modbus || "
    "iec60870_5_103 || iec60870_104 || iec60870_101";

bool ipLessThan(const QString &a, const QString &b)
{
    const QHostAddress ha(a);
    const QHostAddress hb(b);
    if (ha.protocol() == QAbstractSocket::IPv4Protocol &&
        hb.protocol() == QAbstractSocket::IPv4Protocol) {
        return ha.toIPv4Address() < hb.toIPv4Address();
    }
    if (ha.protocol() == QAbstractSocket::IPv4Protocol &&
        hb.protocol() == QAbstractSocket::IPv6Protocol) {
        return true;
    }
    if (ha.protocol() == QAbstractSocket::IPv6Protocol &&
        hb.protocol() == QAbstractSocket::IPv4Protocol) {
        return false;
    }
    return a < b;
}

} // namespace

const QVector<IndustrialProtocolClassifyPanel::ProtoDef> &
IndustrialProtocolClassifyPanel::protocolDefs()
{
    static const QVector<ProtoDef> defs = {
        {"mms", "MMS", "mms", nullptr, "mms"},
        {"goose", "GOOSE", "goose", "r-goose", "(goose || r-goose)"},
        {"sv", "SV", "sv", nullptr, "sv"},
        {"modbus", "MODBUS", "mbtcp", "yushun_modbus", "(mbtcp || yushun_modbus)"},
        {"103", "103", "iec60870_5_103", nullptr, "iec60870_5_103"},
        {"104", "104", "iec60870_104", nullptr, "iec60870_104"},
        {"101", "101", "iec60870_101", nullptr, "iec60870_101"},
    };
    return defs;
}

IndustrialProtocolClassifyPanel::IndustrialProtocolClassifyPanel(QWidget &parent,
                                                                 CaptureFile &capture_file) :
    WiresharkDialog(parent, capture_file),
    ui_(new Ui::IndustrialProtocolClassifyPanel),
    report_widget_(new MmsReportFilterWidget(this)),
    general_widget_(new MmsGeneralFilterWidget(this)),
    filter_timer_(new QTimer(this)),
    selected_is_root_(false),
    selected_is_proto_(false)
{
    ui_->setupUi(this);
    setWindowFlags(Qt::Widget);
    setWindowSubtitle(tr("协议分类"));

    ui_->verticalLayout->setStretch(ui_->verticalLayout->indexOf(ui_->protoTree), 1);

    report_widget_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Maximum);
    report_widget_->setPreviewVisible(false);
    ui_->reportFilterTabLayout->addWidget(report_widget_);
    report_widget_->setDialogHost(this, &cap_file_);

    general_widget_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Maximum);
    general_widget_->setPreviewVisible(false);
    ui_->generalFilterTabLayout->addWidget(general_widget_);

    filter_timer_->setSingleShot(true);
    filter_timer_->setInterval(100);
    connect(filter_timer_, &QTimer::timeout, this, &IndustrialProtocolClassifyPanel::onDebouncedFilterApply);

    connect(ui_->searchEdit, &QLineEdit::textChanged,
            this, &IndustrialProtocolClassifyPanel::onSearchTextChanged);
    connect(ui_->protoTree, &QTreeWidget::itemClicked,
            this, &IndustrialProtocolClassifyPanel::onTreeItemClicked);
    connect(ui_->protoTree, &QTreeWidget::currentItemChanged,
            this, &IndustrialProtocolClassifyPanel::onTreeCurrentItemChanged);
    connect(ui_->clearButton, &QPushButton::clicked,
            this, &IndustrialProtocolClassifyPanel::onClearClicked);
    connect(ui_->refreshButton, &QPushButton::clicked,
            this, &IndustrialProtocolClassifyPanel::refresh);
    connect(ui_->mmsFilterTabs, &QTabWidget::currentChanged,
            this, &IndustrialProtocolClassifyPanel::onMmsFilterTabChanged);
    connect(report_widget_, &MmsReportFilterWidget::filterChanged,
            this, &IndustrialProtocolClassifyPanel::updateHint);
    connect(report_widget_, &MmsReportFilterWidget::requestApplyFilter,
            this, &IndustrialProtocolClassifyPanel::onReportRequestApply);
    connect(general_widget_, &MmsGeneralFilterWidget::filterChanged,
            this, &IndustrialProtocolClassifyPanel::updateHint);
    connect(general_widget_, &MmsGeneralFilterWidget::requestApplyFilter,
            this, &IndustrialProtocolClassifyPanel::onGeneralRequestApply);

    connect(&cap_file_, &CaptureFile::captureEvent, this, [this](CaptureEvent e) {
        if (e.captureContext() != CaptureEvent::File) {
            return;
        }
        if (e.eventType() == CaptureEvent::Finished ||
            e.eventType() == CaptureEvent::Opened) {
            file_closed_ = false;
            refresh();
        }
    });

    rebuildTree();
    if (cap_file_.isValid()) {
        refresh();
    }
}

IndustrialProtocolClassifyPanel::~IndustrialProtocolClassifyPanel()
{
    delete ui_;
}

void IndustrialProtocolClassifyPanel::showProtocolTree()
{
    refresh();
}

void IndustrialProtocolClassifyPanel::refresh()
{
    if (fileClosed() || !cap_file_.isValid() || !cap_file_.capFile()) {
        addrs_by_proto_.clear();
        addr_kind_.clear();
        rebuildTree();
        ui_->hintLabel->setText(tr("未打开抓包。打开文件后将自动枚举协议与地址。"));
        return;
    }
    retap();
}

void IndustrialProtocolClassifyPanel::captureFileClosing()
{
    report_widget_->onCaptureFileClosing();
    removeTapListeners();
    WiresharkDialog::captureFileClosing();
}

void IndustrialProtocolClassifyPanel::captureFileClosed()
{
    addrs_by_proto_.clear();
    addr_kind_.clear();
    selected_proto_key_.clear();
    selected_addr_.clear();
    selected_is_root_ = false;
    selected_is_proto_ = false;
    last_applied_filter_.clear();
    rebuildTree();
    ui_->hintLabel->setText(tr("抓包文件已关闭。"));
    WiresharkDialog::captureFileClosed();
}

void IndustrialProtocolClassifyPanel::tapReset(void *tapdata)
{
    auto *panel = static_cast<IndustrialProtocolClassifyPanel *>(tapdata);
    panel->addrs_by_proto_.clear();
    panel->addr_kind_.clear();
}

void IndustrialProtocolClassifyPanel::rememberAddress(const QString &proto_key,
                                                      const address *addr,
                                                      AddrKind kind)
{
    if (!addr) {
        return;
    }
    if (kind == AddrKind::IPv4 || kind == AddrKind::IPv6) {
        if (addr->type != AT_IPv4 && addr->type != AT_IPv6) {
            return;
        }
    } else if (kind == AddrKind::Ethernet) {
        if (addr->type != AT_ETHER) {
            return;
        }
    }
    const QString text = address_to_qstring(addr);
    if (text.isEmpty()) {
        return;
    }
    addrs_by_proto_[proto_key].insert(text);
    addr_kind_.insert(text, kind);
}

void IndustrialProtocolClassifyPanel::collectAddressesForPacket(packet_info *pinfo,
                                                                const QString &proto_key)
{
    if (!pinfo) {
        return;
    }

    const bool src_ip = (pinfo->src.type == AT_IPv4 || pinfo->src.type == AT_IPv6);
    const bool dst_ip = (pinfo->dst.type == AT_IPv4 || pinfo->dst.type == AT_IPv6);

    if (src_ip) {
        rememberAddress(proto_key, &pinfo->src,
                        pinfo->src.type == AT_IPv6 ? AddrKind::IPv6 : AddrKind::IPv4);
    }
    if (dst_ip) {
        rememberAddress(proto_key, &pinfo->dst,
                        pinfo->dst.type == AT_IPv6 ? AddrKind::IPv6 : AddrKind::IPv4);
    }

    if (!src_ip && !dst_ip) {
        rememberAddress(proto_key, &pinfo->dl_src, AddrKind::Ethernet);
        rememberAddress(proto_key, &pinfo->dl_dst, AddrKind::Ethernet);
    }
}

tap_packet_status IndustrialProtocolClassifyPanel::tapPacket(void *tapdata,
                                                             packet_info *pinfo,
                                                             epan_dissect_t *,
                                                             const void *,
                                                             tap_flags_t)
{
    auto *panel = static_cast<IndustrialProtocolClassifyPanel *>(tapdata);
    if (!pinfo || !pinfo->layers) {
        return TAP_PACKET_DONT_REDRAW;
    }

    for (const ProtoDef &def : protocolDefs()) {
        bool hit = proto_is_frame_protocol(pinfo->layers, def.layer_name);
        if (!hit && def.alt_layer_name) {
            hit = proto_is_frame_protocol(pinfo->layers, def.alt_layer_name);
        }
        if (hit) {
            panel->collectAddressesForPacket(pinfo, QString::fromUtf8(def.key));
        }
    }

    return TAP_PACKET_DONT_REDRAW;
}

void IndustrialProtocolClassifyPanel::tapDraw(void *)
{
}

void IndustrialProtocolClassifyPanel::retap()
{
    beginRetapPackets();
    removeTapListeners();
    addrs_by_proto_.clear();
    addr_kind_.clear();

    if (!registerTapListener("frame", this, kCombinedTapFilter, 0,
                             tapReset, tapPacket, tapDraw)) {
        endRetapPackets();
        ui_->hintLabel->setText(tr("无法挂接工业协议报文。"));
        rebuildTree();
        return;
    }

    cap_file_.retapPackets();
    removeTapListeners();
    endRetapPackets();

    rebuildTree();
}

void IndustrialProtocolClassifyPanel::rebuildTree()
{
    const QString prev_proto = selected_proto_key_;
    const QString prev_addr = selected_addr_;
    const bool prev_root = selected_is_root_;
    const bool prev_proto_sel = selected_is_proto_;

    ui_->protoTree->blockSignals(true);
    ui_->protoTree->clear();

    auto *root = new QTreeWidgetItem(ui_->protoTree);
    root->setText(0, tr("网络报文"));
    root->setData(0, kRoleKind, kKindRoot);
    root->setExpanded(true);

    QTreeWidgetItem *restore_item = nullptr;

    for (const ProtoDef &def : protocolDefs()) {
        const QString key = QString::fromUtf8(def.key);
        auto *proto_item = new QTreeWidgetItem(root);
        const QSet<QString> &addrs = addrs_by_proto_.value(key);
        proto_item->setText(0, tr("%1（%2）")
                                   .arg(QString::fromUtf8(def.display_name))
                                   .arg(addrs.size()));
        proto_item->setData(0, kRoleKind, kKindProto);
        proto_item->setData(0, kRoleProtoKey, key);
        proto_item->setExpanded(true);

        if (prev_proto_sel && prev_proto == key && prev_addr.isEmpty()) {
            restore_item = proto_item;
        }

        QStringList sorted = addrs.values();
        std::sort(sorted.begin(), sorted.end(), ipLessThan);
        for (const QString &addr : sorted) {
            auto *addr_item = new QTreeWidgetItem(proto_item);
            const AddrKind kind = addr_kind_.value(addr, AddrKind::IPv4);
            QString label = addr;
            if (kind == AddrKind::Ethernet) {
                label = tr("%1（MAC）").arg(addr);
            }
            addr_item->setText(0, label);
            addr_item->setData(0, kRoleKind, kKindAddr);
            addr_item->setData(0, kRoleProtoKey, key);
            addr_item->setData(0, kRoleAddr, addr);
            addr_item->setData(0, kRoleAddrKind, static_cast<int>(kind));
            if (!prev_root && !prev_proto_sel && prev_proto == key && prev_addr == addr) {
                restore_item = addr_item;
            }
        }
    }

    if (prev_root) {
        restore_item = root;
    }

    ui_->protoTree->blockSignals(false);
    applySearchFilter(ui_->searchEdit->text());

    if (restore_item) {
        ui_->protoTree->setCurrentItem(restore_item);
    }

    updateReportPanelVisibility();
    updateHint();
}

void IndustrialProtocolClassifyPanel::applySearchFilter(const QString &text)
{
    const QString needle = text.trimmed();
    QTreeWidgetItem *root = ui_->protoTree->topLevelItem(0);
    if (!root) {
        return;
    }
    for (int i = 0; i < root->childCount(); i++) {
        QTreeWidgetItem *proto = root->child(i);
        bool proto_match = needle.isEmpty() ||
                           proto->text(0).contains(needle, Qt::CaseInsensitive);
        bool any_child = false;
        for (int c = 0; c < proto->childCount(); c++) {
            QTreeWidgetItem *child = proto->child(c);
            const bool child_match = needle.isEmpty() ||
                                     child->text(0).contains(needle, Qt::CaseInsensitive);
            child->setHidden(!child_match && !proto_match);
            if (child_match) {
                any_child = true;
            }
        }
        proto->setHidden(!proto_match && !any_child);
        if (any_child && !needle.isEmpty()) {
            proto->setExpanded(true);
        }
    }
}

void IndustrialProtocolClassifyPanel::updateReportPanelVisibility()
{
    ui_->reportContainer->setVisible(selected_proto_key_ == QLatin1String("mms"));
}

QString IndustrialProtocolClassifyPanel::buildTreeFilter() const
{
    if (selected_is_root_) {
        return QString::fromUtf8(kCombinedTapFilter);
    }

    QString proto_filter;
    for (const ProtoDef &def : protocolDefs()) {
        if (selected_proto_key_ == QLatin1String(def.key)) {
            proto_filter = QString::fromUtf8(def.filter_expr);
            break;
        }
    }
    if (proto_filter.isEmpty()) {
        return QString();
    }

    if (selected_is_proto_ || selected_addr_.isEmpty()) {
        return proto_filter;
    }

    QString addr_term;
    const AddrKind kind = addr_kind_.value(selected_addr_, AddrKind::IPv4);
    switch (kind) {
    case AddrKind::IPv6:
        addr_term = QStringLiteral("ipv6.addr==%1").arg(selected_addr_);
        break;
    case AddrKind::Ethernet:
        addr_term = QStringLiteral("eth.addr==%1").arg(selected_addr_);
        break;
    case AddrKind::IPv4:
    default:
        addr_term = QStringLiteral("ip.addr==%1").arg(selected_addr_);
        break;
    }
    return QStringLiteral("(%1) && (%2)").arg(addr_term, proto_filter);
}

bool IndustrialProtocolClassifyPanel::isGeneralFilterTabActive() const
{
    return ui_->mmsFilterTabs->currentIndex() ==
           ui_->mmsFilterTabs->indexOf(ui_->generalFilterTab);
}

QString IndustrialProtocolClassifyPanel::buildCombinedFilter() const
{
    QStringList parts;
    const QString tree_filter = buildTreeFilter();
    if (!tree_filter.isEmpty()) {
        parts << tree_filter;
    }
    if (selected_proto_key_ == QLatin1String("mms")) {
        if (isGeneralFilterTabActive()) {
            /* 通用过滤：仅选中 IP + 全部 MMS（及可选参引/InvokeID），不含报告范围 */
            if (general_widget_->hasGeneralCriteria()) {
                parts << general_widget_->buildFilter();
            }
        } else {
            /* 报告过滤：始终限定 unconfirmed RPT（mms.unconfirmedService == 0） */
            parts << report_widget_->buildFilter();
        }
    }
    return parts.join(QStringLiteral(" && "));
}

void IndustrialProtocolClassifyPanel::applyCombinedFilter(bool force)
{
    const QString filter = buildCombinedFilter();
    if (filter.isEmpty()) {
        last_applied_filter_.clear();
        updateHint();
        return;
    }
    if (!force && filter == last_applied_filter_) {
        updateHint();
        return;
    }
    last_applied_filter_ = filter;

    auto *mw = qobject_cast<WiresharkMainWindow *>(window());
    if (!mw) {
        mw = qobject_cast<WiresharkMainWindow *>(parentWidget());
    }
    /* Walk up from dock content to main window */
    QWidget *w = parentWidget();
    while (w && !mw) {
        mw = qobject_cast<WiresharkMainWindow *>(w);
        w = w->parentWidget();
    }
    if (mw) {
        mw->applyCaptureDisplayFilter(filter, force);
    }
    updateHint();
}

void IndustrialProtocolClassifyPanel::updateHint()
{
    int proto_with_addrs = 0;
    int total_addrs = 0;
    for (const ProtoDef &def : protocolDefs()) {
        const int n = addrs_by_proto_.value(QString::fromUtf8(def.key)).size();
        if (n > 0) {
            proto_with_addrs++;
        }
        total_addrs += n;
    }
    const QString filter = buildCombinedFilter();
    if (filter.isEmpty()) {
        ui_->hintLabel->setText(
            tr("已发现 %1 种协议、%2 个地址。单击节点即可过滤。")
                .arg(proto_with_addrs)
                .arg(total_addrs));
    } else {
        ui_->hintLabel->setText(filter);
    }
}

void IndustrialProtocolClassifyPanel::onSearchTextChanged(const QString &text)
{
    applySearchFilter(text);
}

void IndustrialProtocolClassifyPanel::onTreeItemClicked(QTreeWidgetItem *item, int)
{
    if (!item) {
        return;
    }
    onTreeCurrentItemChanged(item, nullptr);
    filter_timer_->start();
}

void IndustrialProtocolClassifyPanel::onTreeCurrentItemChanged(QTreeWidgetItem *current,
                                                               QTreeWidgetItem *)
{
    selected_proto_key_.clear();
    selected_addr_.clear();
    selected_is_root_ = false;
    selected_is_proto_ = false;

    if (!current) {
        updateReportPanelVisibility();
        updateHint();
        return;
    }

    const int kind = current->data(0, kRoleKind).toInt();
    switch (kind) {
    case kKindRoot:
        selected_is_root_ = true;
        break;
    case kKindProto:
        selected_is_proto_ = true;
        selected_proto_key_ = current->data(0, kRoleProtoKey).toString();
        break;
    case kKindAddr:
        selected_proto_key_ = current->data(0, kRoleProtoKey).toString();
        selected_addr_ = current->data(0, kRoleAddr).toString();
        break;
    default:
        break;
    }

    updateReportPanelVisibility();
    updateHint();
}

void IndustrialProtocolClassifyPanel::onClearClicked()
{
    selected_proto_key_.clear();
    selected_addr_.clear();
    selected_is_root_ = false;
    selected_is_proto_ = false;
    last_applied_filter_.clear();
    ui_->protoTree->clearSelection();
    report_widget_->clearCriteria();
    general_widget_->clearCriteria();
    report_widget_->resetAppliedFilterState();
    general_widget_->resetAppliedFilterState();

    auto *mw = qobject_cast<WiresharkMainWindow *>(window());
    QWidget *w = parentWidget();
    while (w && !mw) {
        mw = qobject_cast<WiresharkMainWindow *>(w);
        w = w->parentWidget();
    }
    if (mw) {
        mw->applyCaptureDisplayFilter(QString(), true);
    }
    updateReportPanelVisibility();
    updateHint();
}

void IndustrialProtocolClassifyPanel::onDebouncedFilterApply()
{
    applyCombinedFilter(false);
}

void IndustrialProtocolClassifyPanel::onReportRequestApply(const QString &, bool force)
{
    if (isGeneralFilterTabActive()) {
        return;
    }
    applyCombinedFilter(force);
}

void IndustrialProtocolClassifyPanel::onGeneralRequestApply(const QString &, bool force)
{
    if (!isGeneralFilterTabActive()) {
        return;
    }
    applyCombinedFilter(force);
}

void IndustrialProtocolClassifyPanel::onMmsFilterTabChanged(int)
{
    report_widget_->resetAppliedFilterState();
    general_widget_->resetAppliedFilterState();
    last_applied_filter_.clear();
    updateHint();
    /* 切换到通用过滤时强制重刷，去掉报告 Tab 留下的 unconfirmedService 范围 */
    applyCombinedFilter(true);
}
