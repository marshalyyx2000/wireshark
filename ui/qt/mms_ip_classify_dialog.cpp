/** @file
 *
 * MMS IP classification by IEC 61850 server (TCP port 102).
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "mms_ip_classify_dialog.h"
#include <ui_mms_ip_classify_dialog.h>

#include "ui/qt/utils/qt_ui_utils.h"

#include <epan/address.h>
#include <epan/packet_info.h>

#include <algorithm>

#include <QAbstractSocket>
#include <QHostAddress>
#include <QTreeWidgetItem>

namespace {

enum {
    kRoleIp = Qt::UserRole,
    kRoleIsIpv6 = Qt::UserRole + 1,
    kRoleUnknownGroup = Qt::UserRole + 2
};

const uint16_t kMmsTcpPort = 102;

QString unknownServerKey()
{
    return QString();
}

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

MmsIpClassifyDialog::MmsIpClassifyDialog(QWidget &parent, CaptureFile &capture_file) :
    WiresharkDialog(parent, capture_file),
    ui_(new Ui::MmsIpClassifyDialog)
{
    ui_->setupUi(this);
    setWindowSubtitle(tr("按服务端分类 IP"));

    ui_->ipTree->setHeaderHidden(false);
    ui_->ipTree->setRootIsDecorated(true);

    connect(ui_->searchEdit, &QLineEdit::textChanged,
            this, &MmsIpClassifyDialog::onSearchTextChanged);
    connect(ui_->applyButton, &QPushButton::clicked,
            this, &MmsIpClassifyDialog::onApplyClicked);
    connect(ui_->clearButton, &QPushButton::clicked,
            this, &MmsIpClassifyDialog::onClearClicked);
    connect(ui_->ipTree, &QTreeWidget::itemChanged,
            this, &MmsIpClassifyDialog::onItemChanged);

    retap();
}

MmsIpClassifyDialog::~MmsIpClassifyDialog()
{
    delete ui_;
}

void MmsIpClassifyDialog::captureFileClosing()
{
    removeTapListeners();
    WiresharkDialog::captureFileClosing();
}

void MmsIpClassifyDialog::tapReset(void *tapdata)
{
    MmsIpClassifyDialog *dlg = static_cast<MmsIpClassifyDialog *>(tapdata);
    dlg->clients_by_server_.clear();
    dlg->unknown_ips_.clear();
    dlg->ipv6_by_ip_.clear();
}

tap_packet_status MmsIpClassifyDialog::tapPacket(void *tapdata, packet_info *pinfo,
                                                 epan_dissect_t *, const void *,
                                                 tap_flags_t)
{
    MmsIpClassifyDialog *dlg = static_cast<MmsIpClassifyDialog *>(tapdata);
    if (!pinfo) {
        return TAP_PACKET_DONT_REDRAW;
    }

    auto remember = [dlg](const address *addr) -> QString {
        if (!addr || (addr->type != AT_IPv4 && addr->type != AT_IPv6)) {
            return QString();
        }
        const QString ip = address_to_qstring(addr);
        if (ip.isEmpty()) {
            return QString();
        }
        dlg->ipv6_by_ip_.insert(ip, addr->type == AT_IPv6);
        return ip;
    };

    const QString src = remember(&pinfo->src);
    const QString dst = remember(&pinfo->dst);
    if (src.isEmpty() && dst.isEmpty()) {
        return TAP_PACKET_DONT_REDRAW;
    }

    const bool src_server = (pinfo->srcport == kMmsTcpPort);
    const bool dst_server = (pinfo->destport == kMmsTcpPort);

    if (src_server && !src.isEmpty()) {
        if (!dst.isEmpty()) {
            dlg->clients_by_server_[src].insert(dst);
        } else {
            dlg->clients_by_server_[src];
        }
    } else if (dst_server && !dst.isEmpty()) {
        if (!src.isEmpty()) {
            dlg->clients_by_server_[dst].insert(src);
        } else {
            dlg->clients_by_server_[dst];
        }
    } else {
        if (!src.isEmpty()) {
            dlg->unknown_ips_.insert(src);
        }
        if (!dst.isEmpty()) {
            dlg->unknown_ips_.insert(dst);
        }
    }

    return TAP_PACKET_DONT_REDRAW;
}

void MmsIpClassifyDialog::tapDraw(void *)
{
}

void MmsIpClassifyDialog::retap()
{
    if (fileClosed()) {
        ui_->hintLabel->setText(tr("抓包文件已关闭。"));
        return;
    }
    if (!cap_file_.isValid() || !cap_file_.capFile()) {
        ui_->hintLabel->setText(tr("未打开抓包。打开含 MMS 的文件后再试。"));
        return;
    }

    beginRetapPackets();
    removeTapListeners();
    clients_by_server_.clear();
    unknown_ips_.clear();
    ipv6_by_ip_.clear();

    if (!registerTapListener("frame", this, "mms", 0, tapReset, tapPacket, tapDraw)) {
        endRetapPackets();
        ui_->hintLabel->setText(tr("无法挂接 MMS 报文。"));
        return;
    }

    cap_file_.retapPackets();
    removeTapListeners();
    endRetapPackets();

    rebuildTree();
}

void MmsIpClassifyDialog::rebuildTree()
{
    ui_->ipTree->blockSignals(true);
    ui_->ipTree->clear();

    QStringList servers = clients_by_server_.keys();
    std::sort(servers.begin(), servers.end(), ipLessThan);

    for (const QString &server : servers) {
        QTreeWidgetItem *parent = new QTreeWidgetItem(ui_->ipTree);
        const QSet<QString> &clients = clients_by_server_.value(server);
        parent->setFlags(parent->flags() | Qt::ItemIsUserCheckable | Qt::ItemIsSelectable);
        parent->setCheckState(0, Qt::Unchecked);
        parent->setData(0, kRoleIp, server);
        parent->setData(0, kRoleIsIpv6, ipv6_by_ip_.value(server, false));
        parent->setData(0, kRoleUnknownGroup, false);
        parent->setText(0, tr("%1  （服务端，%2 个客户端）")
                               .arg(server)
                               .arg(clients.size()));

        QStringList client_list = clients.values();
        std::sort(client_list.begin(), client_list.end(), ipLessThan);
        for (const QString &client : client_list) {
            QTreeWidgetItem *child = new QTreeWidgetItem(parent);
            child->setFlags(child->flags() | Qt::ItemIsUserCheckable | Qt::ItemIsSelectable);
            child->setCheckState(0, Qt::Unchecked);
            child->setData(0, kRoleIp, client);
            child->setData(0, kRoleIsIpv6, ipv6_by_ip_.value(client, false));
            child->setData(0, kRoleUnknownGroup, false);
            child->setText(0, tr("%1  （客户端）").arg(client));
        }
        parent->setExpanded(true);
    }

    if (!unknown_ips_.isEmpty()) {
        QTreeWidgetItem *parent = new QTreeWidgetItem(ui_->ipTree);
        parent->setFlags(parent->flags() | Qt::ItemIsUserCheckable | Qt::ItemIsSelectable);
        parent->setCheckState(0, Qt::Unchecked);
        parent->setData(0, kRoleIp, unknownServerKey());
        parent->setData(0, kRoleUnknownGroup, true);
        parent->setText(0, tr("未知服务端（%1 个地址）").arg(unknown_ips_.size()));

        QStringList ips = unknown_ips_.values();
        std::sort(ips.begin(), ips.end(), ipLessThan);
        for (const QString &ip : ips) {
            QTreeWidgetItem *child = new QTreeWidgetItem(parent);
            child->setFlags(child->flags() | Qt::ItemIsUserCheckable | Qt::ItemIsSelectable);
            child->setCheckState(0, Qt::Unchecked);
            child->setData(0, kRoleIp, ip);
            child->setData(0, kRoleIsIpv6, ipv6_by_ip_.value(ip, false));
            child->setData(0, kRoleUnknownGroup, false);
            child->setText(0, ip);
        }
        parent->setExpanded(true);
    }

    ui_->ipTree->blockSignals(false);
    applySearchFilter(ui_->searchEdit->text());
    updateHint();
}

void MmsIpClassifyDialog::applySearchFilter(const QString &text)
{
    const QString needle = text.trimmed();
    const int n = ui_->ipTree->topLevelItemCount();
    for (int i = 0; i < n; i++) {
        QTreeWidgetItem *parent = ui_->ipTree->topLevelItem(i);
        bool parent_match = needle.isEmpty() ||
                            parent->text(0).contains(needle, Qt::CaseInsensitive);
        bool any_child = false;
        for (int c = 0; c < parent->childCount(); c++) {
            QTreeWidgetItem *child = parent->child(c);
            const bool child_match = needle.isEmpty() ||
                                     child->text(0).contains(needle, Qt::CaseInsensitive);
            child->setHidden(!child_match && !parent_match);
            if (child_match) {
                any_child = true;
            }
        }
        parent->setHidden(!parent_match && !any_child);
        if (any_child && !needle.isEmpty()) {
            parent->setExpanded(true);
        }
    }
}

QString MmsIpClassifyDialog::buildFilter() const
{
    QStringList v4;
    QStringList v6;
    auto addIp = [&](const QString &ip, bool is_v6) {
        if (ip.isEmpty()) {
            return;
        }
        QStringList &list = is_v6 ? v6 : v4;
        if (!list.contains(ip)) {
            list.append(ip);
        }
    };

    const int n = ui_->ipTree->topLevelItemCount();
    for (int i = 0; i < n; i++) {
        QTreeWidgetItem *parent = ui_->ipTree->topLevelItem(i);
        const bool unknown_group = parent->data(0, kRoleUnknownGroup).toBool();
        if (parent->checkState(0) == Qt::Checked && !unknown_group) {
            addIp(parent->data(0, kRoleIp).toString(),
                  parent->data(0, kRoleIsIpv6).toBool());
        }
        for (int c = 0; c < parent->childCount(); c++) {
            QTreeWidgetItem *child = parent->child(c);
            if (child->checkState(0) == Qt::Checked) {
                addIp(child->data(0, kRoleIp).toString(),
                      child->data(0, kRoleIsIpv6).toBool());
            }
        }
    }

    QStringList terms;
    for (const QString &ip : v4) {
        terms << QStringLiteral("ip.addr==%1").arg(ip);
    }
    for (const QString &ip : v6) {
        terms << QStringLiteral("ipv6.addr==%1").arg(ip);
    }
    if (terms.isEmpty()) {
        return QString();
    }
    return QStringLiteral("mms && (%1)").arg(terms.join(QStringLiteral(" || ")));
}

void MmsIpClassifyDialog::updateHint()
{
    const int servers = clients_by_server_.size();
    int clients = 0;
    for (const QSet<QString> &set : clients_by_server_) {
        clients += set.size();
    }
    const QString filter = buildFilter();
    if (filter.isEmpty()) {
        ui_->hintLabel->setText(
            tr("服务端 %1 个，未知地址 %2 个。勾选 IP 后点「应用过滤」。")
                .arg(servers)
                .arg(unknown_ips_.size()));
    } else {
        ui_->hintLabel->setText(filter);
    }
    Q_UNUSED(clients);
}

void MmsIpClassifyDialog::onSearchTextChanged(const QString &text)
{
    applySearchFilter(text);
}

void MmsIpClassifyDialog::onApplyClicked()
{
    const QString filter = buildFilter();
    if (filter.isEmpty()) {
        ui_->hintLabel->setText(tr("请先勾选至少一个 IP。"));
        return;
    }
    emit filterAction(filter, FilterAction::ActionApply, FilterAction::ActionTypePlain);
}

void MmsIpClassifyDialog::onClearClicked()
{
    ui_->ipTree->blockSignals(true);
    QTreeWidgetItemIterator it(ui_->ipTree);
    while (*it) {
        (*it)->setCheckState(0, Qt::Unchecked);
        ++it;
    }
    ui_->ipTree->blockSignals(false);
    updateHint();
}

void MmsIpClassifyDialog::onItemChanged(QTreeWidgetItem *, int)
{
    updateHint();
}
