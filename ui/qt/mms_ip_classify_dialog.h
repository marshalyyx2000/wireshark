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

#ifndef MMS_IP_CLASSIFY_DIALOG_H
#define MMS_IP_CLASSIFY_DIALOG_H

#include "config.h"

#include "filter_action.h"
#include "wireshark_dialog.h"

#include <QHash>
#include <QSet>
#include <QString>

class MmsReportFilterWidget;
class QTimer;
class QTreeWidgetItem;

namespace Ui {
class MmsIpClassifyDialog;
}

class MmsIpClassifyDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit MmsIpClassifyDialog(QWidget &parent, CaptureFile &capture_file);
    ~MmsIpClassifyDialog() override;

signals:
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);

protected:
    void captureFileClosing() override;

private slots:
    void onSearchTextChanged(const QString &text);
    void onApplyClicked();
    void onClearClicked();
    void onItemChanged(QTreeWidgetItem *item, int column);
    void onDebouncedIpFilterApply();

private:
    static void tapReset(void *tapdata);
    static tap_packet_status tapPacket(void *tapdata, packet_info *pinfo,
                                       epan_dissect_t *edt, const void *data,
                                       tap_flags_t flags);
    static void tapDraw(void *tapdata);

    void retap();
    void rebuildTree();
    void applySearchFilter(const QString &text);
    QString buildIpFilter() const;
    QString buildCombinedFilter() const;
    void applyCombinedFilter(bool force = false);
    void updateHint();

    Ui::MmsIpClassifyDialog *ui_;
    MmsReportFilterWidget *report_widget_;
    QHash<QString, QSet<QString>> clients_by_server_;
    QSet<QString> unknown_ips_;
    QHash<QString, bool> ipv6_by_ip_;
    QTimer *ip_filter_timer_;
    QString last_applied_filter_;
};

#endif /* MMS_IP_CLASSIFY_DIALOG_H */
