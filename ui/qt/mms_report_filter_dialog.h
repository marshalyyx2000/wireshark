/** @file
 *
 * MMS / IEC 61850 report display-filter builder.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MMS_REPORT_FILTER_DIALOG_H
#define MMS_REPORT_FILTER_DIALOG_H

#include "config.h"

#include "filter_action.h"
#include "wireshark_dialog.h"

#include <QSet>
#include <QString>

class QComboBox;
class QTimer;

namespace Ui {
class MmsReportFilterDialog;
}

class MmsReportFilterDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit MmsReportFilterDialog(QWidget &parent, CaptureFile &capture_file);
    ~MmsReportFilterDialog() override;

signals:
    void filterAction(QString filter, FilterAction::Action action, FilterAction::ActionType type);

protected:
    void captureFileClosing() override;

private slots:
    void onApplyClicked();
    void onScopeCriteriaChanged();
    void onRptidCriteriaChanged();
    void onDatsetCriteriaChanged();
    void onRptidActivated(int index);
    void onDatsetActivated(int index);
    void onDebouncedScopeRetap();
    void onDebouncedRptidCriteriaChanged();
    void onDebouncedFilterApply();

private:
    static void tapReset(void *tapdata);
    static tap_packet_status tapPacket(void *tapdata, packet_info *pinfo,
                                       epan_dissect_t *edt, const void *data,
                                       tap_flags_t flags);
    static void tapDraw(void *tapdata);

    void retap();
    void fillCombos();
    QString buildScopeFilter(bool include_rptid) const;
    QString buildFilter() const;
    void updatePreview();
    void applyFilterNow();
    void applyFilterIfRealtime(bool debounce = true);
    void refreshDatsetComboForRptid();
    static QString quoteFilterString(const QString &value);
    static QString comboSelectedValue(QComboBox *combo);
    /** True when current text exactly matches a dropdown item (not free-typed). */
    static bool isComboExactSelection(QComboBox *combo);
    static void restoreComboValue(QComboBox *combo, const QString &value);

    Ui::MmsReportFilterDialog *ui_;
    QSet<QString> rptid_values_;
    QSet<QString> datset_values_;
    bool refreshing_combos_;
    QTimer *scope_retap_timer_;
    QTimer *id_change_timer_;
    QTimer *filter_apply_timer_;
};

#endif /* MMS_REPORT_FILTER_DIALOG_H */
