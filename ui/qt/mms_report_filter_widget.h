/** @file
 *
 * MMS / IEC 61850 report display-filter builder widget.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MMS_REPORT_FILTER_WIDGET_H
#define MMS_REPORT_FILTER_WIDGET_H

#include "config.h"

#include <epan/tap.h>

#include "capture_file.h"

struct mms_rpt_tap_data;

#include <QSet>
#include <QString>
#include <QWidget>

class QComboBox;
class QTimer;
class WiresharkDialog;

namespace Ui {
class MmsReportFilterWidget;
}

class MmsReportFilterWidget : public QWidget
{
    Q_OBJECT

public:
    explicit MmsReportFilterWidget(QWidget *parent = nullptr);
    ~MmsReportFilterWidget() override;

    void setDialogHost(WiresharkDialog *host, CaptureFile *capture_file);
    void onCaptureFileClosing();

    QString buildFilter() const;
    bool hasReportCriteria() const;
    bool isRealtimeEnabled() const;
    void setPreviewVisible(bool visible);
    void resetAppliedFilterState();

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

signals:
    void filterChanged();
    void requestApplyFilter(const QString &filter, bool force);

public slots:
    void applyFilterNow(bool force = false);

private slots:
    void onComboAboutToShow();
    void onDebouncedRptidCriteriaChanged();
    void onDebouncedFilterApply();
    void onScopeCriteriaChanged();
    void onRptidCriteriaChanged();
    void onDatsetCriteriaChanged();
    void onRptidActivated(int index);
    void onDatsetActivated(int index);

private:
    static void tapReset(void *tapdata);
    static tap_packet_status tapPacket(void *tapdata, packet_info *pinfo,
                                       epan_dissect_t *edt, const void *data,
                                       tap_flags_t flags);
    static void tapDraw(void *tapdata);

    void retap();
    void fillCombos();
    void updatePreview();
    void applyFilterIfRealtime(bool debounce = true);
    void refreshDatsetComboForRptid();
    void resetTapData();
    QString buildScopeFilter(bool include_rptid) const;
    QString buildTapScopeFilter(bool include_rptid) const;
    static QString quoteFilterString(const QString &value);
    static QString quoteFilterLower(const QString &value);
    static QString ciContainsClause(const QString &field, const QString &segment);
    static QString ciEqualsClause(const QString &field, const QString &text);
    static QStringList filterSegments(const QString &text);
    static void appendRefFilter(QStringList &parts, const QString &field, const QString &text,
                                bool exact_match);
    static void appendSegmentedContains(QStringList &parts, const QString &field, const QString &text);
    static QString comboSelectedValue(QComboBox *combo);
    static void restoreComboValue(QComboBox *combo, const QString &value);

    Ui::MmsReportFilterWidget *ui_;
    WiresharkDialog *host_;
    CaptureFile *capture_file_;
    QSet<QString> rptid_values_;
    QSet<QString> datset_values_;
    bool refreshing_combos_;
    QTimer *id_change_timer_;
    QTimer *filter_apply_timer_;
    QString last_emitted_filter_;
    bool combos_fresh_;
};

#endif /* MMS_REPORT_FILTER_WIDGET_H */
