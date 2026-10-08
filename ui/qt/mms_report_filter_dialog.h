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

class MmsReportFilterWidget;

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

private:
    Ui::MmsReportFilterDialog *ui_;
    MmsReportFilterWidget *filter_widget_;
};

#endif /* MMS_REPORT_FILTER_DIALOG_H */
