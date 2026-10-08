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

#include "mms_report_filter_dialog.h"
#include <ui_mms_report_filter_dialog.h>

#include "mms_report_filter_widget.h"
#include "wireshark_main_window.h"

#include <QVBoxLayout>

MmsReportFilterDialog::MmsReportFilterDialog(QWidget &parent, CaptureFile &capture_file) :
    WiresharkDialog(parent, capture_file),
    ui_(new Ui::MmsReportFilterDialog),
    filter_widget_(new MmsReportFilterWidget(this))
{
    ui_->setupUi(this);
    setWindowSubtitle(tr("报告过滤"));

    auto *layout = new QVBoxLayout(ui_->filterContainer);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(filter_widget_);

    filter_widget_->setDialogHost(this, &cap_file_);

    connect(filter_widget_, &MmsReportFilterWidget::requestApplyFilter, this,
            [this](const QString &filter, bool force) {
        auto *mw = qobject_cast<WiresharkMainWindow *>(parentWidget());
        if (mw) {
            mw->applyCaptureDisplayFilter(filter, force);
            return;
        }
        emit filterAction(filter, FilterAction::ActionApply, FilterAction::ActionTypePlain);
    });
    connect(ui_->applyButton, &QPushButton::clicked, this, &MmsReportFilterDialog::onApplyClicked);
}

MmsReportFilterDialog::~MmsReportFilterDialog()
{
    delete ui_;
}

void MmsReportFilterDialog::captureFileClosing()
{
    filter_widget_->onCaptureFileClosing();
    WiresharkDialog::captureFileClosing();
}

void MmsReportFilterDialog::onApplyClicked()
{
    filter_widget_->applyFilterNow(true);
}
