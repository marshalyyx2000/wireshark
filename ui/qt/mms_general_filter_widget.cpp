/** @file
 *
 * MMS general display-filter builder widget (string match + invokeID, OR).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "mms_general_filter_widget.h"
#include <ui_mms_general_filter_widget.h>

#include "mms_filter_helpers.h"

#include <climits>

#include <QCheckBox>
#include <QIntValidator>
#include <QLineEdit>
#include <QTimer>

using MmsFilterHelpers::buildPayloadStringMatch;

MmsGeneralFilterWidget::MmsGeneralFilterWidget(QWidget *parent) :
    QWidget(parent),
    ui_(new Ui::MmsGeneralFilterWidget),
    filter_apply_timer_(new QTimer(this))
{
    ui_->setupUi(this);

    filter_apply_timer_->setSingleShot(true);
    /* Longer debounce: each apply rescans the capture; avoid per-keystroke cost. */
    filter_apply_timer_->setInterval(350);
    connect(filter_apply_timer_, &QTimer::timeout, this, &MmsGeneralFilterWidget::onDebouncedFilterApply);

    ui_->invokeIdEdit->setValidator(new QIntValidator(0, INT_MAX, ui_->invokeIdEdit));

    connect(ui_->exactRefMatchCheck, &QCheckBox::toggled, this, &MmsGeneralFilterWidget::onCriteriaChanged);
    connect(ui_->stringMatchEdit, &QLineEdit::textChanged, this, &MmsGeneralFilterWidget::onCriteriaChanged);
    connect(ui_->invokeIdEdit, &QLineEdit::textChanged, this, &MmsGeneralFilterWidget::onCriteriaChanged);
    connect(ui_->realtimeFilterCheck, &QCheckBox::toggled, this, [this](bool checked) {
        if (checked) {
            applyFilterNow(false);
        }
    });

    updatePreview();
}

MmsGeneralFilterWidget::~MmsGeneralFilterWidget()
{
    delete ui_;
}

bool MmsGeneralFilterWidget::isRealtimeEnabled() const
{
    return ui_->realtimeFilterCheck->isChecked();
}

void MmsGeneralFilterWidget::setPreviewVisible(bool visible)
{
    ui_->previewLabel->setVisible(visible);
}

void MmsGeneralFilterWidget::resetAppliedFilterState()
{
    last_emitted_filter_.clear();
}

void MmsGeneralFilterWidget::clearCriteria()
{
    ui_->exactRefMatchCheck->setChecked(false);
    ui_->stringMatchEdit->clear();
    ui_->invokeIdEdit->clear();
    last_emitted_filter_.clear();
    updatePreview();
}

bool MmsGeneralFilterWidget::hasGeneralCriteria() const
{
    if (!ui_->stringMatchEdit->text().trimmed().isEmpty()) {
        return true;
    }
    bool ok = false;
    ui_->invokeIdEdit->text().trimmed().toInt(&ok);
    return ok;
}

QString MmsGeneralFilterWidget::buildFilter() const
{
    if (!hasGeneralCriteria()) {
        return QString();
    }

    const bool exact_ref = ui_->exactRefMatchCheck->isChecked();
    const QString string_clause = buildPayloadStringMatch(ui_->stringMatchEdit->text(), exact_ref);

    QString invoke_clause;
    bool ok = false;
    const int invoke_id = ui_->invokeIdEdit->text().trimmed().toInt(&ok);
    if (ok) {
        invoke_clause = QStringLiteral("mms.invokeID == %1").arg(invoke_id);
    }

    QString match_clause;
    if (!string_clause.isEmpty() && !invoke_clause.isEmpty()) {
        match_clause = QStringLiteral("(%1 || %2)").arg(string_clause, invoke_clause);
    } else if (!string_clause.isEmpty()) {
        match_clause = string_clause;
    } else {
        match_clause = invoke_clause;
    }

    return QStringLiteral("mms && (%1)").arg(match_clause);
}

void MmsGeneralFilterWidget::updatePreview()
{
    ui_->previewLabel->setText(buildFilter());
    emit filterChanged();
}

void MmsGeneralFilterWidget::applyFilterNow(bool force)
{
    const QString filter = buildFilter();
    if (!force && filter == last_emitted_filter_) {
        return;
    }
    last_emitted_filter_ = filter;
    emit requestApplyFilter(filter, force);
}

void MmsGeneralFilterWidget::applyFilterIfRealtime(bool debounce)
{
    if (!ui_->realtimeFilterCheck->isChecked()) {
        return;
    }
    if (debounce) {
        filter_apply_timer_->start();
        return;
    }
    applyFilterNow();
}

void MmsGeneralFilterWidget::onDebouncedFilterApply()
{
    if (!ui_->realtimeFilterCheck->isChecked()) {
        return;
    }
    applyFilterNow(false);
}

void MmsGeneralFilterWidget::onCriteriaChanged()
{
    updatePreview();
    applyFilterIfRealtime(true);
}
