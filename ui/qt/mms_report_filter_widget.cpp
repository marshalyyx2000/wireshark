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

#include "mms_report_filter_widget.h"
#include <ui_mms_report_filter_widget.h>

#include "capture_event.h"
#include "wireshark_dialog.h"
#include <epan/dissectors/packet-mms-tap.h>

#include <QCheckBox>
#include <QComboBox>
#include <QEvent>
#include <QLineEdit>
#include <QRegularExpression>
#include <QTimer>

MmsReportFilterWidget::MmsReportFilterWidget(QWidget *parent) :
    QWidget(parent),
    ui_(new Ui::MmsReportFilterWidget),
    host_(nullptr),
    capture_file_(nullptr),
    refreshing_combos_(false),
    id_change_timer_(new QTimer(this)),
    filter_apply_timer_(new QTimer(this)),
    combos_fresh_(false)
{
    ui_->setupUi(this);

    id_change_timer_->setSingleShot(true);
    id_change_timer_->setInterval(150);
    filter_apply_timer_->setSingleShot(true);
    filter_apply_timer_->setInterval(100);
    connect(id_change_timer_, &QTimer::timeout, this, &MmsReportFilterWidget::onDebouncedRptidCriteriaChanged);
    connect(filter_apply_timer_, &QTimer::timeout, this, &MmsReportFilterWidget::onDebouncedFilterApply);

    ui_->rptidCombo->addItem(tr("任意"), QString());
    ui_->datsetCombo->addItem(tr("任意"), QString());

    for (QCheckBox *box : {ui_->reasonDataChange, ui_->reasonIntegrity, ui_->reasonGi,
                           ui_->reasonQuality, ui_->reasonUpdate, ui_->reasonApp,
                           ui_->hasInclusion}) {
        connect(box, &QCheckBox::toggled, this, &MmsReportFilterWidget::onScopeCriteriaChanged);
    }
    connect(ui_->exactRefMatchCheck, &QCheckBox::toggled, this, [this]() {
        updatePreview();
        applyFilterIfRealtime(true);
    });
    connect(ui_->dataRefEdit, &QLineEdit::textChanged, this, &MmsReportFilterWidget::onScopeCriteriaChanged);
    connect(ui_->objRefEdit, &QLineEdit::textChanged, this, &MmsReportFilterWidget::onScopeCriteriaChanged);

    connect(ui_->rptidCombo, &QComboBox::editTextChanged,
            this, &MmsReportFilterWidget::onRptidCriteriaChanged);
    connect(ui_->datsetCombo, &QComboBox::editTextChanged,
            this, &MmsReportFilterWidget::onDatsetCriteriaChanged);
    connect(ui_->rptidCombo, QOverload<int>::of(&QComboBox::activated),
            this, &MmsReportFilterWidget::onRptidActivated);
    connect(ui_->datsetCombo, QOverload<int>::of(&QComboBox::activated),
            this, &MmsReportFilterWidget::onDatsetActivated);
    ui_->rptidCombo->installEventFilter(this);
    ui_->datsetCombo->installEventFilter(this);
    connect(ui_->realtimeFilterCheck, &QCheckBox::toggled, this, [this](bool checked) {
        if (checked) {
            applyFilterNow(false);
        }
    });
}

MmsReportFilterWidget::~MmsReportFilterWidget()
{
    delete ui_;
}

void MmsReportFilterWidget::setDialogHost(WiresharkDialog *host, CaptureFile *capture_file)
{
    host_ = host;
    capture_file_ = capture_file;
    if (!host_ || !capture_file_) {
        return;
    }

    connect(capture_file_, &CaptureFile::captureEvent, this, [this](CaptureEvent e) {
        if (!ui_->realtimeFilterCheck->isChecked()) {
            return;
        }
        if (e.captureContext() == CaptureEvent::Retap && e.eventType() == CaptureEvent::Finished) {
            applyFilterNow(true);
        }
    });

    retap();
    combos_fresh_ = true;
    updatePreview();
    applyFilterIfRealtime(false);
}

void MmsReportFilterWidget::onCaptureFileClosing()
{
    if (host_) {
        host_->removeTapListeners();
    }
}

bool MmsReportFilterWidget::isRealtimeEnabled() const
{
    return ui_->realtimeFilterCheck->isChecked();
}

void MmsReportFilterWidget::setPreviewVisible(bool visible)
{
    ui_->previewLabel->setVisible(visible);
}

void MmsReportFilterWidget::resetAppliedFilterState()
{
    last_emitted_filter_.clear();
}

bool MmsReportFilterWidget::eventFilter(QObject *watched, QEvent *event)
{
    if (event->type() == QEvent::MouseButtonPress &&
        (watched == ui_->rptidCombo || watched == ui_->datsetCombo)) {
        onComboAboutToShow();
    }
    return QWidget::eventFilter(watched, event);
}

void MmsReportFilterWidget::resetTapData()
{
    rptid_values_.clear();
    datset_values_.clear();
}

void MmsReportFilterWidget::tapReset(void *tapdata)
{
    static_cast<MmsReportFilterWidget *>(tapdata)->resetTapData();
}

tap_packet_status MmsReportFilterWidget::tapPacket(void *tapdata, packet_info *,
                                                   epan_dissect_t *, const void *data,
                                                   tap_flags_t)
{
    auto *widget = static_cast<MmsReportFilterWidget *>(tapdata);
    const auto *rpt = static_cast<const mms_rpt_tap_data *>(data);
    if (rpt) {
        if (rpt->rptid[0] != '\0') {
            widget->rptid_values_.insert(QString::fromUtf8(rpt->rptid));
        }
        if (rpt->datset[0] != '\0') {
            widget->datset_values_.insert(QString::fromUtf8(rpt->datset));
        }
    }
    return TAP_PACKET_DONT_REDRAW;
}

void MmsReportFilterWidget::tapDraw(void *)
{
}

QString MmsReportFilterWidget::comboSelectedValue(QComboBox *combo)
{
    QString text;
    if (combo->isEditable() && combo->lineEdit()) {
        text = combo->lineEdit()->text().trimmed();
    } else {
        text = combo->currentText().trimmed();
    }
    if (text.isEmpty() || text == QObject::tr("任意")) {
        return QString();
    }
    return text;
}

void MmsReportFilterWidget::restoreComboValue(QComboBox *combo, const QString &value)
{
    if (value.isEmpty()) {
        combo->setCurrentIndex(0);
        return;
    }
    const int idx = combo->findData(value);
    if (idx >= 0) {
        combo->setCurrentIndex(idx);
    } else {
        combo->setCurrentIndex(0);
        combo->setEditText(value);
    }
}

QString MmsReportFilterWidget::buildScopeFilter(bool include_rptid) const
{
    QStringList parts;
    parts << QStringLiteral("mms.unconfirmedService == 0");

    QStringList reasons;
    if (ui_->reasonDataChange->isChecked()) {
        reasons << QStringLiteral("mms.iec61850.reason.data_change");
    }
    if (ui_->reasonIntegrity->isChecked()) {
        reasons << QStringLiteral("mms.iec61850.reason.integrity");
    }
    if (ui_->reasonGi->isChecked()) {
        reasons << QStringLiteral("mms.iec61850.reason.general_interrogation");
    }
    if (ui_->reasonQuality->isChecked()) {
        reasons << QStringLiteral("mms.iec61850.reason.quality_change");
    }
    if (ui_->reasonUpdate->isChecked()) {
        reasons << QStringLiteral("mms.iec61850.reason.data_update");
    }
    if (ui_->reasonApp->isChecked()) {
        reasons << QStringLiteral("mms.iec61850.reason.application_trigger");
    }
    if (!reasons.isEmpty()) {
        if (reasons.size() == 1) {
            parts << reasons.first();
        } else {
            parts << QStringLiteral("(%1)").arg(reasons.join(QStringLiteral(" || ")));
        }
    }

    if (ui_->hasInclusion->isChecked()) {
        parts << QStringLiteral("mms.iec61850.inclusion_bitstring");
    }
    const bool exact_ref = ui_->exactRefMatchCheck->isChecked();
    appendRefFilter(parts, QStringLiteral("mms.iec61850.data_reference"),
                    ui_->dataRefEdit->text().trimmed(), exact_ref);
    appendRefFilter(parts, QStringLiteral("mms.iec61850.object_reference"),
                    ui_->objRefEdit->text().trimmed(), exact_ref);

    if (include_rptid) {
        const QString rptid = comboSelectedValue(ui_->rptidCombo);
        if (!rptid.isEmpty()) {
            parts << QStringLiteral("mms.iec61850.rptid == %1").arg(quoteFilterString(rptid));
        }
    }

    return parts.join(QStringLiteral(" && "));
}

QString MmsReportFilterWidget::buildTapScopeFilter(bool include_rptid) const
{
    QStringList parts;
    parts << QStringLiteral("mms.unconfirmedService == 0");

    QStringList reasons;
    if (ui_->reasonDataChange->isChecked()) {
        reasons << QStringLiteral("mms.iec61850.reason.data_change");
    }
    if (ui_->reasonIntegrity->isChecked()) {
        reasons << QStringLiteral("mms.iec61850.reason.integrity");
    }
    if (ui_->reasonGi->isChecked()) {
        reasons << QStringLiteral("mms.iec61850.reason.general_interrogation");
    }
    if (ui_->reasonQuality->isChecked()) {
        reasons << QStringLiteral("mms.iec61850.reason.quality_change");
    }
    if (ui_->reasonUpdate->isChecked()) {
        reasons << QStringLiteral("mms.iec61850.reason.data_update");
    }
    if (ui_->reasonApp->isChecked()) {
        reasons << QStringLiteral("mms.iec61850.reason.application_trigger");
    }
    if (!reasons.isEmpty()) {
        if (reasons.size() == 1) {
            parts << reasons.first();
        } else {
            parts << QStringLiteral("(%1)").arg(reasons.join(QStringLiteral(" || ")));
        }
    }

    if (ui_->hasInclusion->isChecked()) {
        parts << QStringLiteral("mms.iec61850.inclusion_bitstring");
    }

    if (include_rptid) {
        const QString rptid = comboSelectedValue(ui_->rptidCombo);
        if (!rptid.isEmpty()) {
            parts << QStringLiteral("mms.iec61850.rptid == %1").arg(quoteFilterString(rptid));
        }
    }

    return parts.join(QStringLiteral(" && "));
}

void MmsReportFilterWidget::retap()
{
    if (!host_ || !capture_file_ || host_->fileClosed() ||
        !capture_file_->isValid() || !capture_file_->capFile()) {
        return;
    }

    const QString prev_rptid = comboSelectedValue(ui_->rptidCombo);
    const QString prev_datset = comboSelectedValue(ui_->datsetCombo);

    host_->beginRetapPackets();
    host_->removeTapListeners();
    rptid_values_.clear();
    datset_values_.clear();

    const QByteArray scope = buildTapScopeFilter(false).toUtf8();
    if (!host_->registerTapListener("mms", this, scope.constData(),
                                    TL_LIMIT_TO_DISPLAY_FILTER,
                                    tapReset, tapPacket, tapDraw)) {
        host_->endRetapPackets();
        return;
    }
    capture_file_->retapPackets();
    host_->removeTapListeners();

    QSet<QString> rptids = rptid_values_;
    QSet<QString> datsets_all = datset_values_;

    rptid_values_.clear();
    datset_values_.clear();
    const QByteArray datset_scope = buildTapScopeFilter(true).toUtf8();
    if (!host_->registerTapListener("mms", this, datset_scope.constData(),
                                    TL_LIMIT_TO_DISPLAY_FILTER,
                                    tapReset, tapPacket, tapDraw)) {
        host_->endRetapPackets();
        rptid_values_ = rptids;
        datset_values_ = datsets_all;
        fillCombos();
        return;
    }
    capture_file_->retapPackets();
    host_->removeTapListeners();
    host_->endRetapPackets();

    const QSet<QString> datsets = datset_values_;
    rptid_values_ = rptids;
    datset_values_ = datsets;

    fillCombos();

    refreshing_combos_ = true;
    restoreComboValue(ui_->rptidCombo, prev_rptid);
    restoreComboValue(ui_->datsetCombo, prev_datset);
    refreshing_combos_ = false;
}

void MmsReportFilterWidget::fillCombos()
{
    auto fill = [](QComboBox *combo, const QSet<QString> &values) {
        combo->blockSignals(true);
        combo->clear();
        combo->addItem(QObject::tr("任意"), QString());
        QStringList list = values.values();
        list.sort(Qt::CaseInsensitive);
        for (const QString &v : list) {
            combo->addItem(v, v);
        }
        combo->setCurrentIndex(0);
        combo->blockSignals(false);
    };
    fill(ui_->rptidCombo, rptid_values_);
    fill(ui_->datsetCombo, datset_values_);
}

QString MmsReportFilterWidget::quoteFilterString(const QString &value)
{
    QString escaped = value;
    escaped.replace(QLatin1Char('\\'), QStringLiteral("\\\\"));
    escaped.replace(QLatin1Char('"'), QStringLiteral("\\\""));
    return QStringLiteral("\"%1\"").arg(escaped);
}

QString MmsReportFilterWidget::quoteFilterLower(const QString &value)
{
    return quoteFilterString(value.toLower());
}

QString MmsReportFilterWidget::ciContainsClause(const QString &field, const QString &segment)
{
    return QStringLiteral("lower(%1) contains %2").arg(field, quoteFilterLower(segment));
}

QString MmsReportFilterWidget::ciEqualsClause(const QString &field, const QString &text)
{
    return QStringLiteral("lower(%1) == %2").arg(field, quoteFilterLower(text));
}

QStringList MmsReportFilterWidget::filterSegments(const QString &text)
{
    return text.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
}

void MmsReportFilterWidget::appendRefFilter(QStringList &parts, const QString &field,
                                            const QString &text, bool exact_match)
{
    if (text.isEmpty()) {
        return;
    }
    static const QString data_ref_field = QStringLiteral("mms.iec61850.data_reference");
    static const QString datset_field = QStringLiteral("mms.iec61850.datset");

    if (exact_match) {
        if (field == data_ref_field) {
            parts << QStringLiteral("(%1 || %2)")
                             .arg(ciEqualsClause(data_ref_field, text),
                                  ciEqualsClause(datset_field, text));
        } else {
            parts << ciEqualsClause(field, text);
        }
        return;
    }
    appendSegmentedContains(parts, field, text);
}

void MmsReportFilterWidget::appendSegmentedContains(QStringList &parts, const QString &field,
                                                      const QString &text)
{
    static const QString data_ref_field = QStringLiteral("mms.iec61850.data_reference");
    static const QString datset_field = QStringLiteral("mms.iec61850.datset");

    for (const QString &segment : filterSegments(text)) {
        if (field == data_ref_field) {
            parts << QStringLiteral("(%1 || %2)")
                             .arg(ciContainsClause(data_ref_field, segment),
                                  ciContainsClause(datset_field, segment));
        } else {
            parts << ciContainsClause(field, segment);
        }
    }
}

QString MmsReportFilterWidget::buildFilter() const
{
    QStringList parts;
    parts << buildScopeFilter(true);

    const QString datset = comboSelectedValue(ui_->datsetCombo);
    if (!datset.isEmpty()) {
        appendSegmentedContains(parts, QStringLiteral("mms.iec61850.datset"), datset);
    }

    return parts.join(QStringLiteral(" && "));
}

void MmsReportFilterWidget::updatePreview()
{
    ui_->previewLabel->setText(buildFilter());
    emit filterChanged();
}

bool MmsReportFilterWidget::hasReportCriteria() const
{
    if (ui_->reasonDataChange->isChecked() || ui_->reasonIntegrity->isChecked() ||
        ui_->reasonGi->isChecked() || ui_->reasonQuality->isChecked() ||
        ui_->reasonUpdate->isChecked() || ui_->reasonApp->isChecked()) {
        return true;
    }
    if (ui_->hasInclusion->isChecked()) {
        return true;
    }
    if (!ui_->dataRefEdit->text().trimmed().isEmpty()) {
        return true;
    }
    if (!ui_->objRefEdit->text().trimmed().isEmpty()) {
        return true;
    }
    if (!comboSelectedValue(ui_->rptidCombo).isEmpty()) {
        return true;
    }
    if (!comboSelectedValue(ui_->datsetCombo).isEmpty()) {
        return true;
    }
    return false;
}

void MmsReportFilterWidget::applyFilterNow(bool force)
{
    const QString filter = buildFilter();
    if (!force && filter == last_emitted_filter_) {
        return;
    }
    last_emitted_filter_ = filter;
    emit requestApplyFilter(filter, force);
}

void MmsReportFilterWidget::applyFilterIfRealtime(bool debounce)
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

void MmsReportFilterWidget::onComboAboutToShow()
{
    if (refreshing_combos_ || combos_fresh_) {
        return;
    }
    retap();
    combos_fresh_ = true;
    updatePreview();
}

void MmsReportFilterWidget::onDebouncedFilterApply()
{
    if (!ui_->realtimeFilterCheck->isChecked()) {
        return;
    }
    applyFilterNow(false);
}

void MmsReportFilterWidget::onScopeCriteriaChanged()
{
    if (refreshing_combos_) {
        return;
    }
    updatePreview();
    applyFilterIfRealtime(true);
    if (!qobject_cast<const QLineEdit *>(sender())) {
        combos_fresh_ = false;
    }
}

void MmsReportFilterWidget::refreshDatsetComboForRptid()
{
    if (!host_ || !capture_file_) {
        return;
    }

    const QString prev_datset = comboSelectedValue(ui_->datsetCombo);
    const QSet<QString> keep_rptids = rptid_values_;
    host_->beginRetapPackets();
    host_->removeTapListeners();
    datset_values_.clear();
    const QByteArray datset_scope = buildTapScopeFilter(true).toUtf8();
    if (host_->registerTapListener("mms", this, datset_scope.constData(),
                                   TL_LIMIT_TO_DISPLAY_FILTER,
                                   tapReset, tapPacket, tapDraw)) {
        capture_file_->retapPackets();
        host_->removeTapListeners();
    }
    rptid_values_ = keep_rptids;
    host_->endRetapPackets();

    refreshing_combos_ = true;
    ui_->datsetCombo->blockSignals(true);
    ui_->datsetCombo->clear();
    ui_->datsetCombo->addItem(tr("任意"), QString());
    QStringList list = datset_values_.values();
    list.sort(Qt::CaseInsensitive);
    for (const QString &v : list) {
        ui_->datsetCombo->addItem(v, v);
    }
    const int idx = ui_->datsetCombo->findData(prev_datset);
    if (idx >= 0) {
        ui_->datsetCombo->setCurrentIndex(idx);
    } else if (!prev_datset.isEmpty()) {
        ui_->datsetCombo->setCurrentIndex(0);
        ui_->datsetCombo->setEditText(prev_datset);
    } else {
        ui_->datsetCombo->setCurrentIndex(0);
    }
    ui_->datsetCombo->blockSignals(false);
    refreshing_combos_ = false;
}

void MmsReportFilterWidget::onRptidCriteriaChanged()
{
    if (refreshing_combos_) {
        return;
    }
    updatePreview();
    applyFilterIfRealtime(true);
    id_change_timer_->start();
}

void MmsReportFilterWidget::onDatsetCriteriaChanged()
{
    if (refreshing_combos_) {
        return;
    }
    updatePreview();
    applyFilterIfRealtime(true);
}

void MmsReportFilterWidget::onRptidActivated(int index)
{
    if (refreshing_combos_ || index < 0) {
        return;
    }
    id_change_timer_->stop();
    filter_apply_timer_->stop();
    updatePreview();
    applyFilterIfRealtime(true);
    id_change_timer_->start();
}

void MmsReportFilterWidget::onDatsetActivated(int index)
{
    if (refreshing_combos_ || index < 0) {
        return;
    }
    filter_apply_timer_->stop();
    updatePreview();
    applyFilterIfRealtime(true);
}

void MmsReportFilterWidget::onDebouncedRptidCriteriaChanged()
{
    if (refreshing_combos_) {
        return;
    }
    refreshDatsetComboForRptid();
    updatePreview();
    applyFilterIfRealtime(true);
}
