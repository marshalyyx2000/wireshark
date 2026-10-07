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

#include <epan/dissectors/packet-mms-tap.h>

#include <QCheckBox>
#include <QLineEdit>
#include <QTimer>

MmsReportFilterDialog::MmsReportFilterDialog(QWidget &parent, CaptureFile &capture_file) :
    WiresharkDialog(parent, capture_file),
    ui_(new Ui::MmsReportFilterDialog),
    refreshing_combos_(false),
    scope_retap_timer_(new QTimer(this)),
    id_change_timer_(new QTimer(this)),
    filter_apply_timer_(new QTimer(this))
{
    ui_->setupUi(this);
    setWindowSubtitle(tr("报告过滤"));

    scope_retap_timer_->setSingleShot(true);
    scope_retap_timer_->setInterval(300);
    id_change_timer_->setSingleShot(true);
    id_change_timer_->setInterval(300);
    filter_apply_timer_->setSingleShot(true);
    filter_apply_timer_->setInterval(250);
    connect(scope_retap_timer_, &QTimer::timeout, this, &MmsReportFilterDialog::onDebouncedScopeRetap);
    connect(id_change_timer_, &QTimer::timeout, this, &MmsReportFilterDialog::onDebouncedRptidCriteriaChanged);
    connect(filter_apply_timer_, &QTimer::timeout, this, &MmsReportFilterDialog::onDebouncedFilterApply);

    ui_->bufovflCombo->addItem(tr("任意"), QString());
    ui_->bufovflCombo->addItem(tr("是"), QStringLiteral("true"));
    ui_->bufovflCombo->addItem(tr("否"), QStringLiteral("false"));

    ui_->rptidCombo->addItem(tr("任意"), QString());
    ui_->datsetCombo->addItem(tr("任意"), QString());

    for (QCheckBox *box : {ui_->reasonDataChange, ui_->reasonIntegrity, ui_->reasonGi,
                           ui_->reasonQuality, ui_->reasonUpdate, ui_->reasonApp,
                           ui_->hasInclusion}) {
        connect(box, &QCheckBox::toggled, this, &MmsReportFilterDialog::onScopeCriteriaChanged);
    }
    connect(ui_->exactRefMatchCheck, &QCheckBox::toggled, this, [this]() {
        updatePreview();
        applyFilterIfRealtime(false);
    });
    connect(ui_->bufovflCombo, &QComboBox::currentIndexChanged, this,
            [this](int) { onScopeCriteriaChanged(); });
    connect(ui_->confrevEdit, &QLineEdit::textChanged, this, &MmsReportFilterDialog::onScopeCriteriaChanged);
    connect(ui_->dataRefEdit, &QLineEdit::textChanged, this, &MmsReportFilterDialog::onScopeCriteriaChanged);
    connect(ui_->objRefEdit, &QLineEdit::textChanged, this, &MmsReportFilterDialog::onScopeCriteriaChanged);

    connect(ui_->rptidCombo->lineEdit(), &QLineEdit::textChanged,
            this, &MmsReportFilterDialog::onRptidCriteriaChanged);
    connect(ui_->datsetCombo->lineEdit(), &QLineEdit::textChanged,
            this, &MmsReportFilterDialog::onDatsetCriteriaChanged);
    connect(ui_->rptidCombo, QOverload<int>::of(&QComboBox::activated),
            this, &MmsReportFilterDialog::onRptidActivated);
    connect(ui_->datsetCombo, QOverload<int>::of(&QComboBox::activated),
            this, &MmsReportFilterDialog::onDatsetActivated);
    connect(ui_->applyButton, &QPushButton::clicked, this, &MmsReportFilterDialog::onApplyClicked);
    connect(ui_->realtimeFilterCheck, &QCheckBox::toggled, this, [this](bool checked) {
        if (checked) {
            applyFilterNow();
        }
    });

    retap();
    updatePreview();
    applyFilterIfRealtime(false);
}

MmsReportFilterDialog::~MmsReportFilterDialog()
{
    delete ui_;
}

void MmsReportFilterDialog::captureFileClosing()
{
    removeTapListeners();
    WiresharkDialog::captureFileClosing();
}

void MmsReportFilterDialog::tapReset(void *tapdata)
{
    MmsReportFilterDialog *dlg = static_cast<MmsReportFilterDialog *>(tapdata);
    dlg->rptid_values_.clear();
    dlg->datset_values_.clear();
}

tap_packet_status MmsReportFilterDialog::tapPacket(void *tapdata, packet_info *,
                                                   epan_dissect_t *, const void *data,
                                                   tap_flags_t)
{
    MmsReportFilterDialog *dlg = static_cast<MmsReportFilterDialog *>(tapdata);
    const mms_rpt_tap_data *rpt = static_cast<const mms_rpt_tap_data *>(data);
    if (!rpt) {
        return TAP_PACKET_DONT_REDRAW;
    }
    if (rpt->rptid[0] != '\0') {
        dlg->rptid_values_.insert(QString::fromUtf8(rpt->rptid));
    }
    if (rpt->datset[0] != '\0') {
        dlg->datset_values_.insert(QString::fromUtf8(rpt->datset));
    }
    return TAP_PACKET_DONT_REDRAW;
}

void MmsReportFilterDialog::tapDraw(void *)
{
}

QString MmsReportFilterDialog::comboSelectedValue(QComboBox *combo)
{
    /* Always use the visible edit text — not itemData — so typed
     * substrings like "dsAin" are not replaced by a still-selected full path. */
    const QString text = combo->currentText().trimmed();
    if (text.isEmpty() || text == QObject::tr("任意")) {
        return QString();
    }
    return text;
}

bool MmsReportFilterDialog::isComboExactSelection(QComboBox *combo)
{
    const QString text = combo->currentText().trimmed();
    if (text.isEmpty() || text == QObject::tr("任意")) {
        return false;
    }
    /* Exact dropdown pick only when the typed/shown text equals an item value. */
    return combo->findData(text) > 0;
}

void MmsReportFilterDialog::restoreComboValue(QComboBox *combo, const QString &value)
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

QString MmsReportFilterDialog::buildScopeFilter(bool include_rptid) const
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

    const QString bufovfl = ui_->bufovflCombo->currentData().toString();
    if (!bufovfl.isEmpty()) {
        parts << QStringLiteral("mms.iec61850.bufovfl == %1").arg(bufovfl);
    }
    const QString confrev = ui_->confrevEdit->text().trimmed();
    if (!confrev.isEmpty()) {
        parts << QStringLiteral("mms.iec61850.confrev == %1").arg(confrev);
    }
    if (ui_->hasInclusion->isChecked()) {
        parts << QStringLiteral("mms.iec61850.inclusion_bitstring");
    }
    const char *ref_op = ui_->exactRefMatchCheck->isChecked() ? "==" : "contains";
    const QString data_ref = ui_->dataRefEdit->text().trimmed();
    if (!data_ref.isEmpty()) {
        parts << QStringLiteral("mms.iec61850.data_reference %1 %2")
                     .arg(QLatin1String(ref_op), quoteFilterString(data_ref));
    }
    const QString obj_ref = ui_->objRefEdit->text().trimmed();
    if (!obj_ref.isEmpty()) {
        parts << QStringLiteral("mms.iec61850.object_reference %1 %2")
                     .arg(QLatin1String(ref_op), quoteFilterString(obj_ref));
    }

    if (include_rptid) {
        const QString rptid = comboSelectedValue(ui_->rptidCombo);
        if (!rptid.isEmpty()) {
            parts << QStringLiteral("mms.iec61850.rptid == %1").arg(quoteFilterString(rptid));
        }
    }

    return parts.join(QStringLiteral(" && "));
}

void MmsReportFilterDialog::retap()
{
    if (fileClosed() || !cap_file_.isValid() || !cap_file_.capFile()) {
        return;
    }

    const QString prev_rptid = comboSelectedValue(ui_->rptidCombo);
    const QString prev_datset = comboSelectedValue(ui_->datsetCombo);

    beginRetapPackets();
    removeTapListeners();
    rptid_values_.clear();
    datset_values_.clear();

    /* Collect RptID from packets matching scope (no RptID/DatSet). */
    const QByteArray scope = buildScopeFilter(false).toUtf8();
    if (!registerTapListener("mms", this, scope.constData(),
                             TL_LIMIT_TO_DISPLAY_FILTER,
                             tapReset, tapPacket, tapDraw)) {
        endRetapPackets();
        return;
    }
    cap_file_.retapPackets();
    removeTapListeners();

    QSet<QString> rptids = rptid_values_;
    QSet<QString> datsets_all = datset_values_;

    /* DatSet list: same scope, optionally narrowed by selected RptID. */
    rptid_values_.clear();
    datset_values_.clear();
    const QByteArray datset_scope = buildScopeFilter(true).toUtf8();
    if (!registerTapListener("mms", this, datset_scope.constData(),
                             TL_LIMIT_TO_DISPLAY_FILTER,
                             tapReset, tapPacket, tapDraw)) {
        endRetapPackets();
        rptid_values_ = rptids;
        datset_values_ = datsets_all;
        fillCombos();
        return;
    }
    cap_file_.retapPackets();
    removeTapListeners();
    endRetapPackets();

    const QSet<QString> datsets = datset_values_;
    rptid_values_ = rptids;
    datset_values_ = datsets;

    fillCombos();

    /* Restore previous choices: list hit → select; free text → keep typed. */
    refreshing_combos_ = true;
    restoreComboValue(ui_->rptidCombo, prev_rptid);
    restoreComboValue(ui_->datsetCombo, prev_datset);
    refreshing_combos_ = false;
}

void MmsReportFilterDialog::fillCombos()
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

QString MmsReportFilterDialog::quoteFilterString(const QString &value)
{
    QString escaped = value;
    escaped.replace(QLatin1Char('\\'), QStringLiteral("\\\\"));
    escaped.replace(QLatin1Char('"'), QStringLiteral("\\\""));
    return QStringLiteral("\"%1\"").arg(escaped);
}

QString MmsReportFilterDialog::buildFilter() const
{
    QStringList parts;
    parts << buildScopeFilter(true);

    const QString datset = comboSelectedValue(ui_->datsetCombo);
    if (!datset.isEmpty()) {
        /* DatSet paths are often partial (e.g. PCL1006); always use contains. */
        parts << QStringLiteral("mms.iec61850.datset contains %1")
                     .arg(quoteFilterString(datset));
    }

    return parts.join(QStringLiteral(" && "));
}

void MmsReportFilterDialog::updatePreview()
{
    ui_->previewLabel->setText(buildFilter());
}

void MmsReportFilterDialog::applyFilterNow()
{
    emit filterAction(buildFilter(), FilterAction::ActionApply, FilterAction::ActionTypePlain);
}

void MmsReportFilterDialog::applyFilterIfRealtime(bool debounce)
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

void MmsReportFilterDialog::onDebouncedScopeRetap()
{
    if (refreshing_combos_) {
        return;
    }
    retap();
    updatePreview();
    applyFilterIfRealtime(false);
}

void MmsReportFilterDialog::onDebouncedFilterApply()
{
    if (!ui_->realtimeFilterCheck->isChecked()) {
        return;
    }
    applyFilterNow();
}

void MmsReportFilterDialog::onScopeCriteriaChanged()
{
    if (refreshing_combos_) {
        return;
    }
    if (qobject_cast<const QLineEdit *>(sender())) {
        updatePreview();
        scope_retap_timer_->start();
        applyFilterIfRealtime();
        return;
    }
    retap();
    updatePreview();
    applyFilterIfRealtime(false);
}

void MmsReportFilterDialog::refreshDatsetComboForRptid()
{
    const QString prev_datset = comboSelectedValue(ui_->datsetCombo);
    const QSet<QString> keep_rptids = rptid_values_;
    beginRetapPackets();
    removeTapListeners();
    datset_values_.clear();
    const QByteArray datset_scope = buildScopeFilter(true).toUtf8();
    if (registerTapListener("mms", this, datset_scope.constData(),
                            TL_LIMIT_TO_DISPLAY_FILTER,
                            tapReset, tapPacket, tapDraw)) {
        cap_file_.retapPackets();
        removeTapListeners();
    }
    rptid_values_ = keep_rptids;
    endRetapPackets();

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

void MmsReportFilterDialog::onRptidCriteriaChanged()
{
    if (refreshing_combos_) {
        return;
    }
    updatePreview();
    id_change_timer_->start();
    applyFilterIfRealtime();
}

void MmsReportFilterDialog::onDatsetCriteriaChanged()
{
    if (refreshing_combos_) {
        return;
    }
    updatePreview();
    applyFilterIfRealtime();
}

void MmsReportFilterDialog::onRptidActivated(int index)
{
    if (refreshing_combos_ || index < 0) {
        return;
    }
    id_change_timer_->stop();
    filter_apply_timer_->stop();
    refreshDatsetComboForRptid();
    updatePreview();
    applyFilterIfRealtime(false);
}

void MmsReportFilterDialog::onDatsetActivated(int index)
{
    if (refreshing_combos_ || index < 0) {
        return;
    }
    filter_apply_timer_->stop();
    updatePreview();
    applyFilterIfRealtime(false);
}

void MmsReportFilterDialog::onDebouncedRptidCriteriaChanged()
{
    if (refreshing_combos_) {
        return;
    }
    refreshDatsetComboForRptid();
    updatePreview();
    applyFilterIfRealtime(false);
}

void MmsReportFilterDialog::onApplyClicked()
{
    applyFilterNow();
}
