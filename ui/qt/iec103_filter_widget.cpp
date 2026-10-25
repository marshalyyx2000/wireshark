/** @file
 *
 * IEC 103 display-filter builder (Shandong / NARI network variants).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "iec103_filter_widget.h"
#include <ui_iec103_filter_widget.h>

#include <climits>

#include <QCheckBox>
#include <QComboBox>
#include <QIntValidator>
#include <QLineEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QSet>
#include <QTimer>

Iec103FilterWidget::Iec103FilterWidget(QWidget *parent) :
    QWidget(parent),
    ui_(new Ui::Iec103FilterWidget),
    filter_apply_timer_(new QTimer(this))
{
    ui_->setupUi(this);

    filter_apply_timer_->setSingleShot(true);
    filter_apply_timer_->setInterval(250);
    connect(filter_apply_timer_, &QTimer::timeout,
            this, &Iec103FilterWidget::onDebouncedFilterApply);

    /* ASDU accepts multiple values (space/comma separated); no IntValidator */
    ui_->groupEdit->setValidator(new QIntValidator(0, 255, ui_->groupEdit));

    connect(ui_->variantCombo, &QComboBox::currentIndexChanged,
            this, &Iec103FilterWidget::onCriteriaChanged);
    connect(ui_->asduEdit, &QLineEdit::textChanged,
            this, &Iec103FilterWidget::onCriteriaChanged);
    connect(ui_->groupEdit, &QLineEdit::textChanged,
            this, &Iec103FilterWidget::onCriteriaChanged);
    connect(ui_->realtimeFilterCheck, &QCheckBox::toggled, this, [this](bool checked) {
        if (checked) {
            applyFilterNow(false);
        }
    });
    connect(ui_->waveDataButton, &QPushButton::clicked,
            this, &Iec103FilterWidget::onWaveDataClicked);
    connect(ui_->waveListButton, &QPushButton::clicked,
            this, &Iec103FilterWidget::onWaveListClicked);

    updateGroupVisibility();
    updatePreview();
}

Iec103FilterWidget::~Iec103FilterWidget()
{
    delete ui_;
}

bool Iec103FilterWidget::isRealtimeEnabled() const
{
    return ui_->realtimeFilterCheck->isChecked();
}

void Iec103FilterWidget::resetAppliedFilterState()
{
    last_emitted_filter_.clear();
}

void Iec103FilterWidget::clearCriteria()
{
    ui_->asduEdit->clear();
    ui_->groupEdit->clear();
    last_emitted_filter_.clear();
    updateGroupVisibility();
    updatePreview();
}

QList<int> Iec103FilterWidget::parseAsduValues() const
{
    QList<int> values;
    QSet<int> seen;
    const QString raw = ui_->asduEdit->text().trimmed();
    if (raw.isEmpty()) {
        return values;
    }

    const QStringList tokens = raw.split(QRegularExpression(QStringLiteral("[\\s,;]+")),
                                         Qt::SkipEmptyParts);
    for (const QString &tok : tokens) {
        bool ok = false;
        const int v = tok.toInt(&ok);
        if (!ok || v < 0 || v > 255 || seen.contains(v)) {
            continue;
        }
        seen.insert(v);
        values.append(v);
    }
    return values;
}

bool Iec103FilterWidget::asduIncludesGeneric() const
{
    for (int asdu : parseAsduValues()) {
        if (asdu == 10 || asdu == 21) {
            return true;
        }
    }
    return false;
}

bool Iec103FilterWidget::isNariNetVariant() const
{
    return ui_->variantCombo->currentIndex() == 1;
}

QString Iec103FilterWidget::filterPrefix() const
{
    return isNariNetVariant() ? QStringLiteral("nari_net_iec103")
                              : QStringLiteral("shandong_iec103");
}

bool Iec103FilterWidget::hasCriteria() const
{
    if (!parseAsduValues().isEmpty()) {
        return true;
    }
    bool ok = false;
    ui_->groupEdit->text().trimmed().toInt(&ok);
    return ok;
}

QString Iec103FilterWidget::buildFilter() const
{
    QStringList parts;
    const QList<int> asdus = parseAsduValues();
    const QString prefix = filterPrefix();

    if (asdus.size() == 1) {
        parts << QStringLiteral("%1.typeid == %2").arg(prefix).arg(asdus.first());
    } else if (asdus.size() > 1) {
        QStringList nums;
        for (int asdu : asdus) {
            nums << QString::number(asdu);
        }
        parts << QStringLiteral("%1.typeid in {%2}").arg(prefix, nums.join(QLatin1String(", ")));
    }

    bool group_ok = false;
    const int group = ui_->groupEdit->text().trimmed().toInt(&group_ok);
    if (group_ok && asduIncludesGeneric()) {
        parts << QStringLiteral("%1.gen.group == %2").arg(prefix).arg(group);
    }

    if (parts.isEmpty()) {
        return QString();
    }
    if (parts.size() == 1) {
        return parts.first();
    }
    return QStringLiteral("(%1)").arg(parts.join(QStringLiteral(" && ")));
}

void Iec103FilterWidget::updateGroupVisibility()
{
    const bool show_group = asduIncludesGeneric();
    ui_->groupLabel->setVisible(show_group);
    ui_->groupEdit->setVisible(show_group);
    if (!show_group) {
        ui_->groupEdit->clear();
    }
}

void Iec103FilterWidget::updatePreview()
{
    ui_->previewLabel->setText(buildFilter());
    emit filterChanged();
}

void Iec103FilterWidget::applyFilterIfRealtime(bool debounce)
{
    if (!isRealtimeEnabled()) {
        return;
    }
    if (debounce) {
        filter_apply_timer_->start();
    } else {
        applyFilterNow(false);
    }
}

void Iec103FilterWidget::onDebouncedFilterApply()
{
    applyFilterNow(false);
}

void Iec103FilterWidget::onCriteriaChanged()
{
    updateGroupVisibility();
    updatePreview();
    applyFilterIfRealtime(true);
}

void Iec103FilterWidget::setAsduValue(int typ)
{
    ui_->asduEdit->setText(QString::number(typ));
    updateGroupVisibility();
    updatePreview();
    applyFilterNow(true);
}

void Iec103FilterWidget::onWaveDataClicked()
{
    /* Shandong: ASDU14 file content; NARI: ASDU30 disturbance values */
    setAsduValue(isNariNetVariant() ? 30 : 14);
}

void Iec103FilterWidget::onWaveListClicked()
{
    /* Shandong: ASDU16 file list; NARI: ASDU23 disturbance table */
    setAsduValue(isNariNetVariant() ? 23 : 16);
}

void Iec103FilterWidget::applyFilterNow(bool force)
{
    const QString filter = buildFilter();
    if (!force && filter == last_emitted_filter_) {
        return;
    }
    last_emitted_filter_ = filter;
    emit requestApplyFilter(filter, force);
}
