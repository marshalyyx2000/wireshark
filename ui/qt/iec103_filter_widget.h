/** @file
 *
 * Shandong / SGCC IEC 103 display-filter builder for classify panel.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef IEC103_FILTER_WIDGET_H
#define IEC103_FILTER_WIDGET_H

#include "config.h"

#include <QList>
#include <QString>
#include <QWidget>

class QTimer;

namespace Ui {
class Iec103FilterWidget;
}

class Iec103FilterWidget : public QWidget
{
    Q_OBJECT

public:
    explicit Iec103FilterWidget(QWidget *parent = nullptr);
    ~Iec103FilterWidget() override;

    QString buildFilter() const;
    bool hasCriteria() const;
    bool isRealtimeEnabled() const;
    void resetAppliedFilterState();
    void clearCriteria();

signals:
    void filterChanged();
    void requestApplyFilter(const QString &filter, bool force);

public slots:
    void applyFilterNow(bool force = false);

private slots:
    void onDebouncedFilterApply();
    void onCriteriaChanged();
    void onWaveDataClicked();
    void onWaveListClicked();
    void onGenericAsduClicked();
    void onWaveFlowClicked();

private:
    void updateGroupVisibility();
    void updateWaveButtonLabels();
    void updatePreview();
    void applyFilterIfRealtime(bool debounce = true);
    void setAsduValue(int typ);
    void setAsduValues(const QList<int> &types);
    QList<int> parseAsduValues() const;
    bool asduIncludesGeneric() const;
    QString filterPrefix() const;
    bool isNariNetVariant() const;

    Ui::Iec103FilterWidget *ui_;
    QTimer *filter_apply_timer_;
    QString last_emitted_filter_;
};

#endif /* IEC103_FILTER_WIDGET_H */
