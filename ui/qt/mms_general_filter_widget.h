/** @file
 *
 * MMS general display-filter builder widget (refs + invokeID).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MMS_GENERAL_FILTER_WIDGET_H
#define MMS_GENERAL_FILTER_WIDGET_H

#include "config.h"

#include <QString>
#include <QWidget>

class QTimer;

namespace Ui {
class MmsGeneralFilterWidget;
}

class MmsGeneralFilterWidget : public QWidget
{
    Q_OBJECT

public:
    explicit MmsGeneralFilterWidget(QWidget *parent = nullptr);
    ~MmsGeneralFilterWidget() override;

    QString buildFilter() const;
    bool hasGeneralCriteria() const;
    bool isRealtimeEnabled() const;
    void setPreviewVisible(bool visible);
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

private:
    void updatePreview();
    void applyFilterIfRealtime(bool debounce = true);

    Ui::MmsGeneralFilterWidget *ui_;
    QTimer *filter_apply_timer_;
    QString last_emitted_filter_;
};

#endif /* MMS_GENERAL_FILTER_WIDGET_H */
