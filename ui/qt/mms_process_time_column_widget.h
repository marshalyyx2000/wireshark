/** @file
 *
 * Sticky time column for MMS process sequence diagram.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MMS_PROCESS_TIME_COLUMN_WIDGET_H
#define MMS_PROCESS_TIME_COLUMN_WIDGET_H

#include "mms_process_diagram_widget.h"

#include <QColor>
#include <QVector>
#include <QWidget>

class MmsProcessTimeColumnWidget : public QWidget
{
    Q_OBJECT

public:
    explicit MmsProcessTimeColumnWidget(QWidget *parent = nullptr);

    void setEvents(const QVector<MmsProcessDiagramEvent> &events);
    void setSelectedIndex(int index);
    void setBackgroundColor(const QColor &color);

    static int preferredWidth();

    QSize minimumSizeHint() const override;
    QSize sizeHint() const override;

protected:
    void paintEvent(QPaintEvent *event) override;

private:
    QVector<MmsProcessDiagramEvent> events_;
    int selected_index_ = -1;
    QColor background_{0xE8, 0xF5, 0xE9};
};

#endif /* MMS_PROCESS_TIME_COLUMN_WIDGET_H */
