/** @file
 *
 * MMS station-layer process sequence diagram widget.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MMS_PROCESS_DIAGRAM_WIDGET_H
#define MMS_PROCESS_DIAGRAM_WIDGET_H

#include <QColor>
#include <QVector>
#include <QWidget>

struct MmsProcessDiagramEvent {
    int index;
    double rel_secs;
    QString src;
    QString dst;
    QString arrow_label;
    int src_col;
    int dst_col;
};

class MmsProcessDiagramWidget : public QWidget
{
    Q_OBJECT

public:
    explicit MmsProcessDiagramWidget(QWidget *parent = nullptr);

    void setColumns(const QStringList &columns);
    void setEvents(const QVector<MmsProcessDiagramEvent> &events);
    void setSelectedIndex(int index);
    void setBackgroundColor(const QColor &color);
    QColor backgroundColor() const { return background_; }

    static int topMargin();
    static int rowHeight();

    QSize minimumSizeHint() const override;
    QSize sizeHint() const override;

signals:
    void eventClicked(int index);
    void eventDoubleClicked(int index);

protected:
    void paintEvent(QPaintEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
    void mouseDoubleClickEvent(QMouseEvent *event) override;

private:
    int eventAtPos(const QPoint &pos) const;

    QStringList columns_;
    QVector<MmsProcessDiagramEvent> events_;
    int selected_index_ = -1;
    QColor background_{0xE8, 0xF5, 0xE9};
};

#endif /* MMS_PROCESS_DIAGRAM_WIDGET_H */
