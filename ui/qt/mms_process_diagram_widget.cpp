/** @file
 *
 * MMS station-layer process sequence diagram widget.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "mms_process_diagram_widget.h"

#include <QFontMetrics>
#include <QMouseEvent>
#include <QPainter>
#include <QPen>

namespace {

constexpr int kLeftMargin = 8;
constexpr int kTopMargin = 28;
constexpr int kRightMargin = 12;
constexpr int kBottomMargin = 12;
constexpr int kColMinWidth = 88;
constexpr int kRowHeight = 26;

} // namespace

MmsProcessDiagramWidget::MmsProcessDiagramWidget(QWidget *parent) :
    QWidget(parent)
{
    setMinimumHeight(200);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    setMouseTracking(true);
}

int MmsProcessDiagramWidget::topMargin()
{
    return kTopMargin;
}

int MmsProcessDiagramWidget::rowHeight()
{
    return kRowHeight;
}

void MmsProcessDiagramWidget::setColumns(const QStringList &columns)
{
    columns_ = columns;
    updateGeometry();
    update();
}

void MmsProcessDiagramWidget::setEvents(const QVector<MmsProcessDiagramEvent> &events)
{
    events_ = events;
    updateGeometry();
    update();
}

void MmsProcessDiagramWidget::setSelectedIndex(int index)
{
    if (selected_index_ == index) {
        return;
    }
    selected_index_ = index;
    update();
}

void MmsProcessDiagramWidget::setBackgroundColor(const QColor &color)
{
    if (!color.isValid() || background_ == color) {
        return;
    }
    background_ = color;
    update();
}

QSize MmsProcessDiagramWidget::minimumSizeHint() const
{
    const int w = kLeftMargin + kRightMargin + qMax(1, columns_.size()) * kColMinWidth;
    const int h = kTopMargin + kBottomMargin + qMax(1, static_cast<int>(events_.size())) * kRowHeight;
    return {w, h};
}

QSize MmsProcessDiagramWidget::sizeHint() const
{
    return minimumSizeHint();
}

int MmsProcessDiagramWidget::eventAtPos(const QPoint &pos) const
{
    if (events_.isEmpty()) {
        return -1;
    }
    const int y = pos.y() - kTopMargin;
    if (y < 0) {
        return -1;
    }
    const int row = y / kRowHeight;
    if (row < 0 || row >= events_.size()) {
        return -1;
    }
    return events_.at(row).index;
}

void MmsProcessDiagramWidget::mousePressEvent(QMouseEvent *event)
{
    const int idx = eventAtPos(event->pos());
    if (idx >= 0) {
        setSelectedIndex(idx);
        emit eventClicked(idx);
    }
    QWidget::mousePressEvent(event);
}

void MmsProcessDiagramWidget::mouseDoubleClickEvent(QMouseEvent *event)
{
    const int idx = eventAtPos(event->pos());
    if (idx >= 0) {
        setSelectedIndex(idx);
        emit eventDoubleClicked(idx);
        return;
    }
    QWidget::mouseDoubleClickEvent(event);
}

void MmsProcessDiagramWidget::paintEvent(QPaintEvent *)
{
    QPainter painter(this);
    painter.fillRect(rect(), background_);

    if (columns_.isEmpty()) {
        painter.drawText(rect(), Qt::AlignCenter, tr("无 MMS 站控层事件"));
        return;
    }

    const int col_w = qMax(kColMinWidth,
                           (width() - kLeftMargin - kRightMargin) / columns_.size());
    const int content_h = events_.size() * kRowHeight;

    painter.setPen(QPen(Qt::black));
    QFont header_font = painter.font();
    header_font.setBold(true);
    painter.setFont(header_font);

    for (int c = 0; c < columns_.size(); c++) {
        const int x = kLeftMargin + c * col_w + col_w / 2;
        const QRect header_rect(kLeftMargin + c * col_w, 4, col_w, kTopMargin - 6);
        painter.drawText(header_rect, Qt::AlignHCenter | Qt::AlignVCenter,
                         painter.fontMetrics().elidedText(columns_.at(c), Qt::ElideRight, col_w - 4));

        QPen dash_pen(Qt::darkGray, 1, Qt::DashLine);
        painter.setPen(dash_pen);
        painter.drawLine(x, kTopMargin, x, kTopMargin + content_h);
        painter.setPen(QPen(Qt::black));
    }

    QFont body_font = painter.font();
    body_font.setBold(false);
    body_font.setPointSize(qMax(8, body_font.pointSize() - 1));
    painter.setFont(body_font);
    const QFontMetrics fm(body_font);

    for (int row = 0; row < events_.size(); row++) {
        const auto &ev = events_.at(row);
        const int y = kTopMargin + row * kRowHeight + kRowHeight / 2;
        const int x1 = kLeftMargin + ev.src_col * col_w + col_w / 2;
        const int x2 = kLeftMargin + ev.dst_col * col_w + col_w / 2;

        if (ev.index == selected_index_) {
            painter.fillRect(0, kTopMargin + row * kRowHeight, width(), kRowHeight,
                             QColor(0xBB, 0xDE, 0xFB));
        }

        QPen arrow_pen(ev.index == selected_index_ ? QColor(0x15, 0x65, 0xC0) : QColor(0x2E, 0x7D, 0x32),
                       ev.index == selected_index_ ? 2 : 1);
        painter.setPen(arrow_pen);
        painter.drawLine(x1, y, x2, y);

        const int dir = (x2 >= x1) ? 1 : -1;
        const int ax = x2;
        const int ay = y;
        painter.drawLine(ax, ay, ax - 6 * dir, ay - 4);
        painter.drawLine(ax, ay, ax - 6 * dir, ay + 4);

        const QString label = ev.arrow_label;
        const int label_w = fm.horizontalAdvance(label) + 8;
        const int lx = (x1 + x2) / 2 - label_w / 2;
        painter.fillRect(lx, y - 9, label_w, 18, background_);
        painter.setPen(QPen(Qt::black));
        painter.drawText(QRect(lx, y - 9, label_w, 18), Qt::AlignCenter, label);
    }
}
