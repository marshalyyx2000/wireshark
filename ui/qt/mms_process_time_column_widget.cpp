/** @file
 *
 * Sticky time column for MMS process sequence diagram.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "mms_process_time_column_widget.h"

#include <QPainter>
#include <QPen>

namespace {

constexpr int kTopMargin = 28;
constexpr int kBottomMargin = 12;
constexpr int kRowHeight = 26;
constexpr int kWidth = 56;

} // namespace

MmsProcessTimeColumnWidget::MmsProcessTimeColumnWidget(QWidget *parent) :
    QWidget(parent)
{
    setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    setFixedWidth(kWidth);
}

int MmsProcessTimeColumnWidget::preferredWidth()
{
    return kWidth;
}

void MmsProcessTimeColumnWidget::setEvents(const QVector<MmsProcessDiagramEvent> &events)
{
    events_ = events;
    updateGeometry();
    update();
}

void MmsProcessTimeColumnWidget::setSelectedIndex(int index)
{
    if (selected_index_ == index) {
        return;
    }
    selected_index_ = index;
    update();
}

void MmsProcessTimeColumnWidget::setBackgroundColor(const QColor &color)
{
    if (background_ == color) {
        return;
    }
    background_ = color;
    update();
}

QSize MmsProcessTimeColumnWidget::minimumSizeHint() const
{
    return {kWidth, kTopMargin + kBottomMargin + qMax(1, static_cast<int>(events_.size())) * kRowHeight};
}

QSize MmsProcessTimeColumnWidget::sizeHint() const
{
    return minimumSizeHint();
}

void MmsProcessTimeColumnWidget::paintEvent(QPaintEvent *)
{
    QPainter painter(this);
    painter.fillRect(rect(), background_);

    painter.setPen(QPen(QColor(0xB0, 0xB0, 0xB0)));
    painter.drawLine(width() - 1, 0, width() - 1, height());

    QFont header_font = painter.font();
    header_font.setBold(true);
    painter.setFont(header_font);
    painter.setPen(QPen(Qt::black));
    painter.drawText(QRect(0, 4, width() - 2, kTopMargin - 6),
                     Qt::AlignHCenter | Qt::AlignVCenter, tr("时间"));

    QFont body_font = painter.font();
    body_font.setBold(false);
    body_font.setPointSize(qMax(8, body_font.pointSize() - 1));
    painter.setFont(body_font);

    for (int row = 0; row < events_.size(); row++) {
        const auto &ev = events_.at(row);
        if (ev.index == selected_index_) {
            painter.fillRect(0, kTopMargin + row * kRowHeight, width() - 1, kRowHeight,
                             QColor(0xBB, 0xDE, 0xFB));
        }
        painter.setPen(QPen(Qt::black));
        painter.drawText(QRect(2, kTopMargin + row * kRowHeight, width() - 6, kRowHeight),
                         Qt::AlignRight | Qt::AlignVCenter,
                         QString::asprintf("%.3f", ev.rel_secs));
    }
}
