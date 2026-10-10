/** @file
 *
 * Small Qt5/Qt6 compatibility helpers for the Ubuntu 16.04 / Qt 5.14 branch.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WS_QT5_COMPAT_H
#define WS_QT5_COMPAT_H

#include <QtGlobal>
#include <Qt>
#include <QColor>
#include <QDropEvent>
#include <QList>
#include <QMouseEvent>
#include <QPoint>
#include <QPointF>
#include <QString>
#include <QVector>

#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
using WsModelRoles = QList<int>;
using WsSizeType = qsizetype;
inline int ws_alignment_to_int(Qt::Alignment a)
{
    return a.toInt();
}
inline Qt::Alignment ws_alignment_from_int(int i)
{
    return Qt::Alignment::fromInt(i);
}
inline QColor ws_color_from_string(const QString &s)
{
    return QColor::fromString(s);
}
#else
using WsModelRoles = QVector<int>;
using WsSizeType = int;
inline int ws_alignment_to_int(Qt::Alignment a)
{
    return static_cast<int>(a);
}
inline Qt::Alignment ws_alignment_from_int(int i)
{
    return static_cast<Qt::Alignment>(i);
}
inline QColor ws_color_from_string(const QString &s)
{
    return QColor(s);
}
#endif

inline QPoint ws_mouse_pos(const QMouseEvent *event)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    return event->position().toPoint();
#else
    return event->pos();
#endif
}

inline QPointF ws_mouse_posf(const QMouseEvent *event)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    return event->position();
#else
    return event->localPos();
#endif
}

inline QPoint ws_mouse_global_pos(const QMouseEvent *event)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    return event->globalPosition().toPoint();
#else
    return event->globalPos();
#endif
}

inline QPoint ws_drop_pos(const QDropEvent *event)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    return event->position().toPoint();
#else
    return event->pos();
#endif
}

#endif /* WS_QT5_COMPAT_H */
