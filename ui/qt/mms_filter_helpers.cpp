/** @file
 *
 * Shared MMS display-filter string helpers (segmented fuzzy / exact match).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "mms_filter_helpers.h"

#include <QRegularExpression>

namespace MmsFilterHelpers {

QString quoteFilterString(const QString &value)
{
    QString escaped = value;
    escaped.replace(QLatin1Char('\\'), QStringLiteral("\\\\"));
    escaped.replace(QLatin1Char('"'), QStringLiteral("\\\""));
    return QStringLiteral("\"%1\"").arg(escaped);
}

QString quoteFilterLower(const QString &value)
{
    return quoteFilterString(value.toLower());
}

QString ciContainsClause(const QString &field, const QString &segment)
{
    return QStringLiteral("lower(%1) contains %2").arg(field, quoteFilterLower(segment));
}

QString ciEqualsClause(const QString &field, const QString &text)
{
    return QStringLiteral("lower(%1) == %2").arg(field, quoteFilterLower(text));
}

QStringList filterSegments(const QString &text)
{
    return text.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
}

void appendSegmentedContains(QStringList &parts, const QString &field, const QString &text)
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

void appendRefFilter(QStringList &parts, const QString &field, const QString &text,
                     bool exact_match)
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

} // namespace MmsFilterHelpers
