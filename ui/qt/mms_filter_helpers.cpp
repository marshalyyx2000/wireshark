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

QString buildMultiFieldStringMatch(const QStringList &fields, const QString &text,
                                   bool exact_match)
{
    if (text.trimmed().isEmpty() || fields.isEmpty()) {
        return QString();
    }

    if (exact_match) {
        QStringList alts;
        for (const QString &field : fields) {
            alts << ciEqualsClause(field, text.trimmed());
        }
        if (alts.size() == 1) {
            return alts.first();
        }
        return QStringLiteral("(%1)").arg(alts.join(QStringLiteral(" || ")));
    }

    QStringList segment_clauses;
    for (const QString &segment : filterSegments(text)) {
        QStringList alts;
        for (const QString &field : fields) {
            alts << ciContainsClause(field, segment);
        }
        if (alts.size() == 1) {
            segment_clauses << alts.first();
        } else {
            segment_clauses << QStringLiteral("(%1)").arg(alts.join(QStringLiteral(" || ")));
        }
    }
    if (segment_clauses.isEmpty()) {
        return QString();
    }
    if (segment_clauses.size() == 1) {
        return segment_clauses.first();
    }
    return QStringLiteral("(%1)").arg(segment_clauses.join(QStringLiteral(" && ")));
}

QString escapeRegexLiteral(const QString &text)
{
    QString out;
    out.reserve(text.size() * 2);
    for (QChar c : text) {
        switch (c.unicode()) {
        case '\\':
        case '.':
        case '^':
        case '$':
        case '*':
        case '+':
        case '?':
        case '(':
        case ')':
        case '[':
        case ']':
        case '{':
        case '}':
        case '|':
            out += QLatin1Char('\\');
            break;
        default:
            break;
        }
        out += c;
    }
    return out;
}

QString buildPayloadStringMatch(const QString &text, bool exact_match)
{
    if (text.trimmed().isEmpty()) {
        return QString();
    }

    /* Exact: equality on a small field set (no _ws.col.info). */
    if (exact_match) {
        static const QStringList exact_fields = {
            QStringLiteral("mms.Identifier"),
            QStringLiteral("mms.domainId"),
            QStringLiteral("mms.objectName_domain_specific_itemId"),
            QStringLiteral("mms.iec61850.data_reference"),
            QStringLiteral("mms.iec61850.object_reference"),
            QStringLiteral("mms.iec61850.datset"),
            QStringLiteral("mms.iec61850.rptid"),
        };
        return buildMultiFieldStringMatch(exact_fields, text, true);
    }

    /* Fuzzy: one case-insensitive regex scan of the MMS tvb per segment.
     * Far cheaper than OR of many lower(field) contains clauses. */
    QStringList segment_clauses;
    for (const QString &segment : filterSegments(text)) {
        const QString pattern = QStringLiteral("(?i)") + escapeRegexLiteral(segment);
        segment_clauses << QStringLiteral("mms matches %1").arg(quoteFilterString(pattern));
    }
    if (segment_clauses.isEmpty()) {
        return QString();
    }
    if (segment_clauses.size() == 1) {
        return segment_clauses.first();
    }
    return QStringLiteral("(%1)").arg(segment_clauses.join(QStringLiteral(" && ")));
}

} // namespace MmsFilterHelpers
