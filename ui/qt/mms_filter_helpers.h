/** @file
 *
 * Shared MMS display-filter string helpers (segmented fuzzy / exact match).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MMS_FILTER_HELPERS_H
#define MMS_FILTER_HELPERS_H

#include <QString>
#include <QStringList>

namespace MmsFilterHelpers {

QString quoteFilterString(const QString &value);
QString quoteFilterLower(const QString &value);
QString ciContainsClause(const QString &field, const QString &segment);
QString ciEqualsClause(const QString &field, const QString &text);
QStringList filterSegments(const QString &text);
void appendRefFilter(QStringList &parts, const QString &field, const QString &text,
                     bool exact_match);
void appendSegmentedContains(QStringList &parts, const QString &field, const QString &text);

} // namespace MmsFilterHelpers

#endif /* MMS_FILTER_HELPERS_H */
