/** @file
 *
 * MMS station-layer message process analysis dialog.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MMS_PROCESS_ANALYSIS_DIALOG_H
#define MMS_PROCESS_ANALYSIS_DIALOG_H

#include "wireshark_dialog.h"

#include <epan/dissectors/packet-mms-tap.h>

#include <QColor>
#include <QHash>
#include <QSet>
#include <QVector>

class MmsProcessDiagramWidget;
class MmsProcessTimeColumnWidget;
class QListWidgetItem;
class QResizeEvent;

namespace Ui {
class MmsProcessAnalysisDialog;
}

class MmsProcessAnalysisDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit MmsProcessAnalysisDialog(QWidget &parent, CaptureFile &capture_file);
    ~MmsProcessAnalysisDialog() override;

signals:
    void goToPacket(int packet_num);

protected:
    void captureFileClosing() override;
    void resizeEvent(QResizeEvent *event) override;

private slots:
    void onExplainItemClicked(QListWidgetItem *item);
    void onExplainItemDoubleClicked(QListWidgetItem *item);
    void onDiagramEventClicked(int index);
    void onDiagramEventDoubleClicked(int index);
    void onBackgroundColorChanged(int index);
    void onDiagramVerticalScroll(int value);
    void onExplainVerticalScroll(int value);
    void onSearchTextChanged(const QString &text);

private:
    struct EventRow {
        uint32_t framenum;
        double rel_secs;
        QString src;
        QString dst;
        QString arrow_label;
        QString explanation;
        mms_process_kind_t kind;
        uint32_t invoke_id;
        bool has_invoke_id;
        QString search_refs; /* RCB / dataset / request object refs */
        int src_col;
        int dst_col;
        int list_row;
    };

    static void tapReset(void *tapdata);
    static tap_packet_status tapPacket(void *tapdata, packet_info *pinfo,
                                       epan_dissect_t *edt, const void *data,
                                       tap_flags_t flags);
    static void tapDraw(void *tapdata);

    void retap();
    void rebuild();
    void applyFilterAndRefresh();
    void selectIndex(int index);
    void syncDiagramSize();
    void jumpToFrame(uint32_t framenum);
    void applyBackgroundColor(const QColor &color, bool persist);
    void initBackgroundColorCombo();
    static QString arrowLabelForKind(mms_process_kind_t kind);
    static QString buildExplanation(const mms_process_tap_data *tap);
    static QString normalizeRefForSearch(const QString &ref);
    static QStringList parseSearchTokens(const QString &text);
    static bool refsMatchTokens(const QString &search_refs, const QStringList &tokens);

    Ui::MmsProcessAnalysisDialog *ui_;
    MmsProcessDiagramWidget *diagram_;
    MmsProcessTimeColumnWidget *time_column_;
    QVector<EventRow> all_rows_;
    QVector<EventRow> rows_;
    QStringList columns_;
    QHash<QString, int> col_index_;
    QColor background_color_;
};

#endif /* MMS_PROCESS_ANALYSIS_DIALOG_H */
