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

#include <QHash>
#include <QVector>

class MmsProcessDiagramWidget;
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

private:
    struct EventRow {
        uint32_t framenum;
        double rel_secs;
        QString src;
        QString dst;
        QString arrow_label;
        QString explanation;
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
    void selectIndex(int index);
    void syncDiagramSize();
    void jumpToFrame(uint32_t framenum);
    static QString arrowLabelForKind(mms_process_kind_t kind);
    static QString buildExplanation(const mms_process_tap_data *tap);

    Ui::MmsProcessAnalysisDialog *ui_;
    MmsProcessDiagramWidget *diagram_;
    QVector<EventRow> rows_;
    QStringList columns_;
    QHash<QString, int> col_index_;
};

#endif /* MMS_PROCESS_ANALYSIS_DIALOG_H */
