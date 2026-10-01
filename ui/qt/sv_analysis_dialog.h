/** @file
 *
 * IEC 61850 Sampled Values analysis (APPID / RMS curves)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SV_ANALYSIS_DIALOG_H
#define SV_ANALYSIS_DIALOG_H

#include "config.h"

#include "wireshark_dialog.h"

#include <QHash>
#include <QVector>

class QCPGraph;
class QTreeWidgetItem;

namespace Ui {
class SvAnalysisDialog;
}

/** Max PhsMeas channels (matches IEC61850_SV_MAX_PHSMEAS_ENTRIES). */
static const int kSvMaxChannels = 64;

/**
 * @brief Dialog for IEC 61850 SV RMS / waveform analysis by APPID.
 */
class SvAnalysisDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit SvAnalysisDialog(QWidget &parent, CaptureFile &capture_file);
    ~SvAnalysisDialog() override;

protected:
    void captureFileClosing() override;

private slots:
    void onAppidChanged(int index);
    void onRefreshClicked();
    void onExportClicked();
    void onModeChanged(int index);
    void onWindowMsChanged();
    void onScaleChanged();
    void onViewRangeChanged();
    void onChannelItemChanged(QTreeWidgetItem *item, int column);
    void onSelectAllClicked();
    void onSelectNoneClicked();

private:
    struct Sample {
        double t;
        uint16_t smpCnt;
        uint8_t num_ch;
        int32_t values[kSvMaxChannels];
    };

    struct StreamInfo {
        uint16_t appid;
        QString svID;
        QVector<Sample> samples;
    };

    struct ChannelStats {
        int channel;
        int count;
        double rms_min;
        double rms_max;
        double rms_sum;
        double rms_last;
    };

    static void tapReset(void *tapdata);
    static tap_packet_status tapPacket(void *tapdata, packet_info *pinfo,
                                       epan_dissect_t *, const void *data,
                                       tap_flags_t flags);
    static void tapDraw(void *tapdata);

    void retap();
    void rebuildAppidList();
    void computeAndDraw();
    void updateChannelTable(const QVector<ChannelStats> &stats);
    void clearGraphs();
    StreamInfo *selectedStream();
    double scaleFactor() const;
    double windowSeconds() const;
    void viewTimeRange(const StreamInfo &stream, double *t_lo, double *t_hi) const;
    void setAllChannelsVisible(bool visible);

    Ui::SvAnalysisDialog *ui_;
    QHash<uint16_t, StreamInfo> streams_;
    QVector<QCPGraph *> graphs_;
};

#endif /* SV_ANALYSIS_DIALOG_H */
