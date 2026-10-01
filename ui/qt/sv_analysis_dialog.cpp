/* sv_analysis_dialog.cpp
 *
 * IEC 61850 Sampled Values analysis (APPID / RMS curves)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "sv_analysis_dialog.h"
#include <ui_sv_analysis_dialog.h>

#include "file.h"
#include "main_application.h"

#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/dissectors/packet-sv.h>

#include <ui/qt/utils/theme_manager.h>
#include <ui/qt/widgets/qcustomplot.h>

#include <QFileDialog>
#include <QMessageBox>
#include <QPen>
#include <QTextStream>
#include <QTimer>
#include <QTreeWidgetItem>

#include <algorithm>
#include <cmath>
#include <limits>

// Cap instantaneous points drawn to keep the UI responsive.
static const int kMaxInstantPoints = 20000;

SvAnalysisDialog::SvAnalysisDialog(QWidget &parent, CaptureFile &capture_file) :
    WiresharkDialog(parent, capture_file),
    ui_(new Ui::SvAnalysisDialog)
{
    ui_->setupUi(this);
    setWindowSubtitle(tr("SV Analysis"));

    ui_->plot->xAxis->setLabel(tr("Time (s)"));
    ui_->plot->yAxis->setLabel(tr("Value"));
    ui_->plot->setInteractions(QCP::iRangeDrag | QCP::iRangeZoom | QCP::iSelectPlottables);
    ui_->plot->axisRect()->setRangeDrag(Qt::Horizontal | Qt::Vertical);
    ui_->plot->axisRect()->setRangeZoom(Qt::Horizontal | Qt::Vertical);
    ui_->plot->legend->setVisible(true);

    ui_->channelTree->setColumnWidth(0, 48);
    ui_->channelTree->setColumnWidth(1, 40);

    connect(ui_->appidCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SvAnalysisDialog::onAppidChanged);
    connect(ui_->refreshButton, &QPushButton::clicked, this, &SvAnalysisDialog::onRefreshClicked);
    connect(ui_->exportButton, &QPushButton::clicked, this, &SvAnalysisDialog::onExportClicked);
    connect(ui_->modeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &SvAnalysisDialog::onModeChanged);
    connect(ui_->windowSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &SvAnalysisDialog::onWindowMsChanged);
    connect(ui_->scaleSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &SvAnalysisDialog::onScaleChanged);
    connect(ui_->viewMsSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &SvAnalysisDialog::onViewRangeChanged);
    connect(ui_->startSecSpin, QOverload<double>::of(&QDoubleSpinBox::valueChanged),
            this, &SvAnalysisDialog::onViewRangeChanged);
    connect(ui_->channelTree, &QTreeWidget::itemChanged,
            this, &SvAnalysisDialog::onChannelItemChanged);
    connect(ui_->selectAllButton, &QPushButton::clicked,
            this, &SvAnalysisDialog::onSelectAllClicked);
    connect(ui_->selectNoneButton, &QPushButton::clicked,
            this, &SvAnalysisDialog::onSelectNoneClicked);

    loadGeometry(parent.width() * 4 / 5, parent.height() * 4 / 5);

    /* Defer retap until the event loop runs (same pattern as Expert Info). */
    QTimer::singleShot(0, this, [this]() { retap(); });
}

SvAnalysisDialog::~SvAnalysisDialog()
{
    delete ui_;
}

void SvAnalysisDialog::captureFileClosing()
{
    removeTapListeners();
    WiresharkDialog::captureFileClosing();
}

void SvAnalysisDialog::tapReset(void *tapdata)
{
    SvAnalysisDialog *dlg = static_cast<SvAnalysisDialog *>(tapdata);
    dlg->streams_.clear();
}

tap_packet_status SvAnalysisDialog::tapPacket(void *tapdata, packet_info *pinfo,
                                              epan_dissect_t *, const void *data,
                                              tap_flags_t)
{
    SvAnalysisDialog *dlg = static_cast<SvAnalysisDialog *>(tapdata);
    const sv_frame_data *sv = static_cast<const sv_frame_data *>(data);
    if (!sv || !pinfo) {
        return TAP_PACKET_DONT_REDRAW;
    }

    StreamInfo &stream = dlg->streams_[sv->appid];
    stream.appid = sv->appid;
    if (stream.svID.isEmpty() && sv->svID[0] != '\0') {
        stream.svID = QString::fromLatin1(sv->svID);
    }

    Sample sample;
    sample.t = nstime_to_sec(&pinfo->rel_ts);
    sample.smpCnt = sv->smpCnt;
    sample.num_ch = sv->num_phsMeas;
    for (int i = 0; i < sv->num_phsMeas && i < kSvMaxChannels; i++) {
        sample.values[i] = sv->phsMeas[i].value;
    }
    stream.samples.append(sample);

    return TAP_PACKET_DONT_REDRAW;
}

void SvAnalysisDialog::tapDraw(void *tapdata)
{
    Q_UNUSED(tapdata);
}

void SvAnalysisDialog::retap()
{
    if (fileClosed()) {
        ui_->hintLabel->setText(tr("Capture file is closed."));
        return;
    }
    if (!cap_file_.isValid() || !cap_file_.capFile()) {
        ui_->hintLabel->setText(tr("No capture file open. Open an SV capture, then click Refresh."));
        return;
    }

    beginRetapPackets();
    removeTapListeners();
    streams_.clear();

    if (!registerTapListener("sv", this, nullptr, 0, tapReset, tapPacket, tapDraw)) {
        endRetapPackets();
        ui_->hintLabel->setText(tr("Failed to attach to SV tap."));
        return;
    }

    cap_file_.retapPackets();
    removeTapListeners();
    endRetapPackets();

    rebuildAppidList();
    computeAndDraw();
}

void SvAnalysisDialog::rebuildAppidList()
{
    const uint16_t prev = ui_->appidCombo->currentData().isValid()
                              ? static_cast<uint16_t>(ui_->appidCombo->currentData().toUInt())
                              : 0;

    ui_->appidCombo->blockSignals(true);
    ui_->appidCombo->clear();

    QList<uint16_t> appids = streams_.keys();
    std::sort(appids.begin(), appids.end());
    for (uint16_t appid : appids) {
        const StreamInfo &s = streams_[appid];
        QString label = QStringLiteral("0x%1").arg(appid, 4, 16, QLatin1Char('0'));
        if (!s.svID.isEmpty()) {
            label += QStringLiteral(" (%1)").arg(s.svID);
        }
        label += QStringLiteral(" [%1]").arg(s.samples.size());
        ui_->appidCombo->addItem(label, appid);
    }
    ui_->appidCombo->blockSignals(false);

    int idx = ui_->appidCombo->findData(prev);
    if (idx < 0 && ui_->appidCombo->count() > 0) {
        idx = 0;
    }
    if (idx >= 0) {
        ui_->appidCombo->setCurrentIndex(idx);
    } else {
        ui_->svIdLabel->setText(QChar(0x2014));
        ui_->hintLabel->setText(
            tr("No SV packets found. Confirm the packet list shows "
               "\"IEC61850 Sampled Values\", then click Refresh. "
               "Instantaneous/RMS only changes the plot, not packet discovery."));
    }
}

SvAnalysisDialog::StreamInfo *SvAnalysisDialog::selectedStream()
{
    if (!ui_->appidCombo->currentData().isValid()) {
        return nullptr;
    }
    uint16_t appid = static_cast<uint16_t>(ui_->appidCombo->currentData().toUInt());
    auto it = streams_.find(appid);
    if (it == streams_.end()) {
        return nullptr;
    }
    return &it.value();
}

double SvAnalysisDialog::scaleFactor() const
{
    return ui_->scaleSpin->value();
}

double SvAnalysisDialog::windowSeconds() const
{
    /* Grid frequency (Hz) → one-cycle period. */
    const double f = ui_->windowSpin->value();
    if (f <= 0.0) {
        return 0.02;
    }
    return 1.0 / f;
}

void SvAnalysisDialog::viewTimeRange(const StreamInfo &stream, double *t_lo, double *t_hi) const
{
    const double t0 = stream.samples.first().t;
    const double start = ui_->startSecSpin->value();
    const double span = ui_->viewMsSpin->value() / 1000.0;
    *t_lo = t0 + start;
    *t_hi = *t_lo + qMax(span, 0.001);
}

void SvAnalysisDialog::clearGraphs()
{
    ui_->plot->clearGraphs();
    graphs_.clear();
}

void SvAnalysisDialog::computeAndDraw()
{
    clearGraphs();

    StreamInfo *stream = selectedStream();
    if (!stream || stream->samples.isEmpty()) {
        ui_->channelTree->clear();
        ui_->plot->replot();
        return;
    }

    ui_->svIdLabel->setText(stream->svID.isEmpty() ? QChar(0x2014) : stream->svID);

    int max_ch = 0;
    for (const Sample &s : stream->samples) {
        if (s.num_ch > max_ch) {
            max_ch = s.num_ch;
        }
    }
    if (max_ch <= 0) {
        ui_->hintLabel->setText(tr("Selected APPID has no PhsMeas values."));
        ui_->channelTree->clear();
        ui_->plot->replot();
        return;
    }

    // Preserve channel visibility selections when possible.
    QVector<bool> show_ch(max_ch, true);
    for (int r = 0; r < ui_->channelTree->topLevelItemCount(); r++) {
        QTreeWidgetItem *item = ui_->channelTree->topLevelItem(r);
        int ch = item->data(1, Qt::UserRole).toInt();
        if (ch >= 0 && ch < max_ch) {
            show_ch[ch] = (item->checkState(0) == Qt::Checked);
        }
    }

    const double scale = scaleFactor();
    /* Mode combo: 0 = Instantaneous (default), 1 = RMS */
    const bool rms_mode = (ui_->modeCombo->currentIndex() == 1);
    double t_lo = 0.0;
    double t_hi = 0.0;
    viewTimeRange(*stream, &t_lo, &t_hi);

    QVector<ChannelStats> stats(max_ch);
    for (int ch = 0; ch < max_ch; ch++) {
        stats[ch].channel = ch;
        stats[ch].count = 0;
        stats[ch].rms_min = std::numeric_limits<double>::infinity();
        stats[ch].rms_max = -std::numeric_limits<double>::infinity();
        stats[ch].rms_sum = 0.0;
        stats[ch].rms_last = 0.0;
    }

    /*
     * First open: show a single AC-like channel. Many MU datasets put DC/status
     * in Ch0 and bury the 50 Hz analogues in higher indices; overlaying several
     * channels also looks like noise even when one of them is a sine.
     */
    if (ui_->channelTree->topLevelItemCount() == 0) {
        int best_ch = 0;
        double best_score = -1.0;
        const int probe_n = qMin(stream->samples.size(), 80);
        for (int ch = 0; ch < max_ch; ch++) {
            double sum = 0.0;
            double sum_sq = 0.0;
            int n = 0;
            int zc = 0;
            int32_t prev = 0;
            bool have_prev = false;
            for (int i = 0; i < probe_n; i++) {
                const Sample &s = stream->samples[i];
                if (ch >= s.num_ch) {
                    continue;
                }
                const double v = static_cast<double>(s.values[ch]);
                sum += v;
                sum_sq += v * v;
                n++;
                if (have_prev && ((prev < 0 && s.values[ch] >= 0) || (prev >= 0 && s.values[ch] < 0))) {
                    zc++;
                }
                prev = s.values[ch];
                have_prev = true;
            }
            if (n < 8) {
                continue;
            }
            const double mean = sum / n;
            const double var = sum_sq / n - mean * mean;
            /* Prefer channels with energy and ~1–3 zero-crossings per cycle. */
            const double zc_score = (zc >= 1 && zc <= 4) ? 1.0 : (zc > 0 && zc <= 8 ? 0.3 : 0.05);
            const double score = var * zc_score;
            if (score > best_score) {
                best_score = score;
                best_ch = ch;
            }
        }
        for (int ch = 0; ch < max_ch; ch++) {
            show_ch[ch] = (ch == best_ch);
        }
    }

    for (int ch = 0; ch < max_ch; ch++) {
        QCPGraph *graph = ui_->plot->addGraph();
        graph->setName(tr("Ch %1").arg(ch));
        QColor color = ThemeManager::instance()->graphColor(ch);
        graph->setPen(QPen(color, 1.5));
        graph->setVisible(show_ch[ch]);
        graphs_.append(graph);

        QVector<double> xs;
        QVector<double> ys;

        if (rms_mode) {
            /*
             * Fixed-cycle RMS at grid frequency (default 50 Hz → 20 ms).
             * Restricted to the View/Start time window.
             */
            const double cycle = windowSeconds();
            const double t0 = stream->samples.first().t;
            const int n_samples = stream->samples.size();
            int idx = 0;

            while (idx < n_samples && stream->samples[idx].t < t_lo) {
                idx++;
            }

            while (idx < n_samples && stream->samples[idx].t < t_hi) {
                const double c_start =
                    t0 + std::floor((stream->samples[idx].t - t0) / cycle + 1e-12) * cycle;
                const double c_end = c_start + cycle;
                double sum_sq = 0.0;
                int n = 0;

                while (idx < n_samples && stream->samples[idx].t < c_end
                       && stream->samples[idx].t < t_hi) {
                    const Sample &s = stream->samples[idx];
                    if (s.t >= t_lo && ch < s.num_ch) {
                        double v = s.values[ch] * scale;
                        sum_sq += v * v;
                        n++;
                    }
                    idx++;
                }

                if (n > 0 && sum_sq >= 0.0) {
                    double rms = std::sqrt(sum_sq / static_cast<double>(n));
                    xs.append(c_start + 0.5 * cycle);
                    ys.append(rms);
                    stats[ch].count++;
                    stats[ch].rms_min = qMin(stats[ch].rms_min, rms);
                    stats[ch].rms_max = qMax(stats[ch].rms_max, rms);
                    stats[ch].rms_sum += rms;
                    stats[ch].rms_last = rms;
                }
                if (idx < n_samples && stream->samples[idx].t >= t_hi) {
                    break;
                }
            }
        } else {
            /* Instantaneous: plot raw samples only inside View window (~20 ms). */
            for (const Sample &s : stream->samples) {
                if (s.t < t_lo) {
                    continue;
                }
                if (s.t >= t_hi) {
                    break;
                }
                if (ch >= s.num_ch) {
                    continue;
                }
                double v = s.values[ch] * scale;
                xs.append(s.t);
                ys.append(v);
            }

            /* Cycle RMS stats over the same view window (50 Hz fixed cycles). */
            const double cycle = windowSeconds();
            const double t0 = stream->samples.first().t;
            int idx = 0;
            while (idx < stream->samples.size() && stream->samples[idx].t < t_lo) {
                idx++;
            }
            while (idx < stream->samples.size() && stream->samples[idx].t < t_hi) {
                const double c_start =
                    t0 + std::floor((stream->samples[idx].t - t0) / cycle + 1e-12) * cycle;
                const double c_end = c_start + cycle;
                double sum_sq = 0.0;
                int n = 0;
                while (idx < stream->samples.size() && stream->samples[idx].t < c_end
                       && stream->samples[idx].t < t_hi) {
                    const Sample &s = stream->samples[idx];
                    if (s.t >= t_lo && ch < s.num_ch) {
                        double v = s.values[ch] * scale;
                        sum_sq += v * v;
                        n++;
                    }
                    idx++;
                }
                if (n > 0 && sum_sq >= 0.0) {
                    double rms = std::sqrt(sum_sq / static_cast<double>(n));
                    stats[ch].count++;
                    stats[ch].rms_min = qMin(stats[ch].rms_min, rms);
                    stats[ch].rms_max = qMax(stats[ch].rms_max, rms);
                    stats[ch].rms_sum += rms;
                    stats[ch].rms_last = rms;
                }
            }
        }

        graph->setData(xs, ys);
    }

    ui_->plot->xAxis->setLabel(tr("Time (s)"));
    ui_->plot->yAxis->setLabel(rms_mode ? tr("RMS") : tr("Instantaneous"));
    ui_->plot->xAxis->setRange(t_lo, t_hi);
    ui_->plot->yAxis->rescale(true);
    ui_->plot->replot();

    updateChannelTable(stats);

    ui_->hintLabel->setText(
        tr("%1 samples total, %2 channels — view %3–%4 s (%5 ms) — %6")
            .arg(stream->samples.size())
            .arg(max_ch)
            .arg(t_lo, 0, 'f', 3)
            .arg(t_hi, 0, 'f', 3)
            .arg(ui_->viewMsSpin->value(), 0, 'f', 0)
            .arg(rms_mode
                     ? tr("Fixed-cycle RMS @ %1 Hz")
                           .arg(ui_->windowSpin->value())
                     : tr("Instantaneous sine (use View/Start to pan)")));
}

void SvAnalysisDialog::updateChannelTable(const QVector<ChannelStats> &stats)
{
    ui_->channelTree->blockSignals(true);
    QVector<bool> show_ch(stats.size(), true);
    for (int r = 0; r < ui_->channelTree->topLevelItemCount(); r++) {
        QTreeWidgetItem *item = ui_->channelTree->topLevelItem(r);
        int ch = item->data(1, Qt::UserRole).toInt();
        if (ch >= 0 && ch < show_ch.size()) {
            show_ch[ch] = (item->checkState(0) == Qt::Checked);
        }
    }

    ui_->channelTree->clear();
    for (const ChannelStats &st : stats) {
        auto *item = new QTreeWidgetItem(ui_->channelTree);
        item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
        item->setCheckState(0, show_ch.value(st.channel, true) ? Qt::Checked : Qt::Unchecked);
        item->setText(1, QString::number(st.channel));
        item->setData(1, Qt::UserRole, st.channel);
        item->setText(2, QString::number(st.count));
        if (st.count > 0) {
            item->setText(3, QString::number(st.rms_min, 'g', 6));
            item->setText(4, QString::number(st.rms_max, 'g', 6));
            item->setText(5, QString::number(st.rms_sum / st.count, 'g', 6));
            item->setText(6, QString::number(st.rms_last, 'g', 6));
        } else {
            item->setText(3, QChar(0x2014));
            item->setText(4, QChar(0x2014));
            item->setText(5, QChar(0x2014));
            item->setText(6, QChar(0x2014));
        }
        if (st.channel < graphs_.size()) {
            item->setForeground(1, graphs_[st.channel]->pen().color());
        }
    }
    ui_->channelTree->blockSignals(false);
}

void SvAnalysisDialog::onAppidChanged(int)
{
    computeAndDraw();
}

void SvAnalysisDialog::onRefreshClicked()
{
    retap();
}

void SvAnalysisDialog::onModeChanged(int)
{
    computeAndDraw();
}

void SvAnalysisDialog::onWindowMsChanged()
{
    /* Grid Hz affects fixed-cycle RMS used in both modes' stats/plot. */
    computeAndDraw();
}

void SvAnalysisDialog::onScaleChanged()
{
    computeAndDraw();
}

void SvAnalysisDialog::onViewRangeChanged()
{
    computeAndDraw();
}

void SvAnalysisDialog::onChannelItemChanged(QTreeWidgetItem *item, int column)
{
    if (!item || column != 0) {
        return;
    }
    int ch = item->data(1, Qt::UserRole).toInt();
    if (ch < 0 || ch >= graphs_.size()) {
        return;
    }
    graphs_[ch]->setVisible(item->checkState(0) == Qt::Checked);
    ui_->plot->replot();
}

void SvAnalysisDialog::setAllChannelsVisible(bool visible)
{
    ui_->channelTree->blockSignals(true);
    for (int r = 0; r < ui_->channelTree->topLevelItemCount(); r++) {
        QTreeWidgetItem *item = ui_->channelTree->topLevelItem(r);
        item->setCheckState(0, visible ? Qt::Checked : Qt::Unchecked);
        int ch = item->data(1, Qt::UserRole).toInt();
        if (ch >= 0 && ch < graphs_.size()) {
            graphs_[ch]->setVisible(visible);
        }
    }
    ui_->channelTree->blockSignals(false);
    ui_->plot->replot();
}

void SvAnalysisDialog::onSelectAllClicked()
{
    setAllChannelsVisible(true);
}

void SvAnalysisDialog::onSelectNoneClicked()
{
    setAllChannelsVisible(false);
}

void SvAnalysisDialog::onExportClicked()
{
    StreamInfo *stream = selectedStream();
    if (!stream || stream->samples.isEmpty()) {
        QMessageBox::information(this, tr("Export CSV"), tr("No SV data to export."));
        return;
    }

    QString path = QFileDialog::getSaveFileName(
        this, tr("Export SV CSV"),
        QStringLiteral("sv_0x%1.csv").arg(stream->appid, 4, 16, QLatin1Char('0')),
        tr("CSV files (*.csv)"));
    if (path.isEmpty()) {
        return;
    }

    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Export CSV"),
                             tr("Could not write \"%1\".").arg(path));
        return;
    }

    QTextStream out(&file);
    out << "time_s,smpCnt";
    int max_ch = 0;
    for (const Sample &s : stream->samples) {
        if (s.num_ch > max_ch) {
            max_ch = s.num_ch;
        }
    }
    for (int ch = 0; ch < max_ch; ch++) {
        out << ",ch" << ch;
    }
    out << '\n';

    const double scale = scaleFactor();
    for (const Sample &s : stream->samples) {
        out << QString::number(s.t, 'f', 9) << ',' << s.smpCnt;
        for (int ch = 0; ch < max_ch; ch++) {
            out << ',';
            if (ch < s.num_ch) {
                out << QString::number(s.values[ch] * scale, 'g', 12);
            }
        }
        out << '\n';
    }

    mainApp->pushStatus(MainApplication::TemporaryStatus,
                        tr("Exported %1 SV samples to %2.")
                            .arg(stream->samples.size())
                            .arg(path));
}
