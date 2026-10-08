/** @file
 *
 * MMS station-layer message process analysis dialog.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "mms_process_analysis_dialog.h"
#include <ui_mms_process_analysis_dialog.h>

#include "mms_process_diagram_widget.h"
#include "main_application.h"

#include <epan/packet_info.h>

#include <algorithm>

#include <QAbstractSocket>
#include <QHostAddress>
#include <QListWidget>
#include <QScrollArea>

namespace {

bool ipLessThan(const QString &a, const QString &b)
{
    const QHostAddress ha(a);
    const QHostAddress hb(b);
    if (ha.protocol() == QAbstractSocket::IPv4Protocol &&
        hb.protocol() == QAbstractSocket::IPv4Protocol) {
        return ha.toIPv4Address() < hb.toIPv4Address();
    }
    if (ha.protocol() == QAbstractSocket::IPv4Protocol &&
        hb.protocol() == QAbstractSocket::IPv6Protocol) {
        return true;
    }
    if (ha.protocol() == QAbstractSocket::IPv6Protocol &&
        hb.protocol() == QAbstractSocket::IPv4Protocol) {
        return false;
    }
    return a < b;
}

double nstimeToSeconds(const nstime_t &ts)
{
    return static_cast<double>(ts.secs) + static_cast<double>(ts.nsecs) / 1e9;
}

} // namespace

MmsProcessAnalysisDialog::MmsProcessAnalysisDialog(QWidget &parent, CaptureFile &capture_file) :
    WiresharkDialog(parent, capture_file),
    ui_(new Ui::MmsProcessAnalysisDialog),
    diagram_(nullptr)
{
    ui_->setupUi(this);
    setWindowSubtitle(tr("站控层分析"));

    diagram_ = ui_->diagramWidget;
    ui_->mainSplitter->setStretchFactor(0, 3);
    ui_->mainSplitter->setStretchFactor(1, 2);
    ui_->mainSplitter->setSizes({700, 360});
    ui_->hintLabel->setSmallText();

    connect(ui_->explainList, &QListWidget::itemClicked,
            this, &MmsProcessAnalysisDialog::onExplainItemClicked);
    connect(ui_->explainList, &QListWidget::itemDoubleClicked,
            this, &MmsProcessAnalysisDialog::onExplainItemDoubleClicked);
    connect(diagram_, &MmsProcessDiagramWidget::eventClicked,
            this, &MmsProcessAnalysisDialog::onDiagramEventClicked);

    retap();
}

MmsProcessAnalysisDialog::~MmsProcessAnalysisDialog()
{
    delete ui_;
}

void MmsProcessAnalysisDialog::captureFileClosing()
{
    removeTapListeners();
    WiresharkDialog::captureFileClosing();
}

QString MmsProcessAnalysisDialog::arrowLabelForKind(mms_process_kind_t kind)
{
    switch (kind) {
    case MMS_PROCESS_KIND_REPORT_PDU:
        return QObject::tr("报告报文");
    case MMS_PROCESS_KIND_REPORT_SERVICE:
        return QObject::tr("报告服务");
    }
    return QString();
}

QString MmsProcessAnalysisDialog::buildExplanation(const mms_process_tap_data *tap)
{
    if (!tap) {
        return QString();
    }
    QString text;
    if (tap->rcb_ref[0] != '\0') {
        text = QObject::tr("报告控制块:%1").arg(QString::fromUtf8(tap->rcb_ref));
    } else {
        text = QObject::tr("报告控制块:(未知)");
    }
    if (tap->reason_zh[0] != '\0') {
        text += QObject::tr(" 上送原因:%1").arg(QString::fromUtf8(tap->reason_zh));
    }
    return text;
}

void MmsProcessAnalysisDialog::tapReset(void *tapdata)
{
    auto *dlg = static_cast<MmsProcessAnalysisDialog *>(tapdata);
    dlg->rows_.clear();
    dlg->columns_.clear();
    dlg->col_index_.clear();
}

tap_packet_status MmsProcessAnalysisDialog::tapPacket(void *tapdata, packet_info *,
                                                      epan_dissect_t *, const void *data,
                                                      tap_flags_t)
{
    auto *dlg = static_cast<MmsProcessAnalysisDialog *>(tapdata);
    const auto *proc = static_cast<const mms_process_tap_data *>(data);
    if (!proc) {
        return TAP_PACKET_DONT_REDRAW;
    }

    EventRow row;
    row.framenum = proc->framenum;
    row.rel_secs = nstimeToSeconds(proc->rel_ts);
    row.src = QString::fromUtf8(proc->src);
    row.dst = QString::fromUtf8(proc->dst);
    row.arrow_label = arrowLabelForKind(proc->kind);
    row.explanation = buildExplanation(proc);
    dlg->rows_.append(row);

    for (const QString &ip : {row.src, row.dst}) {
        if (!ip.isEmpty() && !dlg->columns_.contains(ip)) {
            dlg->columns_.append(ip);
        }
    }

    return TAP_PACKET_DONT_REDRAW;
}

void MmsProcessAnalysisDialog::tapDraw(void *tapdata)
{
    static_cast<MmsProcessAnalysisDialog *>(tapdata)->rebuild();
}

void MmsProcessAnalysisDialog::retap()
{
    if (fileClosed()) {
        ui_->hintLabel->setText(tr("抓包文件已关闭。"));
        return;
    }
    if (!cap_file_.isValid() || !cap_file_.capFile()) {
        ui_->hintLabel->setText(tr("未打开抓包。打开含 MMS 的文件后再试。"));
        return;
    }

    beginRetapPackets();
    removeTapListeners();
    rows_.clear();
    columns_.clear();
    col_index_.clear();

    if (!registerTapListener("mms-process", this, nullptr, 0,
                             tapReset, tapPacket, tapDraw)) {
        ui_->hintLabel->setText(tr("无法挂接 MMS 过程分析。"));
        endRetapPackets();
        return;
    }

    cap_file_.retapPackets();
    removeTapListeners();
    endRetapPackets();
}

void MmsProcessAnalysisDialog::rebuild()
{
    std::sort(columns_.begin(), columns_.end(), ipLessThan);
    col_index_.clear();
    for (int i = 0; i < columns_.size(); i++) {
        col_index_.insert(columns_.at(i), i);
    }

    std::sort(rows_.begin(), rows_.end(), [](const EventRow &a, const EventRow &b) {
        if (a.rel_secs != b.rel_secs) {
            return a.rel_secs < b.rel_secs;
        }
        return a.framenum < b.framenum;
    });

    ui_->explainList->clear();
    QVector<MmsProcessDiagramEvent> diagram_events;
    diagram_events.reserve(rows_.size());

    for (int i = 0; i < rows_.size(); i++) {
        EventRow &row = rows_[i];
        row.list_row = i;
        row.src_col = col_index_.value(row.src, 0);
        row.dst_col = col_index_.value(row.dst, 0);

        auto *item = new QListWidgetItem(row.explanation);
        item->setData(Qt::UserRole, i);
        ui_->explainList->addItem(item);

        MmsProcessDiagramEvent dev;
        dev.index = i;
        dev.rel_secs = row.rel_secs;
        dev.src = row.src;
        dev.dst = row.dst;
        dev.arrow_label = row.arrow_label;
        dev.src_col = row.src_col;
        dev.dst_col = row.dst_col;
        diagram_events.append(dev);
    }

    diagram_->setColumns(columns_);
    diagram_->setEvents(diagram_events);
    diagram_->setMinimumHeight(qMax(200, rows_.size() * 26 + 40));
    diagram_->updateGeometry();

    if (rows_.isEmpty()) {
        ui_->hintLabel->setText(tr("当前抓包中未找到 MMS 站控层报告事件。"));
    } else {
        ui_->hintLabel->setText(tr("共 %1 条事件，%2 个 IP。双击说明行可跳转到对应报文。")
                                    .arg(rows_.size())
                                    .arg(columns_.size()));
    }
}

void MmsProcessAnalysisDialog::selectIndex(int index)
{
    if (index < 0 || index >= rows_.size()) {
        return;
    }
    diagram_->setSelectedIndex(index);
    ui_->explainList->setCurrentRow(index);
    ui_->hintLabel->setText(tr("帧 %1 — 双击可跳转").arg(rows_.at(index).framenum));
}

void MmsProcessAnalysisDialog::onExplainItemClicked(QListWidgetItem *item)
{
    if (!item) {
        return;
    }
    selectIndex(item->data(Qt::UserRole).toInt());
}

void MmsProcessAnalysisDialog::onExplainItemDoubleClicked(QListWidgetItem *item)
{
    if (!item) {
        return;
    }
    const int index = item->data(Qt::UserRole).toInt();
    if (index < 0 || index >= rows_.size()) {
        return;
    }
    selectIndex(index);
    mainApp->gotoFrame(static_cast<int>(rows_.at(index).framenum));
}

void MmsProcessAnalysisDialog::onDiagramEventClicked(int index)
{
    selectIndex(index);
}
