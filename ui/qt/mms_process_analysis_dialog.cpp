/** @file
 *
 * MMS station-layer message process analysis dialog.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "mms_process_analysis_dialog.h"
#include <ui_mms_process_analysis_dialog.h>

#include "mms_process_diagram_widget.h"
#include "mms_process_time_column_widget.h"
#include "main_application.h"

#include <epan/packet_info.h>

#include <algorithm>

#include <QAbstractSocket>
#include <QColorDialog>
#include <QComboBox>
#include <QFrame>
#include <QHostAddress>
#include <QListWidget>
#include <QPalette>
#include <QResizeEvent>
#include <QScrollArea>
#include <QScrollBar>
#include <QSettings>
#include <QSignalBlocker>

namespace {

constexpr char kBgColorSettingKey[] = "MmsProcessAnalysis/backgroundColor";

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

struct NamedColor {
    const char *name;
    QRgb rgb;
};

const NamedColor kPresetColors[] = {
    {"浅绿", qRgb(0xE8, 0xF5, 0xE9)},
    {"白色", qRgb(0xFF, 0xFF, 0xFF)},
    {"浅黄", qRgb(0xFF, 0xF8, 0xE1)},
    {"浅蓝", qRgb(0xE3, 0xF2, 0xFD)},
    {"浅灰", qRgb(0xF5, 0xF5, 0xF5)},
    {"米色", qRgb(0xFA, 0xF0, 0xE6)},
};

} // namespace

MmsProcessAnalysisDialog::MmsProcessAnalysisDialog(QWidget &parent, CaptureFile &capture_file) :
    WiresharkDialog(parent, capture_file),
    ui_(new Ui::MmsProcessAnalysisDialog),
    diagram_(nullptr),
    time_column_(nullptr),
    background_color_(0xE8, 0xF5, 0xE9)
{
    ui_->setupUi(this);
    setWindowSubtitle(tr("站控层分析"));

    diagram_ = ui_->diagramWidget;
    time_column_ = ui_->timeColumn;

    ui_->verticalLayout->setStretch(0, 0);
    ui_->verticalLayout->setStretch(1, 1);
    ui_->verticalLayout->setStretch(2, 0);
    ui_->mainSplitter->setStretchFactor(0, 3);
    ui_->mainSplitter->setStretchFactor(1, 2);
    ui_->mainSplitter->setSizes({700, 360});
    ui_->hintLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    ui_->hintLabel->setMaximumHeight(24);
    ui_->hintLabel->setSmallText();

    ui_->diagramPanelLayout->setStretch(0, 0);
    ui_->diagramPanelLayout->setStretch(1, 1);
    ui_->timeVScroll->setFixedWidth(MmsProcessTimeColumnWidget::preferredWidth());
    ui_->timeVScroll->setWidget(time_column_);
    ui_->diagramScroll->setWidget(diagram_);

    initBackgroundColorCombo();

    connect(ui_->explainList, &QListWidget::itemClicked,
            this, &MmsProcessAnalysisDialog::onExplainItemClicked);
    connect(ui_->explainList, &QListWidget::itemDoubleClicked,
            this, &MmsProcessAnalysisDialog::onExplainItemDoubleClicked);
    connect(ui_->explainList, &QListWidget::itemActivated,
            this, &MmsProcessAnalysisDialog::onExplainItemDoubleClicked);
    connect(diagram_, &MmsProcessDiagramWidget::eventClicked,
            this, &MmsProcessAnalysisDialog::onDiagramEventClicked);
    connect(diagram_, &MmsProcessDiagramWidget::eventDoubleClicked,
            this, &MmsProcessAnalysisDialog::onDiagramEventDoubleClicked);
    connect(ui_->bgColorCombo, QOverload<int>::of(&QComboBox::activated),
            this, &MmsProcessAnalysisDialog::onBackgroundColorChanged);

    /* Keep time column vertically aligned with the diagram; only the diagram scrolls horizontally. */
    connect(ui_->diagramScroll->verticalScrollBar(), &QScrollBar::valueChanged,
            ui_->timeVScroll->verticalScrollBar(), &QScrollBar::setValue);
    connect(ui_->timeVScroll->verticalScrollBar(), &QScrollBar::valueChanged,
            ui_->diagramScroll->verticalScrollBar(), &QScrollBar::setValue);

    retap();
}

MmsProcessAnalysisDialog::~MmsProcessAnalysisDialog()
{
    delete ui_;
}

void MmsProcessAnalysisDialog::initBackgroundColorCombo()
{
    QSettings settings;
    const QString saved = settings.value(kBgColorSettingKey).toString();
    if (!saved.isEmpty()) {
        const QColor c(saved);
        if (c.isValid()) {
            background_color_ = c;
        }
    }

    {
        QSignalBlocker blocker(ui_->bgColorCombo);
        ui_->bgColorCombo->clear();
        int select = 0;
        const int preset_count = static_cast<int>(sizeof(kPresetColors) / sizeof(kPresetColors[0]));
        for (int i = 0; i < preset_count; i++) {
            const QColor c(kPresetColors[i].rgb);
            ui_->bgColorCombo->addItem(QString::fromUtf8(kPresetColors[i].name), c);
            if (c == background_color_) {
                select = i;
            }
        }
        ui_->bgColorCombo->addItem(tr("自定义…"), QVariant());
        bool matched = false;
        for (int i = 0; i < preset_count; i++) {
            if (QColor(kPresetColors[i].rgb) == background_color_) {
                matched = true;
                break;
            }
        }
        if (!matched) {
            const int custom_idx = ui_->bgColorCombo->count() - 1;
            ui_->bgColorCombo->insertItem(custom_idx, tr("当前自定义"), background_color_);
            select = custom_idx;
        }
        ui_->bgColorCombo->setCurrentIndex(select);
    }

    applyBackgroundColor(background_color_, false);
}

void MmsProcessAnalysisDialog::applyBackgroundColor(const QColor &color, bool persist)
{
    if (!color.isValid()) {
        return;
    }
    background_color_ = color;
    if (diagram_) {
        diagram_->setBackgroundColor(color);
    }
    if (time_column_) {
        time_column_->setBackgroundColor(color);
    }
    if (ui_) {
        for (QScrollArea *area : {ui_->timeVScroll, ui_->diagramScroll}) {
            if (!area || !area->viewport()) {
                continue;
            }
            area->viewport()->setAutoFillBackground(true);
            QPalette pal = area->viewport()->palette();
            pal.setColor(QPalette::Window, color);
            area->viewport()->setPalette(pal);
        }
    }
    if (persist) {
        QSettings settings;
        settings.setValue(kBgColorSettingKey, color.name(QColor::HexRgb));
    }
}

void MmsProcessAnalysisDialog::onBackgroundColorChanged(int index)
{
    if (index < 0) {
        return;
    }
    const QVariant data = ui_->bgColorCombo->itemData(index);
    if (!data.isValid()) {
        const QColor picked = QColorDialog::getColor(background_color_, this, tr("选择背景色"));
        if (!picked.isValid()) {
            initBackgroundColorCombo();
            return;
        }
        applyBackgroundColor(picked, true);
        initBackgroundColorCombo();
        return;
    }
    applyBackgroundColor(data.value<QColor>(), true);
}

void MmsProcessAnalysisDialog::captureFileClosing()
{
    removeTapListeners();
    WiresharkDialog::captureFileClosing();
}

void MmsProcessAnalysisDialog::resizeEvent(QResizeEvent *event)
{
    WiresharkDialog::resizeEvent(event);
    syncDiagramSize();
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
    const QString reason = QString::fromUtf8(tap->reason_zh).trimmed();
    if (!reason.isEmpty()) {
        text += QObject::tr(" 上送原因:%1").arg(reason);
    }
    /* Enumerate leaf values for spontaneous (data-change) reports: [0.5,0.7] */
    if (reason.contains(QStringLiteral("突发性")) && tap->values[0] != '\0') {
        QString vals = QString::fromUtf8(tap->values).trimmed();
        vals.replace(QStringLiteral(", "), QStringLiteral(","));
        while (vals.contains(QStringLiteral(",,"))) {
            vals.replace(QStringLiteral(",,"), QStringLiteral(","));
        }
        if (vals.startsWith(QLatin1Char(','))) {
            vals.remove(0, 1);
        }
        if (vals.endsWith(QLatin1Char(','))) {
            vals.chop(1);
        }
        if (!vals.isEmpty()) {
            text += QStringLiteral(" [%1]").arg(vals);
        }
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
    time_column_->setEvents(diagram_events);
    syncDiagramSize();

    if (rows_.isEmpty()) {
        ui_->hintLabel->setText(tr("当前抓包中未找到 MMS 站控层报告事件。"));
    } else {
        ui_->hintLabel->setText(tr("共 %1 条事件，%2 个 IP。双击说明行或时序图可跳转到对应报文。")
                                    .arg(rows_.size())
                                    .arg(columns_.size()));
    }
}

void MmsProcessAnalysisDialog::syncDiagramSize()
{
    if (!diagram_ || !time_column_ || !ui_) {
        return;
    }

    const int time_w = MmsProcessTimeColumnWidget::preferredWidth();
    const int diagram_view_w = qMax(1, ui_->diagramScroll->viewport()->width());
    const int diagram_view_h = qMax(1, ui_->diagramScroll->viewport()->height());

    const QSize diagram_hint = diagram_->sizeHint();
    const int content_h = qMax(200, diagram_hint.height());
    /* Fill viewport when few events, so no white gap below the sequence. */
    const int h = qMax(content_h, diagram_view_h);
    const int diagram_w = qMax(diagram_hint.width(), diagram_view_w);

    time_column_->setFixedSize(time_w, h);
    diagram_->setFixedSize(diagram_w, h);
    ui_->timeVScroll->setFixedWidth(time_w);

    if (ui_->timeVScroll->widget() != time_column_) {
        ui_->timeVScroll->setWidget(time_column_);
    }
    if (ui_->diagramScroll->widget() != diagram_) {
        ui_->diagramScroll->setWidget(diagram_);
    }

    /* Keep vertical scroll ranges in sync. */
    QScrollBar *dv = ui_->diagramScroll->verticalScrollBar();
    QScrollBar *tv = ui_->timeVScroll->verticalScrollBar();
    if (dv && tv) {
        tv->setRange(dv->minimum(), dv->maximum());
        tv->setPageStep(dv->pageStep());
        tv->setSingleStep(dv->singleStep());
        tv->setValue(dv->value());
    }
}

void MmsProcessAnalysisDialog::jumpToFrame(uint32_t framenum)
{
    if (framenum == 0) {
        return;
    }
    emit goToPacket(static_cast<int>(framenum));
    mainApp->gotoFrame(static_cast<int>(framenum));
}

void MmsProcessAnalysisDialog::selectIndex(int index)
{
    if (index < 0 || index >= rows_.size()) {
        return;
    }
    diagram_->setSelectedIndex(index);
    time_column_->setSelectedIndex(index);
    ui_->explainList->setCurrentRow(index);
    if (QListWidgetItem *item = ui_->explainList->item(index)) {
        ui_->explainList->scrollToItem(item);
    }

    const int row_top = MmsProcessDiagramWidget::topMargin() +
                        index * MmsProcessDiagramWidget::rowHeight();
    if (QScrollBar *vbar = ui_->diagramScroll->verticalScrollBar()) {
        const int view_h = ui_->diagramScroll->viewport()->height();
        if (row_top < vbar->value() ||
            row_top + MmsProcessDiagramWidget::rowHeight() > vbar->value() + view_h) {
            vbar->setValue(qMax(0, row_top - view_h / 3));
        }
    }

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
    jumpToFrame(rows_.at(index).framenum);
}

void MmsProcessAnalysisDialog::onDiagramEventClicked(int index)
{
    selectIndex(index);
}

void MmsProcessAnalysisDialog::onDiagramEventDoubleClicked(int index)
{
    if (index < 0 || index >= rows_.size()) {
        return;
    }
    selectIndex(index);
    jumpToFrame(rows_.at(index).framenum);
}
