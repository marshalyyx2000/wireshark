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

#include <QAbstractItemView>
#include <QAbstractSocket>
#include <QColorDialog>
#include <QComboBox>
#include <QFrame>
#include <QHostAddress>
#include <QLineEdit>
#include <QListWidget>
#include <QPalette>
#include <QRegularExpression>
#include <QResizeEvent>
#include <QScrollArea>
#include <QScrollBar>
#include <QSettings>
#include <QSignalBlocker>
#include <QSet>

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
    setWindowSubtitle(tr("MMS服务过程分析"));

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

    /* Align 说明 rows with diagram: same top margin + row height, pixel scroll. */
    ui_->explainGroup->setTitle(QString());
    ui_->explainGroup->setFlat(true);
    ui_->explainLayout->setContentsMargins(0, 0, 0, 0);
    ui_->explainLayout->setSpacing(0);
    ui_->explainList->setUniformItemSizes(false);
    ui_->explainList->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    ui_->explainList->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    ui_->explainList->setSpacing(0);
    ui_->explainList->setFrameShape(QFrame::NoFrame);

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
    connect(ui_->searchEdit, &QLineEdit::textChanged,
            this, &MmsProcessAnalysisDialog::onSearchTextChanged);

    /* Keep time column, diagram, and explain list vertically aligned. */
    connect(ui_->diagramScroll->verticalScrollBar(), &QScrollBar::valueChanged,
            this, &MmsProcessAnalysisDialog::onDiagramVerticalScroll);
    connect(ui_->timeVScroll->verticalScrollBar(), &QScrollBar::valueChanged,
            ui_->diagramScroll->verticalScrollBar(), &QScrollBar::setValue);
    connect(ui_->explainList->verticalScrollBar(), &QScrollBar::valueChanged,
            this, &MmsProcessAnalysisDialog::onExplainVerticalScroll);

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
    case MMS_PROCESS_KIND_REPORT_SERVICE:
        return QObject::tr("报告服务");
    case MMS_PROCESS_KIND_REQUEST:
        return QObject::tr("请求");
    case MMS_PROCESS_KIND_RESPONSE:
        return QObject::tr("回复");
    }
    return QString();
}

QString MmsProcessAnalysisDialog::buildExplanation(const mms_process_tap_data *tap)
{
    if (!tap) {
        return QString();
    }

    if (tap->kind == MMS_PROCESS_KIND_REQUEST) {
        const QString obj = tap->object_ref[0] != '\0'
                                ? QString::fromUtf8(tap->object_ref)
                                : (tap->rcb_ref[0] != '\0'
                                       ? QString::fromUtf8(tap->rcb_ref)
                                       : QObject::tr("(未知)"));
        return QObject::tr("请求对象: %1").arg(obj);
    }

    if (tap->kind == MMS_PROCESS_KIND_RESPONSE) {
        const QString result = QString::fromUtf8(tap->result_zh).trimmed();
        if (!result.isEmpty()) {
            return result;
        }
        return QObject::tr("失败");
    }

    /* Report PDU / legacy report-service */
    QString text;
    if (tap->rcb_ref[0] != '\0') {
        text = QObject::tr("报告控制块:%1").arg(QString::fromUtf8(tap->rcb_ref));
    } else {
        text = QObject::tr("报告控制块:(未知)");
    }
    QString reason = QString::fromUtf8(tap->reason_zh).trimmed();
    /* Align display wording with legacy MMS process UI. */
    reason.replace(QStringLiteral("周期性"), QStringLiteral("周期上送"));
    reason.replace(QStringLiteral("突发性"), QStringLiteral("突发上送"));
    if (!reason.isEmpty()) {
        text += QObject::tr(" 上送原因:%1").arg(reason);
    }
    /* Enumerate leaf values for spontaneous (data-change) reports: [0.5,0.7] */
    if (reason.contains(QStringLiteral("突发")) && tap->values[0] != '\0') {
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

QString MmsProcessAnalysisDialog::normalizeRefForSearch(const QString &ref)
{
    QString s = ref.trimmed().toLower();
    s.replace(QLatin1Char('/'), QLatin1Char('$'));
    s.replace(QLatin1Char('.'), QLatin1Char('$'));
    return s;
}

QStringList MmsProcessAnalysisDialog::parseSearchTokens(const QString &text)
{
    const QStringList raw = text.split(QRegularExpression(QStringLiteral("\\s+")),
                                       Qt::SkipEmptyParts);
    QStringList tokens;
    tokens.reserve(raw.size());
    for (const QString &t : raw) {
        const QString n = normalizeRefForSearch(t);
        if (!n.isEmpty()) {
            tokens.append(n);
        }
    }
    return tokens;
}

bool MmsProcessAnalysisDialog::refsMatchTokens(const QString &search_refs,
                                               const QStringList &tokens)
{
    if (tokens.isEmpty()) {
        return true;
    }
    const QString hay = normalizeRefForSearch(search_refs);
    if (hay.isEmpty()) {
        return false;
    }
    for (const QString &tok : tokens) {
        if (!hay.contains(tok)) {
            return false;
        }
    }
    return true;
}

void MmsProcessAnalysisDialog::tapReset(void *tapdata)
{
    auto *dlg = static_cast<MmsProcessAnalysisDialog *>(tapdata);
    dlg->all_rows_.clear();
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
    const QString tap_label = QString::fromUtf8(proc->arrow_label).trimmed();
    row.arrow_label = tap_label.isEmpty() ? arrowLabelForKind(proc->kind) : tap_label;
    row.explanation = buildExplanation(proc);
    row.kind = proc->kind;
    row.has_invoke_id = proc->has_invoke_id;
    row.invoke_id = proc->invoke_id;
    row.search_refs = QString::fromUtf8(proc->search_refs).trimmed();
    if (row.search_refs.isEmpty()) {
        QStringList parts;
        const QString obj = QString::fromUtf8(proc->object_ref).trimmed();
        const QString rcb = QString::fromUtf8(proc->rcb_ref).trimmed();
        const QString ds = QString::fromUtf8(proc->dataset_ref).trimmed();
        if (!obj.isEmpty()) {
            parts << obj;
        }
        if (!rcb.isEmpty()) {
            parts << rcb;
        }
        if (!ds.isEmpty()) {
            parts << ds;
        }
        row.search_refs = parts.join(QLatin1Char(' '));
    }
    dlg->all_rows_.append(row);

    return TAP_PACKET_DONT_REDRAW;
}

void MmsProcessAnalysisDialog::tapDraw(void *tapdata)
{
    static_cast<MmsProcessAnalysisDialog *>(tapdata)->applyFilterAndRefresh();
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
    all_rows_.clear();
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

void MmsProcessAnalysisDialog::onSearchTextChanged(const QString &)
{
    applyFilterAndRefresh();
}

void MmsProcessAnalysisDialog::applyFilterAndRefresh()
{
    const QStringList tokens = parseSearchTokens(ui_->searchEdit->text());

    std::sort(all_rows_.begin(), all_rows_.end(), [](const EventRow &a, const EventRow &b) {
        if (a.rel_secs != b.rel_secs) {
            return a.rel_secs < b.rel_secs;
        }
        return a.framenum < b.framenum;
    });

    rows_.clear();
    columns_.clear();
    col_index_.clear();

    if (tokens.isEmpty()) {
        rows_ = all_rows_;
    } else {
        QSet<uint32_t> matched_invokes;
        QVector<bool> hit(all_rows_.size(), false);

        for (int i = 0; i < all_rows_.size(); i++) {
            const EventRow &row = all_rows_.at(i);
            if (!refsMatchTokens(row.search_refs, tokens)) {
                continue;
            }
            hit[i] = true;
            if (row.kind == MMS_PROCESS_KIND_REQUEST && row.has_invoke_id) {
                matched_invokes.insert(row.invoke_id);
            }
        }
        /* Request hit → also show paired response (same invokeID). */
        if (!matched_invokes.isEmpty()) {
            for (int i = 0; i < all_rows_.size(); i++) {
                const EventRow &row = all_rows_.at(i);
                if (row.kind == MMS_PROCESS_KIND_RESPONSE && row.has_invoke_id &&
                    matched_invokes.contains(row.invoke_id)) {
                    hit[i] = true;
                }
            }
        }
        for (int i = 0; i < all_rows_.size(); i++) {
            if (hit.at(i)) {
                rows_.append(all_rows_.at(i));
            }
        }
    }

    for (const EventRow &row : rows_) {
        for (const QString &ip : {row.src, row.dst}) {
            if (!ip.isEmpty() && !columns_.contains(ip)) {
                columns_.append(ip);
            }
        }
    }

    rebuild();
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

    /* Header spacer matches diagram/time-column topMargin so row 0 lines up. */
    auto *header = new QListWidgetItem(tr("说明"));
    header->setFlags(Qt::NoItemFlags);
    header->setTextAlignment(Qt::AlignCenter);
    header->setSizeHint(QSize(0, MmsProcessDiagramWidget::topMargin()));
    {
        QFont hf = ui_->explainList->font();
        hf.setBold(true);
        header->setFont(hf);
    }
    ui_->explainList->addItem(header);

    const int row_h = MmsProcessDiagramWidget::rowHeight();
    for (int i = 0; i < rows_.size(); i++) {
        EventRow &row = rows_[i];
        row.list_row = i;
        row.src_col = col_index_.value(row.src, 0);
        row.dst_col = col_index_.value(row.dst, 0);

        auto *item = new QListWidgetItem(row.explanation);
        item->setData(Qt::UserRole, i);
        item->setSizeHint(QSize(0, row_h));
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

    /* Trailing spacer matches diagram bottomMargin so scroll ranges stay equal. */
    auto *footer = new QListWidgetItem;
    footer->setFlags(Qt::NoItemFlags);
    footer->setSizeHint(QSize(0, 12));
    ui_->explainList->addItem(footer);

    diagram_->setColumns(columns_);
    diagram_->setEvents(diagram_events);
    time_column_->setEvents(diagram_events);
    syncDiagramSize();

    const QStringList tokens = parseSearchTokens(ui_->searchEdit->text());
    if (all_rows_.isEmpty()) {
        ui_->hintLabel->setText(tr("当前抓包中未找到 MMS 站控层过程事件。"));
    } else if (!tokens.isEmpty()) {
        ui_->hintLabel->setText(tr("参引搜索：显示 %1 / %2 条（按时序）。双击可跳转报文。")
                                    .arg(rows_.size())
                                    .arg(all_rows_.size()));
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

    /* Keep vertical scroll ranges in sync across time / diagram / explain. */
    QScrollBar *dv = ui_->diagramScroll->verticalScrollBar();
    QScrollBar *tv = ui_->timeVScroll->verticalScrollBar();
    QScrollBar *ev = ui_->explainList->verticalScrollBar();
    if (dv && tv) {
        tv->setRange(dv->minimum(), dv->maximum());
        tv->setPageStep(dv->pageStep());
        tv->setSingleStep(dv->singleStep());
        tv->setValue(dv->value());
    }
    if (dv && ev) {
        /* Explain list content height tracks diagram rows; clamp to diagram range. */
        ev->setSingleStep(dv->singleStep());
        ev->setPageStep(dv->pageStep());
        if (ev->value() != dv->value()) {
            ev->setValue(dv->value());
        }
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
    /* Row 0 is the "说明" header spacer. */
    const int list_row = index + 1;
    ui_->explainList->setCurrentRow(list_row);
    if (QListWidgetItem *item = ui_->explainList->item(list_row)) {
        ui_->explainList->scrollToItem(item, QAbstractItemView::PositionAtCenter);
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

void MmsProcessAnalysisDialog::onDiagramVerticalScroll(int value)
{
    if (QScrollBar *tv = ui_->timeVScroll->verticalScrollBar()) {
        if (tv->value() != value) {
            tv->setValue(value);
        }
    }
    if (QScrollBar *ev = ui_->explainList->verticalScrollBar()) {
        if (ev->value() != value) {
            ev->setValue(value);
        }
    }
}

void MmsProcessAnalysisDialog::onExplainVerticalScroll(int value)
{
    if (QScrollBar *dv = ui_->diagramScroll->verticalScrollBar()) {
        if (dv->value() != value) {
            dv->setValue(value);
        }
    }
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
