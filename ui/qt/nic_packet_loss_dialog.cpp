/** @file
 *
 * Common tool: detect NIC / path packet loss via timed ping with MTU-sized payload.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "nic_packet_loss_dialog.h"
#include <ui_nic_packet_loss_dialog.h>

#include <QAbstractSocket>
#include <QCloseEvent>
#include <QFile>
#include <QFileDialog>
#include <QHostAddress>
#include <QMessageBox>
#include <QRegularExpression>
#include <QTextStream>
#include <QTimer>
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
#include <QStringConverter>
#else
#include <QTextCodec>
#endif

NicPacketLossDialog::NicPacketLossDialog(QWidget &parent) :
    QDialog(&parent),
    ui_(new Ui::NicPacketLossDialog),
    ping_process_(new QProcess(this)),
    running_(false),
    stop_requested_(false),
    mtu_(1500),
    duration_minutes_(1),
    sent_(0),
    received_(0),
    lost_(0)
{
    ui_->setupUi(this);
    setWindowTitle(tr("判断网卡是否丢包"));

    connect(ui_->startButton, &QPushButton::clicked, this, &NicPacketLossDialog::onStartClicked);
    connect(ui_->stopButton, &QPushButton::clicked, this, &NicPacketLossDialog::onStopClicked);
    connect(ui_->saveButton, &QPushButton::clicked, this, &NicPacketLossDialog::onSaveReportClicked);
    connect(ping_process_, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &NicPacketLossDialog::onPingFinished);
    connect(ping_process_, &QProcess::errorOccurred, this, &NicPacketLossDialog::onPingError);

    ping_process_->setProcessChannelMode(QProcess::MergedChannels);
}

NicPacketLossDialog::~NicPacketLossDialog()
{
    if (ping_process_->state() != QProcess::NotRunning) {
        ping_process_->kill();
        ping_process_->waitForFinished(1000);
    }
    delete ui_;
}

void NicPacketLossDialog::closeEvent(QCloseEvent *event)
{
    if (running_) {
        const auto answer = QMessageBox::question(this, tr("检测进行中"),
            tr("检测尚未结束，确定停止并关闭？"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (answer != QMessageBox::Yes) {
            event->ignore();
            return;
        }
        stop_requested_ = true;
        if (ping_process_->state() != QProcess::NotRunning) {
            ping_process_->kill();
            ping_process_->waitForFinished(1000);
        }
        setRunning(false);
    }
    QDialog::closeEvent(event);
}

int NicPacketLossDialog::payloadSize() const
{
    // IPv4 header (20) + ICMP echo header (8)
    return qMax(0, mtu_ - 28);
}

void NicPacketLossDialog::setRunning(bool running)
{
    running_ = running;
    ui_->startButton->setEnabled(!running);
    ui_->stopButton->setEnabled(running);
    ui_->ipEdit->setEnabled(!running);
    ui_->mtuSpin->setEnabled(!running);
    ui_->durationSpin->setEnabled(!running);
    ui_->closeButton->setEnabled(!running);
}

void NicPacketLossDialog::onStartClicked()
{
    const QString ip = ui_->ipEdit->text().trimmed();
    QHostAddress addr;
    if (ip.isEmpty() || !addr.setAddress(ip)) {
        QMessageBox::warning(this, tr("参数错误"), tr("请输入有效的 IP 地址。"));
        return;
    }
    if (addr.protocol() != QAbstractSocket::IPv4Protocol) {
        QMessageBox::warning(this, tr("参数错误"),
            tr("当前检测使用 IPv4 ping（载荷 = MTU−28）。请输入 IPv4 地址。"));
        return;
    }

    target_ip_ = addr.toString();
    mtu_ = ui_->mtuSpin->value();
    duration_minutes_ = ui_->durationSpin->value();
    if (payloadSize() <= 0) {
        QMessageBox::warning(this, tr("参数错误"), tr("MTU 过小，无法构造 ICMP 载荷。"));
        return;
    }

    sent_ = 0;
    received_ = 0;
    lost_ = 0;
    loss_details_.clear();
    stop_requested_ = false;
    ui_->reportEdit->clear();
    ui_->saveButton->setEnabled(false);
    ui_->progressBar->setValue(0);

    start_time_ = QDateTime::currentDateTime();
    end_time_ = start_time_.addSecs(duration_minutes_ * 60);

    setRunning(true);
    updateStatus();
    startNextPing();
}

void NicPacketLossDialog::onStopClicked()
{
    if (!running_) {
        return;
    }
    stop_requested_ = true;
    ui_->statusLabel->setText(tr("正在停止…"));
    if (ping_process_->state() != QProcess::NotRunning) {
        ping_process_->kill();
    } else {
        finishTest();
    }
}

void NicPacketLossDialog::startNextPing()
{
    if (!running_) {
        return;
    }
    if (stop_requested_ || QDateTime::currentDateTime() >= end_time_) {
        finishTest();
        return;
    }

    const QStringList args = {
        QStringLiteral("-n"), QStringLiteral("1"),
        QStringLiteral("-l"), QString::number(payloadSize()),
        QStringLiteral("-f"),
        QStringLiteral("-w"), QStringLiteral("1000"),
        target_ip_
    };
    ping_process_->start(QStringLiteral("ping"), args);
}

void NicPacketLossDialog::onPingError()
{
    if (!running_) {
        return;
    }
    if (ping_process_->error() == QProcess::FailedToStart) {
        setRunning(false);
        ui_->statusLabel->setText(tr("启动失败"));
        QMessageBox::critical(this, tr("启动失败"),
            tr("无法启动 ping 命令，请确认系统已安装并可用。\n%1")
                .arg(ping_process_->errorString()));
        return;
    }
    // Treat process crash as a lost sample and continue until time is up
    sent_++;
    lost_++;
    loss_details_.append(tr("%1  第 %2 次  ping 进程错误：%3")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")))
        .arg(sent_)
        .arg(ping_process_->errorString()));
    updateStatus();

    if (stop_requested_ || QDateTime::currentDateTime() >= end_time_) {
        finishTest();
        return;
    }
    QTimer::singleShot(200, this, &NicPacketLossDialog::startNextPing);
}

bool NicPacketLossDialog::isPingReplyOk(const QString &output) const
{
    // Success: English "TTL=" / Chinese reply with time+TTL
    static const QRegularExpression ttl_re(
        QStringLiteral("\\bTTL="),
        QRegularExpression::CaseInsensitiveOption);
    if (ttl_re.match(output).hasMatch()) {
        return true;
    }
    // Chinese Windows: "字节=... 时间=...ms TTL=..." already covered by TTL=
    // Explicit failure markers
    static const QRegularExpression fail_re(
        QStringLiteral(
            "请求超时|timed out|无法访问|unreachable|transmit failed|"
            "general failure|needs to be fragmented|Must fragment|"
            "碎片|找不到主机|could not find host|unknown host"),
        QRegularExpression::CaseInsensitiveOption);
    if (fail_re.match(output).hasMatch()) {
        return false;
    }
    return false;
}

void NicPacketLossDialog::onPingFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    Q_UNUSED(exitCode);

    if (!running_) {
        return;
    }

    const QString output = QString::fromLocal8Bit(ping_process_->readAllStandardOutput());
    const QDateTime now = QDateTime::currentDateTime();
    sent_++;

    const bool ok = (exitStatus == QProcess::NormalExit) && isPingReplyOk(output);
    if (ok) {
        received_++;
    } else {
        lost_++;
        QString reason = tr("无有效回复");
        const QString trimmed = output.trimmed().simplified();
        if (!trimmed.isEmpty()) {
            // Keep one concise line from ping output
            reason = trimmed.section(QLatin1Char('\n'), 0, 0).trimmed();
            if (reason.size() > 160) {
                reason = reason.left(160) + QLatin1String("…");
            }
        }
        loss_details_.append(tr("%1  第 %2 次  %3")
            .arg(now.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")))
            .arg(sent_)
            .arg(reason));
    }

    updateStatus();

    if (stop_requested_ || now >= end_time_) {
        finishTest();
        return;
    }

    // Small gap so UI stays responsive; ~1 ping/sec cadence with -w 1000
    QTimer::singleShot(0, this, &NicPacketLossDialog::startNextPing);
}

void NicPacketLossDialog::updateStatus()
{
    const qint64 total_ms = start_time_.msecsTo(end_time_);
    const qint64 elapsed_ms = start_time_.msecsTo(QDateTime::currentDateTime());
    int pct = 0;
    if (total_ms > 0) {
        pct = static_cast<int>(qBound(0LL, (elapsed_ms * 100) / total_ms, 100LL));
    }
    ui_->progressBar->setValue(pct);

    const double loss_pct = sent_ > 0 ? (100.0 * lost_ / sent_) : 0.0;
    const qint64 remain_sec = qMax(0LL, QDateTime::currentDateTime().secsTo(end_time_));
    ui_->statusLabel->setText(tr("目标 %1 | MTU %2 (载荷 %3) | 已发送 %4  接收 %5  丢失 %6 (%7%) | 剩余约 %8 秒")
        .arg(target_ip_)
        .arg(mtu_)
        .arg(payloadSize())
        .arg(sent_)
        .arg(received_)
        .arg(lost_)
        .arg(loss_pct, 0, 'f', 1)
        .arg(remain_sec));
}

QString NicPacketLossDialog::buildReport() const
{
    const double loss_pct = sent_ > 0 ? (100.0 * lost_ / sent_) : 0.0;
    QString text;
    text += tr("网卡/路径丢包检测报告\n");
    text += tr("====================\n");
    text += tr("目标 IP：%1\n").arg(target_ip_);
    text += tr("MTU：%1 字节（ping 载荷 %2，勿分片）\n").arg(mtu_).arg(payloadSize());
    text += tr("计划时长：%1 分钟\n").arg(duration_minutes_);
    text += tr("开始时间：%1\n").arg(start_time_.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")));
    text += tr("结束时间：%1\n").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")));
    text += tr("统计：已发送 %1，已接收 %2，丢失 %3（%4%）\n")
        .arg(sent_).arg(received_).arg(lost_).arg(loss_pct, 0, 'f', 2);
    text += QLatin1Char('\n');
    if (lost_ == 0) {
        text += tr("结论：未检测到丢包，一切正常。\n");
    } else {
        text += tr("结论：检测到丢包。详情如下：\n\n");
        for (const QString &line : loss_details_) {
            text += line;
            text += QLatin1Char('\n');
        }
    }
    return text;
}

QString NicPacketLossDialog::defaultReportFileName() const
{
    const QString stamp = start_time_.toString(QStringLiteral("yyyyMMdd_HHmmss"));
    QString ip = target_ip_;
    ip.replace(QLatin1Char(':'), QLatin1Char('-'));
    return QStringLiteral("%1_%2.txt").arg(stamp, ip);
}

void NicPacketLossDialog::finishTest()
{
    setRunning(false);
    ui_->progressBar->setValue(100);
    updateStatus();

    if (lost_ == 0 && sent_ > 0) {
        ui_->reportEdit->clear();
        ui_->saveButton->setEnabled(false);
        ui_->statusLabel->setText(tr("检测完成：一切正常，未检测到丢包。"));
        QMessageBox::information(this, tr("检测完成"),
            tr("目标 %1 在 %2 分钟检测中一切正常，未发现丢包。\n"
               "已发送 %3，已接收 %4。")
                .arg(target_ip_)
                .arg(duration_minutes_)
                .arg(sent_)
                .arg(received_));
        return;
    }

    if (sent_ == 0) {
        ui_->statusLabel->setText(tr("检测已结束：未发出任何探测包。"));
        QMessageBox::warning(this, tr("检测结束"), tr("未发出任何探测包。"));
        return;
    }

    const QString report = buildReport();
    ui_->reportEdit->setPlainText(report);
    ui_->saveButton->setEnabled(true);
    ui_->statusLabel->setText(tr("检测完成：发现丢包，请查看报告并可保存。"));

    // Present the report for viewing (open)
    QMessageBox::warning(this, tr("检测完成 — 发现丢包"),
        tr("目标 %1 检测到丢包：已发送 %2，丢失 %3。\n"
           "详情已显示在报告中，可点击「保存报告…」保存为「时间_IP地址.txt」。")
            .arg(target_ip_)
            .arg(sent_)
            .arg(lost_));
}

void NicPacketLossDialog::onSaveReportClicked()
{
    const QString report = ui_->reportEdit->toPlainText();
    if (report.isEmpty()) {
        return;
    }
    const QString path = QFileDialog::getSaveFileName(this, tr("保存报告"),
        defaultReportFileName(), tr("文本文件 (*.txt)"));
    if (path.isEmpty()) {
        return;
    }
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        QMessageBox::critical(this, tr("保存失败"),
            tr("无法写入文件：%1").arg(file.errorString()));
        return;
    }
    QTextStream out(&file);
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    out.setEncoding(QStringConverter::Utf8);
#else
    out.setCodec(QTextCodec::codecForName("UTF-8"));
#endif
    out << report;
    file.close();
    QMessageBox::information(this, tr("保存成功"), tr("报告已保存到：\n%1").arg(path));
}
