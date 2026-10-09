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

#ifndef NIC_PACKET_LOSS_DIALOG_H
#define NIC_PACKET_LOSS_DIALOG_H

#include "config.h"

#include <QDateTime>
#include <QDialog>
#include <QProcess>
#include <QStringList>

namespace Ui {
class NicPacketLossDialog;
}

class NicPacketLossDialog : public QDialog
{
    Q_OBJECT

public:
    explicit NicPacketLossDialog(QWidget &parent);
    ~NicPacketLossDialog() override;

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void onStartClicked();
    void onStopClicked();
    void onSaveReportClicked();
    void onPingFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onPingError();

private:
    void setRunning(bool running);
    void startNextPing();
    void finishTest();
    void updateStatus();
    QString buildReport() const;
    QString defaultReportFileName() const;
    bool isPingReplyOk(const QString &output) const;
    int payloadSize() const;

    Ui::NicPacketLossDialog *ui_;
    QProcess *ping_process_;
    bool running_;
    bool stop_requested_;
    QString target_ip_;
    int mtu_;
    int duration_minutes_;
    QDateTime start_time_;
    QDateTime end_time_;
    int sent_;
    int received_;
    int lost_;
    QStringList loss_details_;
};

#endif /* NIC_PACKET_LOSS_DIALOG_H */
