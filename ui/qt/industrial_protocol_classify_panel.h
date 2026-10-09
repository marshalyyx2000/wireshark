/** @file
 *
 * Smart-substation protocol classification tree (dock content).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef INDUSTRIAL_PROTOCOL_CLASSIFY_PANEL_H
#define INDUSTRIAL_PROTOCOL_CLASSIFY_PANEL_H

#include "config.h"

#include "wireshark_dialog.h"

#include <QHash>
#include <QSet>
#include <QString>
#include <QVector>

class MmsGeneralFilterWidget;
class MmsReportFilterWidget;
class QTimer;
class QTreeWidgetItem;

namespace Ui {
class IndustrialProtocolClassifyPanel;
}

class IndustrialProtocolClassifyPanel : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit IndustrialProtocolClassifyPanel(QWidget &parent, CaptureFile &capture_file);
    ~IndustrialProtocolClassifyPanel() override;

    void refresh();
    void showProtocolTree();

protected:
    void captureFileClosing() override;
    void captureFileClosed() override;

private slots:
    void onSearchTextChanged(const QString &text);
    void onTreeItemClicked(QTreeWidgetItem *item, int column);
    void onTreeCurrentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    void onClearClicked();
    void onDebouncedFilterApply();
    void onReportRequestApply(const QString &filter, bool force);
    void onGeneralRequestApply(const QString &filter, bool force);
    void onMmsFilterTabChanged(int index);

private:
    enum class AddrKind {
        IPv4,
        IPv6,
        Ethernet
    };

    struct ProtoDef {
        const char *key;
        const char *display_name;
        const char *layer_name;      /* proto_is_frame_protocol name */
        const char *alt_layer_name;  /* optional second layer (e.g. r-goose) */
        const char *filter_expr;     /* display filter for this protocol */
    };

    static void tapReset(void *tapdata);
    static tap_packet_status tapPacket(void *tapdata, packet_info *pinfo,
                                       epan_dissect_t *edt, const void *data,
                                       tap_flags_t flags);
    static void tapDraw(void *tapdata);

    void retap();
    void rebuildTree();
    void applySearchFilter(const QString &text);
    void updateReportPanelVisibility();
    void updateHint();
    bool isGeneralFilterTabActive() const;
    QString buildTreeFilter() const;
    QString buildCombinedFilter() const;
    void applyCombinedFilter(bool force = false);
    void rememberAddress(const QString &proto_key, const address *addr, AddrKind kind);
    void collectAddressesForPacket(packet_info *pinfo, const QString &proto_key);

    static const QVector<ProtoDef> &protocolDefs();

    Ui::IndustrialProtocolClassifyPanel *ui_;
    MmsReportFilterWidget *report_widget_;
    MmsGeneralFilterWidget *general_widget_;
    QTimer *filter_timer_;
    QHash<QString, QSet<QString>> addrs_by_proto_;
    QHash<QString, AddrKind> addr_kind_;
    QString last_applied_filter_;
    QString selected_proto_key_;
    QString selected_addr_;
    bool selected_is_root_;
    bool selected_is_proto_;
};

#endif /* INDUSTRIAL_PROTOCOL_CLASSIFY_PANEL_H */
