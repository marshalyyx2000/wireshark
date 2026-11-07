/* vendor_recipe_dialog.h
 *
 * 「更多厂家规约」选择对话框的实现放在 .cpp 里，这里只暴露一个入口。
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef VENDOR_RECIPE_DIALOG_H
#define VENDOR_RECIPE_DIALOG_H

#include <QDialog>
#include <QVector>

class QComboBox;
class QDialogButtonBox;
class QLabel;
class QLineEdit;

/**
 * 让用户从一张"厂家 -> 承载/协议短名"的表中挑一项，用于中性抓包的手动试解。
 *
 * 表内容由 vendor_recipe_dialog.cpp 的 g_recipes 提供，和
 * tools/protocol-audit/*.json 里的厂家清单保持一致。
 */
class VendorRecipeDialog : public QDialog
{
    Q_OBJECT

public:
    explicit VendorRecipeDialog(QWidget *parent = nullptr);

    /** 选中项的协议短名（未选则为空）。 */
    QString protocolName() const;
    /** 选中项的承载："serial" / "tcp" / "udp"。 */
    QString carrier() const;

private:
    void rebuild();

    QComboBox *carrier_combo_ = nullptr;
    QComboBox *vendor_combo_ = nullptr;
    QLineEdit *filter_edit_ = nullptr;
    QLabel *hint_label_ = nullptr;
    QDialogButtonBox *button_box_ = nullptr;
};

#endif /* VENDOR_RECIPE_DIALOG_H */
