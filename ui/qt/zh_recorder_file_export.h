/** @file
 *
 * 武汉中元华电 ZH 系列录波器文件重组导出。
 *
 * ZH 规约的文件传输是分包的：先有 PTYPE_FILE_INFO（文件名/大小），随后若干
 * PTYPE_FILE_DATA 携带数据块。本模块按包顺序累加数据块，导出为文件。
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ZH_RECORDER_FILE_EXPORT_H
#define ZH_RECORDER_FILE_EXPORT_H

#include "config.h"

#include <QString>
#include <QStringList>

class CaptureFile;
class QWidget;

class ZhRecorderFileExporter
{
public:
    /**
     * @brief 让用户选择输出目录。
     * @return 选中目录；取消时返回空字符串。
     */
    static QString promptOutputDir(QWidget *parent);

    /**
     * @brief 从抓包中重组并导出 ZH 录波文件。
     *
     * 需要抓包已按 zh_recorder 解析（菜单「录波器规约 → 武汉中原录波器规约解析」），
     * 或调用方已对 TCP 30282 应用 Decode As。
     *
     * @param out_dir   输出目录
     * @param err_msg   失败原因
     * @param info_msg  成功时的摘要（可选）
     * @param written   实际写出的文件完整路径（可选）
     * @return 至少写出一个文件时返回 true
     */
    static bool exportFromCapture(CaptureFile &cap_file, const QString &out_dir,
                                  QString &err_msg, QString *info_msg = nullptr,
                                  QStringList *written = nullptr);

private:
    ZhRecorderFileExporter() = delete;
};

#endif /* ZH_RECORDER_FILE_EXPORT_H */
