/** @file
 *
 * 武汉中元华电 ZH 系列录波器文件重组导出。
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "zh_recorder_file_export.h"

#include "capture_file.h"
#include "file.h"

#include <epan/dissectors/packet-zh-recorder-tap.h>
#include <epan/tap.h>

#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QHash>
#include <QMessageBox>

#include <cstring>

namespace {

/** 一个待导出的文件：按到达顺序累积的数据块。 */
struct ZhPendingFile {
    QString name;
    quint32 declared_size = 0;
    QByteArray data;

    QByteArray accumulated() const { return data; }
};
struct ZhCollector {
    QHash<QString, ZhPendingFile> files;
    QStringList order;              /* 保持首次出现顺序 */
    QString current_name;           /* 最近一次 FILE_INFO 声明的文件名 */
    quint32 current_size = 0;
};

void zh_tap_reset(void *tapdata)
{
    auto *c = static_cast<ZhCollector *>(tapdata);
    c->files.clear();
    c->order.clear();
    c->current_name.clear();
    c->current_size = 0;
}

tap_packet_status zh_tap_packet(void *tapdata, packet_info *, epan_dissect_t *,
                                const void *data, tap_flags_t)
{
    auto *c = static_cast<ZhCollector *>(tapdata);
    const auto *rec = static_cast<const zh_recorder_tap_data_t *>(data);
    if (!rec)
        return TAP_PACKET_DONT_REDRAW;

    if (rec->kind == ZH_RECORDER_TAP_FILE_BEGIN) {
        if (rec->name[0] == '\0')
            return TAP_PACKET_DONT_REDRAW;

        c->current_name = QString::fromUtf8(rec->name);
        c->current_size = rec->total_size;

        if (!c->files.contains(c->current_name)) {
            ZhPendingFile f;
            f.name = c->current_name;
            f.declared_size = c->current_size;
            c->files.insert(c->current_name, f);
            c->order.append(c->current_name);
        } else {
            c->files[c->current_name].declared_size = rec->total_size;
        }
        return TAP_PACKET_DONT_REDRAW;
    }

    /* FILE_DATA: 归属到最近一次 FILE_INFO 声明的文件。 */
    if (rec->kind == ZH_RECORDER_TAP_FILE_DATA && rec->data != nullptr && rec->length > 0) {
        QString key = c->current_name;
        if (key.isEmpty() && !c->order.isEmpty())
            key = c->order.last();
        if (key.isEmpty())
            return TAP_PACKET_DONT_REDRAW;

        if (!c->files.contains(key)) {
            ZhPendingFile f;
            f.name = key;
            f.declared_size = c->current_size;
            c->files.insert(key, f);
            c->order.append(key);
        }
        ZhPendingFile &f = c->files[key];
        f.data.append(reinterpret_cast<const char *>(rec->data),
                      static_cast<int>(rec->length));
    }
    return TAP_PACKET_DONT_REDRAW;
}

/** 只取文件名部分，避免报文里的路径写到输出目录之外。 */
QString safeBasename(const QString &name)
{
    QString base = QFileInfo(name).fileName();
    if (base.isEmpty())
        base = QStringLiteral("zh_recorder_file");
    base.replace(QLatin1Char('/'), QLatin1Char('_'));
    base.replace(QLatin1Char('\\'), QLatin1Char('_'));
    if (base == QLatin1String(".") || base == QLatin1String(".."))
        base = QStringLiteral("zh_recorder_file");
    return base;
}

} // namespace

QString ZhRecorderFileExporter::promptOutputDir(QWidget *parent)
{
    return QFileDialog::getExistingDirectory(parent, QObject::tr("选择录波文件输出目录"));
}

bool ZhRecorderFileExporter::exportFromCapture(CaptureFile &cap_file, const QString &out_dir,
                                               QString &err_msg, QString *info_msg,
                                               QStringList *written)
{
    if (!cap_file.isValid() || !cap_file.capFile()) {
        err_msg = QObject::tr("未打开抓包文件。");
        return false;
    }

    if (out_dir.isEmpty()) {
        err_msg = QObject::tr("未指定输出目录。");
        return false;
    }

    ZhCollector collector;

    GString *error_string = register_tap_listener(
        ZH_RECORDER_TAP_NAME, &collector, nullptr, 0,
        zh_tap_reset, zh_tap_packet, nullptr, nullptr);
    if (error_string) {
        err_msg = QString::fromUtf8(error_string->str);
        g_string_free(error_string, TRUE);
        return false;
    }

    cf_retap_packets(cap_file.capFile());
    remove_tap_listener(&collector);

    if (collector.order.isEmpty()) {
        err_msg = QObject::tr(
            "未找到 ZH 录波文件数据。请先用「录波器规约 → 武汉中原录波器规约解析」"
            "解析抓包，再执行导出。");
        return false;
    }

    QDir dir(out_dir);
    if (!dir.exists() && !dir.mkpath(QStringLiteral("."))) {
        err_msg = QObject::tr("无法创建输出目录: %1").arg(out_dir);
        return false;
    }

    QStringList problems;
    QStringList done;
    int written_count = 0;

    for (const QString &key : collector.order) {
        const ZhPendingFile &f = collector.files.value(key);
        if (f.data.isEmpty())
            continue;

        if (f.declared_size != 0 && static_cast<quint32>(f.data.size()) != f.declared_size) {
            problems << QObject::tr("%1: 声明 %2 字节，实际重组 %3 字节")
                            .arg(safeBasename(f.name))
                            .arg(f.declared_size)
                            .arg(f.data.size());
            continue;
        }

        const QString out_path = dir.filePath(safeBasename(f.name));
        QFile out(out_path);
        if (!out.open(QIODevice::WriteOnly)) {
            problems << QObject::tr("%1: 无法写入").arg(out_path);
            continue;
        }
        if (out.write(f.data) != f.data.size()) {
            problems << QObject::tr("%1: 写入不完整").arg(out_path);
            out.close();
            continue;
        }
        out.close();
        done << out_path;
        if (written)
            written->append(out_path);
        ++written_count;
    }

    if (written_count == 0) {
        err_msg = problems.isEmpty()
            ? QObject::tr("未找到可导出的文件数据。")
            : problems.join(QLatin1Char('\n'));
        return false;
    }

    if (info_msg) {
        QString text = QObject::tr("已导出 %1 个文件到:\n%2")
                           .arg(written_count)
                           .arg(out_dir);
        if (!done.isEmpty())
            text += QStringLiteral("\n\n") + done.join(QLatin1Char('\n'));
        if (!problems.isEmpty())
            text += QStringLiteral("\n\n") + QObject::tr("有 %1 个文件被跳过:")
                        .arg(problems.size()) + QStringLiteral("\n")
                    + problems.join(QLatin1Char('\n'));
        *info_msg = text;
    }

    return true;
}
