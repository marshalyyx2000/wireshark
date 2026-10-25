/** @file
 *
 * NARI network IEC 103 disturbance recording → COMTRADE 1999 export.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "iec103_wave_comtrade_export.h"

#include "capture_file.h"
#include "file.h"

#include <epan/tap.h>
#include <epan/dissectors/packet-nari-wave-tap.h>

#include <QComboBox>
#include <QDataStream>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFile>
#include <QFormLayout>
#include <QHash>
#include <QLabel>
#include <QList>
#include <QMap>
#include <QObject>
#include <QSpinBox>
#include <QTextStream>
#include <QVector>
#include <QVBoxLayout>

#include <algorithm>
#include <cstring>

namespace {

struct AnalogScale {
    float rpv = 1.0f;
    float rdv = 1.0f;
    float rfa = 1.0f;
};

struct TagEvent {
    uint16_t tap = 0;
    uint8_t  fun = 0;
    uint8_t  inf = 0;
    uint8_t  dpi = 0;
};

struct DigitalChannel {
    uint8_t ch_num = 0;
    uint8_t fun = 255;
    uint8_t inf = 0;
    int     initial_dpi = 0;
};

struct WaveCollector {
    uint16_t target_fan = 0;
    bool     has_asdu23 = false;
    bool     duplicate_asdu23 = false;
    uint8_t  cp56time[7] = {};
    uint8_t  noe = 0;
    uint16_t int_us = 1000;
    QHash<uint8_t, AnalogScale>      scales;
    QMap<uint8_t, QVector<int16_t>>  analog;
    QList<QVector<TagEvent>>         asdu29_tag_sets;
};

static bool
parse_cp56(const uint8_t *cp56, QDateTime *out_dt, int *out_ms)
{
    const uint16_t ms = (uint16_t)(cp56[0] | (cp56[1] << 8));
    const int min = cp56[2] & 0x3f;
    const int hour = cp56[3] & 0x1f;
    const int day = cp56[4] & 0x1f;
    const int month = cp56[5] & 0x0f;
    int year = cp56[6] & 0x7f;

    if (year < 70)
        year += 100;
    year += 1900;

    const QDate date(year, month > 0 ? month : 1, day > 0 ? day : 1);
    const QTime time(hour, min, ms / 1000, (ms % 1000) * 1000);
    if (!date.isValid() || !time.isValid())
        return false;

    *out_dt = QDateTime(date, time);
    *out_ms = ms % 1000;
    return true;
}

static QString
base_name(uint16_t fan, const uint8_t *cp56, bool used_fallback)
{
    QDateTime dt;
    int ms = 0;

    if (!parse_cp56(cp56, &dt, &ms) || used_fallback)
        dt = QDateTime::currentDateTime();

    return QStringLiteral("%1_%2_%3_%4")
        .arg(fan)
        .arg(dt.toString(QStringLiteral("yyyyMMdd")))
        .arg(dt.toString(QStringLiteral("HHmmss")))
        .arg(ms, 3, 10, QChar('0'));
}

static int
dpi_to_digital(uint8_t dpi)
{
    return dpi == 2 ? 1 : 0;
}

static bool
is_init_tag(const TagEvent &t)
{
    return t.inf == 0 && (t.fun == 254 || t.fun == 255);
}

static void
tap_reset(void *tapdata)
{
    auto *col = static_cast<WaveCollector *>(tapdata);

    col->has_asdu23 = false;
    col->duplicate_asdu23 = false;
    col->noe = 0;
    col->int_us = 1000;
    col->scales.clear();
    col->analog.clear();
    col->asdu29_tag_sets.clear();
    memset(col->cp56time, 0, sizeof(col->cp56time));
}

static tap_packet_status
tap_packet(void *tapdata, packet_info *, epan_dissect_t *, const void *data, tap_flags_t)
{
    const auto *td = static_cast<const nari_wave_tap_data_t *>(data);
    auto *col = static_cast<WaveCollector *>(tapdata);

    if (td->fan != col->target_fan)
        return TAP_PACKET_DONT_REDRAW;

    switch (td->kind) {
    case NARI_WAVE_TAP_ASDU23:
        if (!col->has_asdu23) {
            memcpy(col->cp56time, td->cp56time, 7);
            col->has_asdu23 = true;
        } else {
            col->duplicate_asdu23 = true;
        }
        break;
    case NARI_WAVE_TAP_ASDU26:
        col->noe = td->noe;
        if (td->int_us > 0)
            col->int_us = td->int_us;
        break;
    case NARI_WAVE_TAP_ASDU27:
        col->scales[td->acc] = { td->rpv, td->rdv, td->rfa };
        break;
    case NARI_WAVE_TAP_ASDU29:
        if (td->tag_count > 0) {
            QVector<TagEvent> tags;
            tags.reserve(td->tag_count);
            for (uint16_t i = 0; i < td->tag_count; i++) {
                TagEvent te;
                te.tap = td->tags[i].tap;
                te.fun = td->tags[i].fun;
                te.inf = td->tags[i].inf;
                te.dpi = td->tags[i].dpi;
                tags.append(te);
            }
            col->asdu29_tag_sets.append(tags);
        }
        break;
    case NARI_WAVE_TAP_ASDU30:
    {
        QVector<int16_t> &samples = col->analog[td->acc];
        const int needed = (int)td->nfe + td->sdv_count;

        if (samples.size() < needed)
            samples.resize(needed);
        for (uint16_t i = 0; i < td->sdv_count; i++)
            samples[(int)td->nfe + i] = td->sdv[i];
        break;
    }
    default:
        break;
    }

    return TAP_PACKET_DONT_REDRAW;
}

static QVector<DigitalChannel>
build_digital_channels(const QList<QVector<TagEvent>> &sets)
{
    QHash<uint8_t, int> inits;

    for (const auto &tags : sets) {
        for (const TagEvent &t : tags) {
            if (is_init_tag(t))
                inits.insert(t.tap, t.dpi);
        }
    }

    QList<uint8_t> keys = inits.keys();
    std::sort(keys.begin(), keys.end());

    QVector<DigitalChannel> out;
    for (uint8_t k : keys) {
        DigitalChannel dc;
        dc.ch_num = k;
        dc.fun = 255;
        dc.inf = 0;
        dc.initial_dpi = inits[k];
        out.append(dc);
    }
    return out;
}

static QVector<QVector<int>>
build_digital_states(int sample_count, const QVector<DigitalChannel> &channels,
                     const QList<QVector<TagEvent>> &sets)
{
    QVector<QVector<int>> states(channels.size());
    for (int c = 0; c < channels.size(); c++)
        states[c].fill(dpi_to_digital((uint8_t)channels[c].initial_dpi), sample_count);

    QVector<TagEvent> changes;
    for (const auto &tags : sets) {
        for (const TagEvent &t : tags) {
            if (!is_init_tag(t))
                changes.append(t);
        }
    }
    std::sort(changes.begin(), changes.end(), [](const TagEvent &a, const TagEvent &b) {
        return a.tap < b.tap;
    });

    for (const TagEvent &ch : changes) {
        for (int c = 0; c < channels.size(); c++) {
            const DigitalChannel &dc = channels[c];
            const bool match = (ch.fun == dc.fun && ch.inf == dc.inf) ||
                (is_init_tag(ch) && ch.tap == dc.ch_num);
            if (!match)
                continue;

            const int from = ch.tap >= (uint16_t)sample_count ? sample_count : (int)ch.tap;
            const int val = dpi_to_digital(ch.dpi);
            for (int s = from; s < sample_count; s++)
                states[c][s] = val;
        }
    }
    return states;
}

static bool
write_comtrade(WaveCollector &col, const QString &out_dir, uint16_t fan,
               Iec103ComtradeDatFormat dat_format, QString &err_msg, QString *info_msg)
{
    if (col.analog.isEmpty()) {
        err_msg = QObject::tr("录波序号 %1 未找到 ASDU30 扰动值数据。").arg(fan);
        return false;
    }

    QList<uint8_t> analog_keys = col.analog.keys();
    std::sort(analog_keys.begin(), analog_keys.end());

    const QVector<DigitalChannel> dig_channels = build_digital_channels(col.asdu29_tag_sets);
    int sample_count = col.noe > 0 ? (int)col.noe : 0;
    for (const auto &samples : col.analog) {
        if (samples.size() > sample_count)
            sample_count = samples.size();
    }
    if (sample_count <= 0) {
        err_msg = QObject::tr("无法确定采样点数。");
        return false;
    }

    for (uint8_t acc : analog_keys) {
        if (col.analog[acc].size() < sample_count)
            col.analog[acc].resize(sample_count);
    }

    const QVector<QVector<int>> digital_states = build_digital_states(
        sample_count, dig_channels, col.asdu29_tag_sets);

    const bool time_fallback = !col.has_asdu23;
    uint8_t cp56_copy[7];
    memcpy(cp56_copy, col.cp56time, 7);
    if (time_fallback)
        memset(cp56_copy, 0, sizeof(cp56_copy));

    const QString base = base_name(fan, cp56_copy, time_fallback);
    const QString cfg_path = out_dir + QLatin1Char('/') + base + QStringLiteral(".cfg");
    const QString dat_path = out_dir + QLatin1Char('/') + base + QStringLiteral(".dat");
    const QString hdr_path = out_dir + QLatin1Char('/') + base + QStringLiteral(".hdr");

    QDateTime start_dt;
    int start_ms = 0;
    if (!parse_cp56(cp56_copy, &start_dt, &start_ms) || !start_dt.isValid())
        start_dt = QDateTime::currentDateTime();

    const int ana_count = analog_keys.size();
    const int dig_count = dig_channels.size();
    const double sample_rate = col.int_us > 0 ? 1000000.0 / col.int_us : 1000.0;

    QFile cfg_file(cfg_path);
    if (!cfg_file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        err_msg = QObject::tr("无法写入 cfg 文件: %1").arg(cfg_path);
        return false;
    }
    QTextStream cfg(&cfg_file);
    cfg.setRealNumberNotation(QTextStream::FixedNotation);

    cfg << "NARI_IEC103,WAVE_EXPORT,1999\n";
    cfg << (ana_count + dig_count) << ',' << ana_count << ',' << dig_count << '\n';

    int ch_idx = 1;
    for (uint8_t acc : analog_keys) {
        const AnalogScale sc = col.scales.value(acc);
        float primary = 1.0f;
        float secondary = 1.0f;
        if (sc.rdv != 0.0f && sc.rfa != 0.0f)
            primary = sc.rfa * sc.rpv / sc.rdv;

        cfg << ch_idx << ','
            << QStringLiteral("模拟量通道%1").arg(acc) << ",,,,"
            << primary << ',' << secondary << ",0,-32768,32767,"
            << primary << ',' << secondary << ",S\n";
        ch_idx++;
    }
    for (int d = 0; d < dig_count; d++) {
        cfg << ch_idx << ','
            << QStringLiteral("开关量通道%1").arg(dig_channels[d].ch_num) << ",,,1\n";
        ch_idx++;
    }

    cfg << "50\n";
    cfg << "1\n";
    cfg << sample_rate << '\n';
    cfg << start_dt.toString(QStringLiteral("dd/MM/yyyy")) << '\n';
    cfg << start_dt.toString(QStringLiteral("HH:mm:ss."))
        << QString::asprintf("%06d", start_ms * 1000) << '\n';
    cfg << start_dt.toString(QStringLiteral("dd/MM/yyyy")) << '\n';
    cfg << start_dt.toString(QStringLiteral("HH:mm:ss."))
        << QString::asprintf("%06d", start_ms * 1000) << '\n';
    cfg << (dat_format == Iec103ComtradeDatFormat::Binary ? "BINARY" : "ASCII") << '\n';
    cfg << "1\n";
    cfg_file.close();

    const int dig_words = dig_count > 0 ? (dig_count + 15) / 16 : 0;

    QFile dat_file(dat_path);
    if (dat_format == Iec103ComtradeDatFormat::Binary) {
        if (!dat_file.open(QIODevice::WriteOnly)) {
            err_msg = QObject::tr("无法写入 dat 文件: %1").arg(dat_path);
            return false;
        }
        QDataStream dat(&dat_file);
        dat.setByteOrder(QDataStream::LittleEndian);

        for (int s = 0; s < sample_count; s++) {
            const quint32 sample_num = static_cast<quint32>(s + 1);
            const qint32 ts_us = static_cast<qint32>(static_cast<qint64>(s) * col.int_us);
            dat << sample_num << ts_us;
            for (uint8_t acc : analog_keys) {
                const qint16 val = col.analog[acc][s];
                dat << val;
            }
            for (int w = 0; w < dig_words; w++) {
                quint16 word = 0;
                for (int bit = 0; bit < 16; bit++) {
                    const int dch = w * 16 + bit;
                    if (dch < dig_count && digital_states[dch][s])
                        word |= static_cast<quint16>(1u << bit);
                }
                dat << word;
            }
        }
    } else {
        if (!dat_file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            err_msg = QObject::tr("无法写入 dat 文件: %1").arg(dat_path);
            return false;
        }
        QTextStream dat(&dat_file);

        for (int s = 0; s < sample_count; s++) {
            const qint64 ts_us = static_cast<qint64>(s) * col.int_us;
            dat << (s + 1) << ',' << ts_us;
            for (uint8_t acc : analog_keys)
                dat << ',' << col.analog[acc][s];
            for (int w = 0; w < dig_words; w++) {
                uint16_t word = 0;
                for (int bit = 0; bit < 16; bit++) {
                    const int dch = w * 16 + bit;
                    if (dch < dig_count && digital_states[dch][s])
                        word |= static_cast<uint16_t>(1u << bit);
                }
                dat << ',' << word;
            }
            dat << '\n';
        }
    }
    dat_file.close();

    QFile hdr_file(hdr_path);
    if (!hdr_file.open(QIODevice::WriteOnly)) {
        err_msg = QObject::tr("无法写入 hdr 文件: %1").arg(hdr_path);
        return false;
    }
    hdr_file.close();

    if (info_msg) {
        QStringList parts;
        const QString fmt_label = dat_format == Iec103ComtradeDatFormat::Binary
            ? QObject::tr("二进制 (BINARY)")
            : QObject::tr("ASCII");
        parts << QObject::tr("已导出 COMTRADE 文件 (dat: %1):\n%2\n%3\n%4")
                    .arg(fmt_label, cfg_path, dat_path, hdr_path);
        if (col.duplicate_asdu23)
            parts << QObject::tr("注意: 抓包中存在多条相同录波序号，使用首次出现的故障时间。");
        if (time_fallback)
            parts << QObject::tr("注意: 未找到 ASDU23 故障时间，文件名时间使用当前时间。");
        *info_msg = parts.join(QLatin1Char('\n'));
    }
    return true;
}

} // namespace

bool Iec103WaveComtradeExporter::promptExport(QWidget *parent, Iec103WaveExportRequest &request)
{
    QDialog dlg(parent);
    dlg.setWindowTitle(QObject::tr("103录波导出"));

    auto *fan_spin = new QSpinBox(&dlg);
    fan_spin->setRange(1, 65535);
    fan_spin->setValue(request.fan);

    auto *format_combo = new QComboBox(&dlg);
    format_combo->addItem(QObject::tr("ASCII 文本格式"), static_cast<int>(Iec103ComtradeDatFormat::Ascii));
    format_combo->addItem(QObject::tr("二进制格式 (BINARY)"), static_cast<int>(Iec103ComtradeDatFormat::Binary));
    const int fmt_idx = format_combo->findData(static_cast<int>(request.dat_format));
    format_combo->setCurrentIndex(fmt_idx >= 0 ? fmt_idx : 0);

    auto *form = new QFormLayout;
    form->addRow(QObject::tr("录波序号 (FAN):"), fan_spin);
    form->addRow(QObject::tr("dat 文件格式:"), format_combo);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    QObject::connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    auto *layout = new QVBoxLayout(&dlg);
    layout->addWidget(new QLabel(QObject::tr("请输入要提取的录波序号，并选择 COMTRADE dat 文件格式。"), &dlg));
    layout->addLayout(form);
    layout->addWidget(buttons);

    if (dlg.exec() != QDialog::Accepted)
        return false;

    request.fan = static_cast<uint16_t>(fan_spin->value());
    request.dat_format = static_cast<Iec103ComtradeDatFormat>(format_combo->currentData().toInt());
    return true;
}

bool Iec103WaveComtradeExporter::exportFromCapture(CaptureFile &cap_file, uint16_t fan,
                                                   const QString &out_dir,
                                                   Iec103ComtradeDatFormat dat_format,
                                                   QString &err_msg, QString *info_msg)
{
    if (!cap_file.isValid() || !cap_file.capFile()) {
        err_msg = QObject::tr("未打开抓包文件。");
        return false;
    }

    WaveCollector collector;
    collector.target_fan = fan;

    GString *error_string = register_tap_listener(
        NARI_WAVE_TAP_NAME, &collector, "nari_net_iec103", 0,
        tap_reset, tap_packet, nullptr, nullptr);
    if (error_string) {
        err_msg = QString::fromUtf8(error_string->str);
        g_string_free(error_string, TRUE);
        return false;
    }

    cf_retap_packets(cap_file.capFile());
    remove_tap_listener(&collector);

    const bool found_any = collector.has_asdu23 || !collector.analog.isEmpty()
        || !collector.asdu29_tag_sets.isEmpty() || collector.noe > 0;
    if (!found_any) {
        err_msg = QObject::tr("未找到录波序号 %1 的南自网络103录波数据，请确认抓包包含 nari_net_iec103 报文。").arg(fan);
        return false;
    }

    return write_comtrade(collector, out_dir, fan, dat_format, err_msg, info_msg);
}
