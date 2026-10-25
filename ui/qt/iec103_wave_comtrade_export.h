/** @file
 *
 * NARI network IEC 103 disturbance recording → COMTRADE 1999 export.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef IEC103_WAVE_COMTRADE_EXPORT_H
#define IEC103_WAVE_COMTRADE_EXPORT_H

#include <QString>

class CaptureFile;
class QWidget;

enum class Iec103ComtradeDatFormat {
    Ascii,
    Binary,
};

struct Iec103WaveExportRequest {
    uint16_t              fan = 1;
    Iec103ComtradeDatFormat dat_format = Iec103ComtradeDatFormat::Ascii;
};

class Iec103WaveComtradeExporter
{
public:
    /** Modal dialog: FAN + ASCII/BINARY dat format. Returns false if cancelled. */
    static bool promptExport(QWidget *parent, Iec103WaveExportRequest &request);

    static bool exportFromCapture(CaptureFile &cap_file, uint16_t fan,
                                  const QString &out_dir,
                                  Iec103ComtradeDatFormat dat_format,
                                  QString &err_msg, QString *info_msg = nullptr);

private:
    Iec103WaveComtradeExporter() = delete;
};

#endif /* IEC103_WAVE_COMTRADE_EXPORT_H */
