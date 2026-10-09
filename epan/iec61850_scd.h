/** @file
 *
 * IEC 61850 SCD/SCL model index for ObjectReference description lookup.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include <stdbool.h>
#include <epan/proto.h>
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Load an SCD/CID/ICD (SCL) file and build a reference→description index.
 * Replaces any previously loaded model.
 *
 * @param path Absolute or relative path to the SCL file (UTF-8).
 * @param err  Optional; on failure set to a newly allocated error string (g_free).
 * @return true on success.
 */
WS_DLL_PUBLIC bool iec61850_scd_load(const char *path, char **err);

/** Clear the loaded SCD model and free the index. */
WS_DLL_PUBLIC void iec61850_scd_clear(void);

/** @return true if a model is currently loaded. */
WS_DLL_PUBLIC bool iec61850_scd_loaded(void);

/** @return path of the loaded file, or NULL. */
WS_DLL_PUBLIC const char *iec61850_scd_path(void);

/**
 * Look up a description for an ObjectReference / datSet / gocbRef / svID.
 * Tries the raw string and a '$'→'.' normalized form.
 *
 * @return description owned by the SCD module, or NULL if not found.
 */
WS_DLL_PUBLIC const char *iec61850_scd_lookup_desc(const char *ref);

/**
 * If a description is found for @p ref, append " (desc)" to @p ti.
 */
WS_DLL_PUBLIC void iec61850_scd_append_desc(proto_item *ti, const char *ref);

#ifdef __cplusplus
}
#endif
