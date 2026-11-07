/** @file
 * Neutral serial_raw transport for serialdump captures.
 * Payload may be force-decoded by UI menus via serial_raw_set_payload_dissector().
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once

#include "ws_symbol_export.h"

#include <epan/prefs.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Force serial_raw payloads to be dissected by @p name (e.g. "yushun_modbus").
 * Pass NULL or "" to clear the override (show as Serial Raw / Data).
 */
WS_DLL_PUBLIC void serial_raw_set_payload_dissector(const char *name);

/** @return Current override name, or NULL if none. */
WS_DLL_PUBLIC const char *serial_raw_get_payload_dissector(void);

/**
 * Register the "payload dissector" preference so the try-decode choice can be
 * persisted. Pass the module returned by prefs_register_protocol().
 */
WS_DLL_PUBLIC void serial_raw_register_prefs(module_t *module);

#ifdef __cplusplus
}
#endif
