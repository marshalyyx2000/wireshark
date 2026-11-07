/* packet-serial-raw.c
 *
 * Neutral serial capture payload (exported_pdu name "serial_raw").
 *
 * Default display is Serial Raw: a capture never states which vendor protocol
 * produced the bytes. The user selects a protocol from the 串口103 menu, which
 * calls serial_raw_set_payload_dissector(); the next dissection then hands the
 * payload to that dissector.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/serial_raw.h>
#include <wsutil/array.h>

void proto_register_serial_raw(void);
void proto_reg_handoff_serial_raw(void);

static int proto_serial_raw;
static int ett_serial_raw;
static int hf_serial_raw_payload;
static int hf_serial_raw_forced;

static dissector_handle_t serial_raw_handle;

/*
 * Two separate owners on purpose:
 *
 *  - g_runtime_payload is owned here (g_strdup/g_free) and is what the menu
 *    sets. It is never handed to the preference system, because prefs stores
 *    string preferences with wmem and would free() memory that was allocated
 *    with g_malloc (or vice versa), which crashes the GUI on redissect.
 *
 *  - g_pref_payload is owned by the preference system. An apply callback
 *    copies it into the runtime variable, so "-o serial_raw.payload_dissector:X"
 *    and the protocol preferences dialog work without sharing an allocator.
 */
static char *g_runtime_payload;
static const char *g_pref_payload;

void
serial_raw_set_payload_dissector(const char *name)
{
    g_free(g_runtime_payload);
    g_runtime_payload = NULL;
    if (name != NULL && name[0] != '\0')
        g_runtime_payload = g_strdup(name);
}

const char *
serial_raw_get_payload_dissector(void)
{
    return g_runtime_payload;
}

static void
serial_raw_prefs_apply(void)
{
    /* Only ever add an override here; clearing is the menu's job so that a
     * preference reset cannot silently undo an explicit user choice. */
    if (g_pref_payload != NULL && g_pref_payload[0] != '\0')
        serial_raw_set_payload_dissector(g_pref_payload);
}

void
serial_raw_register_prefs(module_t *module)
{
    if (module == NULL)
        return;
    prefs_register_string_preference(module, "payload_dissector",
        "Payload dissector",
        "Dissector name applied to every serial payload (same effect as "
        "choosing a protocol from the 串口103 menu). Empty keeps the payload "
        "neutral.",
        &g_pref_payload);
    prefs_register_obsolete_preference(module, "forced_dissector");
}

static int
dissect_serial_raw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *ti;
    proto_tree *serial_tree;
    int len = (int)tvb_captured_length(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Serial Raw");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Serial payload (%d bytes)", len);

    ti = proto_tree_add_item(tree, proto_serial_raw, tvb, 0, len, ENC_NA);
    serial_tree = proto_item_add_subtree(ti, ett_serial_raw);

    if (g_runtime_payload != NULL && g_runtime_payload[0] != '\0') {
        dissector_handle_t forced = find_dissector(g_runtime_payload);

        if (forced != NULL) {
            /* The vendor dissector returns 0 when the payload does not match its
             * framing (e.g. the wrong vendor was picked). In that case fall back
             * to the neutral view instead of leaving an empty tree. */
            int consumed = call_dissector_with_data(forced, tvb, pinfo, tree, data);
            if (consumed > 0)
                return consumed;

            col_set_str(pinfo->cinfo, COL_PROTOCOL, "Serial Raw");
            col_clear(pinfo->cinfo, COL_INFO);
            col_add_fstr(pinfo->cinfo, COL_INFO, "Serial payload (%d bytes)", len);
            proto_item *note = proto_tree_add_string(serial_tree, hf_serial_raw_forced,
                                                     tvb, 0, 0, g_runtime_payload);
            proto_item_set_generated(note);
            proto_item_append_text(note, " (did not match this payload)");
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO,
                            " [try-decode: %s not found]", g_runtime_payload);
        }
    }

    proto_tree_add_item(serial_tree, hf_serial_raw_payload, tvb, 0, len, ENC_NA);
    call_data_dissector(tvb, pinfo, tree);
    return len;
}

void
proto_register_serial_raw(void)
{
    static hf_register_info hf[] = {
        { &hf_serial_raw_payload,
          { "Payload", "serial_raw.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Undecoded serial bytes", HFILL }},
        { &hf_serial_raw_forced,
          { "Try-decode dissector", "serial_raw.forced_dissector",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Dissector picked from the 串口103 menu", HFILL }},
    };
    static int *ett[] = { &ett_serial_raw };

    proto_serial_raw = proto_register_protocol(
            "串口原始数据",
            "Serial Raw",
            "serial_raw");
    proto_register_field_array(proto_serial_raw, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    serial_raw_register_prefs(prefs_register_protocol(proto_serial_raw,
                                                      serial_raw_prefs_apply));

    serial_raw_handle = register_dissector("serial_raw", dissect_serial_raw,
                                           proto_serial_raw);
}

void
proto_reg_handoff_serial_raw(void)
{
    /* registered by name for exported_pdu lookup only */
    (void)serial_raw_handle;
}
