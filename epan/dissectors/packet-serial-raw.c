/* packet-serial-raw.c
 *
 * Neutral serial capture payload (exported_pdu name "serial_raw").
 * Default: show as Serial Raw. UI may force a concrete protocol via
 * serial_raw_set_payload_dissector() then redissect.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <epan/packet.h>
#include <epan/serial_raw.h>
#include <wsutil/array.h>

void proto_register_serial_raw(void);
void proto_reg_handoff_serial_raw(void);

static int proto_serial_raw;
static int ett_serial_raw;
static int hf_serial_raw_payload;
static int hf_serial_raw_forced;

static dissector_handle_t serial_raw_handle;

/* Runtime override set by industrial protocol menus (not a preference). */
static char *g_serial_raw_payload_dissector;

void
serial_raw_set_payload_dissector(const char *name)
{
    g_free(g_serial_raw_payload_dissector);
    g_serial_raw_payload_dissector = NULL;
    if (name != NULL && name[0] != '\0')
        g_serial_raw_payload_dissector = g_strdup(name);
}

const char *
serial_raw_get_payload_dissector(void)
{
    return g_serial_raw_payload_dissector;
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

    if (g_serial_raw_payload_dissector != NULL) {
        dissector_handle_t forced;

        proto_tree_add_string(serial_tree, hf_serial_raw_forced, tvb, 0, 0,
                              g_serial_raw_payload_dissector);
        forced = find_dissector(g_serial_raw_payload_dissector);
        if (forced != NULL) {
            col_clear(pinfo->cinfo, COL_PROTOCOL);
            col_clear(pinfo->cinfo, COL_INFO);
            return call_dissector_with_data(forced, tvb, pinfo, tree, data);
        }
        col_append_str(pinfo->cinfo, COL_INFO, " [forced dissector not found]");
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
          { "Forced payload dissector", "serial_raw.forced_dissector",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Dissector name applied by try-decode menu", HFILL }},
    };
    static int *ett[] = { &ett_serial_raw };

    proto_serial_raw = proto_register_protocol(
            "串口原始数据",
            "Serial Raw",
            "serial_raw");
    proto_register_field_array(proto_serial_raw, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    serial_raw_handle = register_dissector("serial_raw", dissect_serial_raw,
                                           proto_serial_raw);
}

void
proto_reg_handoff_serial_raw(void)
{
    /* registered by name for exported_pdu lookup only */
    (void)serial_raw_handle;
}
