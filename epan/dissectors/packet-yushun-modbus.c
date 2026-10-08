/* packet-yushun-modbus.c
 *
 * Yushun (禹舜) MODBUS lower-end voltage hard-plate protocol dissector.
 * TCP port 502 carries Modbus RTU frames (unit id + PDU + CRC16, no MBAP).
 * Application data at holding registers 5000+ per YSV2.9 section 9.5.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/crc16-tvb.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <wsutil/array.h>
#include "packet-tcp.h"
#include "packet-mbtcp.h"

void proto_register_yushun_modbus(void);
void proto_reg_handoff_yushun_modbus(void);

#define YUSHUN_PORT              502
#define YUSHUN_REG_BASE          5000
#define YUSHUN_REG_END           5506
#define YUSHUN_UNIT_BYTES        18
#define YUSHUN_MAGIC             0x4459

static int proto_yushun_modbus;

static dissector_handle_t yushun_modbus_tcp_handle;

static int ett_yushun_modbus;
static int ett_yushun_pdu;
static int ett_yushun_unit;

static int hf_yushun_unit_id;
static int hf_yushun_crc16;
static int hf_yushun_crc16_status;
static int hf_yushun_function_code;
static int hf_yushun_start_address;
static int hf_yushun_quantity;
static int hf_yushun_byte_count;
static int hf_yushun_request_frame;
static int hf_yushun_point_index;
static int hf_yushun_point_address;
static int hf_yushun_voltage;
static int hf_yushun_comm_state;
static int hf_yushun_plate_state;
static int hf_yushun_spare;
static int hf_yushun_zero_coeff;
static int hf_yushun_full_coeff;
static int hf_yushun_magic;

static expert_field ei_yushun_crc_incorrect;
static expert_field ei_yushun_magic_invalid;

static bool global_yushun_desegment = true;
static bool global_yushun_crc_verify = true;

typedef struct {
    wmem_list_t *request_frames;
} yushun_conversation_t;

typedef struct {
    uint32_t  fnum;
    uint16_t  start_reg;
    uint16_t  quantity;
    uint8_t   unit_id;
    uint8_t   function_code;
} yushun_request_info_t;

typedef struct {
    uint16_t  start_reg;
    uint16_t  quantity;
    bool      request_found;
    uint32_t  req_frame_num;
} yushun_pkt_info_t;

static const value_string yushun_comm_state_vals[] = {
    { 0x00, "Normal (正常)" },
    { 0xFF, "Communication fault (通讯中断)" },
    { 0,    NULL }
};

static const value_string yushun_plate_state_vals[] = {
    { 0x00, "Engaged (投入)" },
    { 0x01, "Disengaged (退出)" },
    { 0,    NULL }
};

static int
classify_yushun_packet(tvbuff_t *tvb)
{
    uint8_t func;
    unsigned len;

    if (tvb_reported_length(tvb) < 2)
        return CANNOT_CLASSIFY;

    func = tvb_get_uint8(tvb, 1);
    len = tvb_reported_length(tvb);

    if (func & 0x80)
        return RESPONSE_PACKET;

    switch (func) {
    case READ_HOLDING_REGS:
    case READ_INPUT_REGS:
        if (len == 8)
            return QUERY_PACKET;
        return RESPONSE_PACKET;
    default:
        break;
    }

    return CANNOT_CLASSIFY;
}

static unsigned
get_yushun_pdu_len(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data _U_)
{
    uint8_t function_code;
    int packet_type;

    if (!tvb_bytes_exist(tvb, offset, 2))
        return 0;

    function_code = tvb_get_uint8(tvb, offset + 1);
    packet_type = classify_yushun_packet(tvb);

    switch (packet_type) {
    case QUERY_PACKET:
        switch (function_code) {
        case READ_COILS:
        case READ_DISCRETE_INPUTS:
        case READ_HOLDING_REGS:
        case READ_INPUT_REGS:
        case WRITE_SINGLE_COIL:
        case WRITE_SINGLE_REG:
            return 8;
        case WRITE_MULT_REGS:
        case WRITE_MULT_COILS:
            if (tvb_bytes_exist(tvb, offset + 6, 1))
                return tvb_get_uint8(tvb, offset + 6) + 9;
            break;
        default:
            break;
        }
        break;
    case RESPONSE_PACKET:
        if (function_code & 0x80)
            return 5;
        switch (function_code) {
        case READ_COILS:
        case READ_DISCRETE_INPUTS:
        case READ_HOLDING_REGS:
        case READ_INPUT_REGS:
            if (tvb_bytes_exist(tvb, offset + 2, 1))
                return tvb_get_uint8(tvb, offset + 2) + 5;
            break;
        case WRITE_SINGLE_COIL:
        case WRITE_SINGLE_REG:
        case WRITE_MULT_REGS:
        case WRITE_MULT_COILS:
            return 8;
        default:
            break;
        }
        break;
    default:
        break;
    }

    return tvb_captured_length_remaining(tvb, offset);
}

static bool
reg_range_overlaps_yushun(uint16_t start_reg, uint16_t quantity)
{
    uint32_t end_reg;

    if (quantity == 0)
        return false;

    end_reg = (uint32_t)start_reg + quantity;
    return (start_reg < YUSHUN_REG_END) && (end_reg > YUSHUN_REG_BASE);
}

static void
dissect_yushun_units(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     int offset, int data_len, uint16_t start_reg)
{
    int unit_offset;
    int point_index;
    uint16_t reg_addr;
    proto_tree *unit_tree;
    proto_item *ti;
    float voltage, zero_coeff, full_coeff;
    uint8_t comm_state, plate_state;
    uint16_t spare, magic;

    for (unit_offset = 0; unit_offset + YUSHUN_UNIT_BYTES <= data_len; unit_offset += YUSHUN_UNIT_BYTES) {
        reg_addr = (uint16_t)(start_reg + (unit_offset / 2));
        point_index = (int)((start_reg - YUSHUN_REG_BASE) + (unit_offset / YUSHUN_UNIT_BYTES)) + 1;

        unit_tree = proto_tree_add_subtree_format(tree, tvb, offset + unit_offset, YUSHUN_UNIT_BYTES,
                ett_yushun_unit, &ti, "Point %d (reg %u)", point_index, reg_addr);

        voltage = tvb_get_letohieee_float(tvb, offset + unit_offset);
        comm_state = tvb_get_uint8(tvb, offset + unit_offset + 4);
        plate_state = tvb_get_uint8(tvb, offset + unit_offset + 5);
        spare = tvb_get_ntohs(tvb, offset + unit_offset + 6);
        zero_coeff = tvb_get_letohieee_float(tvb, offset + unit_offset + 8);
        full_coeff = tvb_get_letohieee_float(tvb, offset + unit_offset + 12);
        magic = tvb_get_ntohs(tvb, offset + unit_offset + 16);

        proto_tree_add_float(unit_tree, hf_yushun_voltage, tvb, offset + unit_offset, 4, voltage);
        proto_tree_add_uint(unit_tree, hf_yushun_comm_state, tvb, offset + unit_offset + 4, 1, comm_state);
        proto_tree_add_uint(unit_tree, hf_yushun_plate_state, tvb, offset + unit_offset + 5, 1, plate_state);
        proto_tree_add_uint(unit_tree, hf_yushun_spare, tvb, offset + unit_offset + 6, 2, spare);
        proto_tree_add_float(unit_tree, hf_yushun_zero_coeff, tvb, offset + unit_offset + 8, 4, zero_coeff);
        proto_tree_add_float(unit_tree, hf_yushun_full_coeff, tvb, offset + unit_offset + 12, 4, full_coeff);
        proto_tree_add_uint(unit_tree, hf_yushun_magic, tvb, offset + unit_offset + 16, 2, magic);
        proto_tree_add_uint(unit_tree, hf_yushun_point_index, tvb, offset + unit_offset, 0, point_index);
        proto_tree_add_uint(unit_tree, hf_yushun_point_address, tvb, offset + unit_offset, 0, reg_addr);

        if (magic != YUSHUN_MAGIC) {
            expert_add_info_format(pinfo, ti, &ei_yushun_magic_invalid,
                    "Invalid device magic 0x%04X (expected 0x%04X)", magic, YUSHUN_MAGIC);
        }
    }
}

static yushun_pkt_info_t *
get_yushun_pkt_info(packet_info *pinfo, uint8_t unit_id, bool is_request,
                    uint16_t start_reg, uint16_t quantity, uint8_t function_code)
{
    conversation_t *conversation;
    yushun_conversation_t *conv_data;
    yushun_pkt_info_t *pkt_info;
    uint32_t conv_key;

    conv_key = unit_id;
    conversation = find_or_create_conversation(pinfo);
    conv_data = (yushun_conversation_t *)conversation_get_proto_data(conversation, proto_yushun_modbus);

    if (!pinfo->fd->visited) {
        if (conv_data == NULL) {
            conv_data = wmem_new(wmem_file_scope(), yushun_conversation_t);
            conv_data->request_frames = wmem_list_new(wmem_file_scope());
            conversation_add_proto_data(conversation, proto_yushun_modbus, conv_data);
        }

        pkt_info = wmem_new0(wmem_file_scope(), yushun_pkt_info_t);

        if (is_request) {
            yushun_request_info_t *req = wmem_new0(wmem_file_scope(), yushun_request_info_t);
            req->fnum = pinfo->num;
            req->start_reg = start_reg;
            req->quantity = quantity;
            req->unit_id = unit_id;
            req->function_code = function_code;
            wmem_list_prepend(conv_data->request_frames, req);

            pkt_info->start_reg = start_reg;
            pkt_info->quantity = quantity;
        } else {
            wmem_list_frame_t *frame = wmem_list_head(conv_data->request_frames);
            while (frame) {
                yushun_request_info_t *req = (yushun_request_info_t *)wmem_list_frame_data(frame);
                if (req && pinfo->num > req->fnum &&
                    req->unit_id == unit_id &&
                    req->function_code == function_code) {
                    pkt_info->start_reg = req->start_reg;
                    pkt_info->quantity = req->quantity;
                    pkt_info->request_found = true;
                    pkt_info->req_frame_num = req->fnum;
                    break;
                }
                frame = wmem_list_frame_next(frame);
            }
        }

        p_add_proto_data(wmem_file_scope(), pinfo, proto_yushun_modbus, conv_key, pkt_info);
    } else {
        pkt_info = (yushun_pkt_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_yushun_modbus, conv_key);
    }

    return pkt_info;
}

static int
dissect_yushun_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *yushun_tree, *pdu_tree;
    int offset = 0;
    unsigned len;
    uint8_t unit_id, function_code;
    uint16_t calc_crc16;
    int packet_type;
    uint16_t start_reg = 0, quantity = 0, byte_count = 0;
    yushun_pkt_info_t *pkt_info = NULL;
    bool dissect_units = false;

    len = tvb_reported_length(tvb);
    if (len < 5)
        return 0;

    unit_id = tvb_get_uint8(tvb, 0);
    function_code = tvb_get_uint8(tvb, 1) & 0x7F;
    packet_type = classify_yushun_packet(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "禹舜MODBUS-下端电压硬压板");
    col_clear(pinfo->cinfo, COL_INFO);

    if (packet_type == QUERY_PACKET && function_code == READ_HOLDING_REGS && len >= 6) {
        start_reg = tvb_get_ntohs(tvb, 2);
        quantity = tvb_get_ntohs(tvb, 4);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Query: Reg %u, Qty %u", start_reg, quantity);
    } else if (packet_type == RESPONSE_PACKET && function_code == READ_HOLDING_REGS && len >= 3) {
        byte_count = tvb_get_uint8(tvb, 2);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Response: %u data bytes", byte_count);
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unit %u, Func %u", unit_id, function_code);
    }

    ti = proto_tree_add_protocol_format(tree, proto_yushun_modbus, tvb, 0, (int)len,
            "禹舜MODBUS-下端电压硬压板协议");
    yushun_tree = proto_item_add_subtree(ti, ett_yushun_modbus);

    proto_tree_add_uint(yushun_tree, hf_yushun_unit_id, tvb, offset, 1, unit_id);
    offset += 1;

    pdu_tree = proto_tree_add_subtree(yushun_tree, tvb, offset, (int)len - offset - 2,
            ett_yushun_pdu, NULL, "Modbus PDU");

    proto_tree_add_uint(pdu_tree, hf_yushun_function_code, tvb, offset, 1, function_code);
    offset += 1;

    if (packet_type == QUERY_PACKET && function_code == READ_HOLDING_REGS && len >= 8) {
        start_reg = tvb_get_ntohs(tvb, offset);
        quantity = tvb_get_ntohs(tvb, offset + 2);
        pkt_info = get_yushun_pkt_info(pinfo, unit_id, true, start_reg, quantity, function_code);
        proto_tree_add_uint(pdu_tree, hf_yushun_start_address, tvb, offset, 2, start_reg);
        proto_tree_add_uint(pdu_tree, hf_yushun_quantity, tvb, offset + 2, 2, quantity);
        offset += 4;
    } else if (packet_type == RESPONSE_PACKET && function_code == READ_HOLDING_REGS && len >= 3) {
        pkt_info = get_yushun_pkt_info(pinfo, unit_id, false, 0, 0, function_code);
        byte_count = tvb_get_uint8(tvb, offset);
        proto_tree_add_uint(pdu_tree, hf_yushun_byte_count, tvb, offset, 1, byte_count);
        offset += 1;

        if (pkt_info && pkt_info->request_found) {
            proto_tree_add_uint(yushun_tree, hf_yushun_request_frame, tvb, 0, 0, pkt_info->req_frame_num);
            start_reg = pkt_info->start_reg;
            dissect_units = reg_range_overlaps_yushun(start_reg, pkt_info->quantity);
        }

        if (dissect_units && (int)byte_count > 0) {
            dissect_yushun_units(tvb, pinfo, pdu_tree, offset, byte_count, start_reg);
        }
        offset += byte_count;
    }

    if (global_yushun_crc_verify) {
        calc_crc16 = crc16_plain_tvb_offset_seed(tvb, 0, (unsigned)(len - 2), 0xFFFF);
        proto_tree_add_checksum(yushun_tree, tvb, (int)len - 2, hf_yushun_crc16, hf_yushun_crc16_status,
                &ei_yushun_crc_incorrect, pinfo, g_htons(calc_crc16), ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
    } else {
        proto_tree_add_checksum(yushun_tree, tvb, (int)len - 2, hf_yushun_crc16, hf_yushun_crc16_status,
                &ei_yushun_crc_incorrect, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
    }

    return (int)tvb_captured_length(tvb);
}

static int
dissect_yushun_modbus_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!tvb_bytes_exist(tvb, 0, 5))
        return 0;

    if (tvb_get_uint8(tvb, 0) == 0)
        return 0;

    tcp_dissect_pdus(tvb, pinfo, tree, global_yushun_desegment, 5,
            get_yushun_pdu_len, dissect_yushun_pdu, data);

    return (int)tvb_captured_length(tvb);
}

void
proto_register_yushun_modbus(void)
{
    static hf_register_info hf[] = {
        { &hf_yushun_unit_id,
          { "Unit ID", "yushun_modbus.unit_id", FT_UINT8, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},
        { &hf_yushun_crc16,
          { "CRC", "yushun_modbus.crc16", FT_UINT16, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},
        { &hf_yushun_crc16_status,
          { "CRC Status", "yushun_modbus.crc16.status", FT_UINT8, BASE_NONE,
            VALS(proto_checksum_vals), 0x0, NULL, HFILL }},
        { &hf_yushun_function_code,
          { "Function Code", "yushun_modbus.function_code", FT_UINT8, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},
        { &hf_yushun_start_address,
          { "Starting Address", "yushun_modbus.start_address", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},
        { &hf_yushun_quantity,
          { "Quantity", "yushun_modbus.quantity", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},
        { &hf_yushun_byte_count,
          { "Byte Count", "yushun_modbus.byte_count", FT_UINT8, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},
        { &hf_yushun_request_frame,
          { "Request Frame", "yushun_modbus.request_frame", FT_FRAMENUM, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_yushun_point_index,
          { "Point Index", "yushun_modbus.point_index", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},
        { &hf_yushun_point_address,
          { "Register Address", "yushun_modbus.point_address", FT_UINT16, BASE_DEC,
            NULL, 0x0, NULL, HFILL }},
        { &hf_yushun_voltage,
          { "Voltage (V)", "yushun_modbus.voltage", FT_FLOAT, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_yushun_comm_state,
          { "Communication State", "yushun_modbus.comm_state", FT_UINT8, BASE_HEX,
            VALS(yushun_comm_state_vals), 0x0, NULL, HFILL }},
        { &hf_yushun_plate_state,
          { "Plate State", "yushun_modbus.plate_state", FT_UINT8, BASE_HEX,
            VALS(yushun_plate_state_vals), 0x0, NULL, HFILL }},
        { &hf_yushun_spare,
          { "Spare", "yushun_modbus.spare", FT_UINT16, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},
        { &hf_yushun_zero_coeff,
          { "Zero Coefficient", "yushun_modbus.zero_coeff", FT_FLOAT, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_yushun_full_coeff,
          { "Full-scale Coefficient", "yushun_modbus.full_coeff", FT_FLOAT, BASE_NONE,
            NULL, 0x0, NULL, HFILL }},
        { &hf_yushun_magic,
          { "Device Magic", "yushun_modbus.magic", FT_UINT16, BASE_HEX,
            NULL, 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_yushun_modbus,
        &ett_yushun_pdu,
        &ett_yushun_unit,
    };

    static ei_register_info ei[] = {
        { &ei_yushun_crc_incorrect,
          { "yushun_modbus.crc16.incorrect", PI_CHECKSUM, PI_WARN,
            "Incorrect CRC", EXPFILL }},
        { &ei_yushun_magic_invalid,
          { "yushun_modbus.magic.invalid", PI_PROTOCOL, PI_WARN,
            "Invalid device magic (expected 0x4459)", EXPFILL }},
    };

    module_t *module;
    expert_module_t *expert;

    proto_yushun_modbus = proto_register_protocol(
            "禹舜MODBUS-下端电压硬压板协议",
            "禹舜MODBUS-下端电压硬压板",
            "yushun_modbus");

    yushun_modbus_tcp_handle = register_dissector("yushun_modbus", dissect_yushun_modbus_tcp, proto_yushun_modbus);

    proto_register_field_array(proto_yushun_modbus, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert = expert_register_protocol(proto_yushun_modbus);
    expert_register_field_array(expert, ei, array_length(ei));

    module = prefs_register_protocol(proto_yushun_modbus, NULL);
    prefs_register_bool_preference(module, "desegment",
            "Desegment Yushun MODBUS RTU over TCP",
            "Whether to desegment messages spanning multiple TCP segments",
            &global_yushun_desegment);
    prefs_register_bool_preference(module, "crc_verification",
            "Validate CRC",
            "Whether to validate the Modbus RTU CRC",
            &global_yushun_crc_verify);
}

void
proto_reg_handoff_yushun_modbus(void)
{
    dissector_add_uint_with_preference("tcp.port", YUSHUN_PORT, yushun_modbus_tcp_handle);
}
