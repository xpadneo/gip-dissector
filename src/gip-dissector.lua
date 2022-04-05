-- To use, place a symlink in:
--
-- ~/.wireshark/plugins/gip-dissector.lua or
-- ~/.config/wireshark/plugins/gip-dissector.lua

local gip = Proto("GIP", "Microsoft GIP Protocol")

local GIP_HDR_LEN = 4

local ms_gip_reports = {
    [0x01] = "ACKNOWLEDGE",
    [0x02] = "ANNOUNCE",
    [0x03] = "STATUS",
    [0x04] = "IDENTIFY",
    [0x05] = "POWER",
    [0x06] = "AUTHENTICATE",
    [0x07] = "GUIDE_BUTTON",
    [0x08] = "AUDIO_CONTROL",
    [0x0A] = "LED",
    [0x0B] = "HID_REPORT",
    [0x0C] = "FIRMWARE",
    [0x0D] = "DYNAMIC_LATENCY_INPUT",
    [0x1E] = "SERIAL_NUMBER",
    [0x60] = "AUDIO_SAMPLES",
}

local ms_acc_reports = {
    [0x09] = "RUMBLE",
    [0x20] = "INPUT",
}

local ms_gip_powersupply = {
    [0x00] = "USB",
    [0x04] = "disposable batteries",
    [0x08] = "rechargeable battery kit",
    [0x0C] = "invalid/unknown",
}

-- GIP Header
local pf_gip_report   = ProtoField.uint8 ("gip.gip_report", "GIP Report", base.HEX_DEC, ms_gip_reports, nil, "internal command")
local pf_acc_report   = ProtoField.uint8 ("gip.acc_report", "ACC Report", base.HEX_DEC, ms_acc_reports, nil, "external command")
local pf_client_id    = ProtoField.uint8 ("gip.client_id", "Client", base.DEC, nil, 0x0F, "session ID of a connected client")
local pf_acknowledge  = ProtoField.bool  ("gip.acknowledge", "Acknowledge", 8, nil, 0x10, "does the message require acknowledgement?")
local pf_report_type  = ProtoField.bool  ("gip.internal", "Report Type", 8, {"GIP","ACC"}, 0x20)
local pf_chunk_start  = ProtoField.bool  ("gip.chunk_start", "First Chunk", 8, nil, 0x40, "is this the first chunk?")
local pf_chunk        = ProtoField.bool  ("gip.chunk", "Chunk", 8, nil, 0x80, "is this a chunk?")
local pf_sequence     = ProtoField.uint8 ("gip.sequence", "Packet Sequence Number", base.DEC)
local pf_length       = ProtoField.bytes ("gip.length", "Payload Length", base.SPACE, nil)

-- Chunk Header
local pf_chunk_total  = ProtoField.bytes ("gip.chunk_total", "Chunk Total Parameter", base.SPACE, nil, nil)
local pf_chunk_offset = ProtoField.bytes ("gip.chunk_offset", "Chunk Offset Parameter", base.SPACE, nil, nil)

local pf_payload      = ProtoField.bytes ("gip.payload", "Unknown Data", base.SPACE)

-- GIP 0x03 Status
local pf_online       = ProtoField.bool  ("gip.online", "Online", 8, {"powered on","powering off"}, 0x80)
local pf_charging     = ProtoField.bool  ("gip.charging", "Charging", 8, nil, 0x10)
local pf_psy_mode     = ProtoField.uint8 ("gip.psy_mode", "Power Supply", base.HEX, ms_gip_powersupply, 0x0C, "power supply mode")
local pf_capacity     = ProtoField.uint8 ("gip.capacity", "Capacity", base.DEC, nil, 0x03, "battery capacity level")

-- ACC 0x20 Input
local pf_btn_a        = ProtoField.bool  ("gip.btn_a", "Button A", 8, nil, 0x10)
local pf_btn_b        = ProtoField.bool  ("gip.btn_b", "Button B", 8, nil, 0x20)
local pf_btn_x        = ProtoField.bool  ("gip.btn_x", "Button X", 8, nil, 0x40)
local pf_btn_y        = ProtoField.bool  ("gip.btn_y", "Button Y", 8, nil, 0x80)

gip.fields = {
     -- Header
    pf_gip_report, pf_acc_report,
    pf_client_id, pf_acknowledge, pf_report_type, pf_chunk_start, pf_chunk,
    pf_sequence,
    pf_length,

    -- Payloads
    pf_chunk_total, pf_chunk_offset,
    pf_payload,
    pf_online, pf_charging, pf_psy_mode, pf_capacity,
    pf_btn_a, pf_btn_b, pf_btn_x, pf_btn_y,
}

local ef_too_short = ProtoExpert.new("gip.too_short.expert", "GIP message too short", expert.group.MALFORMED, expert.severity.ERROR)

gip.experts = { ef_too_short }

local function is_internal(buffer)
    return bit.band(buffer(1,1):uint(), 0x20) > 0
end

-- unsigned LEB128 implementation
-- https://en.wikipedia.org/wiki/LEB128
local function dissect_leb128(buffer, start_offset)
    local offset, shift, byte = start_offset, 0, 0
    local value = 0

    repeat
        byte = buffer(offset,1):uint()
        offset = offset + 1

        value = bit.bor(value, bit.lshift(bit.band(byte, 0x7F), shift))
        shift = shift + 7
    until bit.band(byte, 0x80) == 0

    local length = offset - start_offset
    return value, length
end

function gip.dissector(buffer, pinfo, tree)
    local offset = GIP_HDR_LEN
    local length = buffer:len()
    if length < GIP_HDR_LEN then
        tree:add_proto_expert_info(ef_too_short)
        return 0
    end

    pinfo.cols.protocol = gip.name

    local chunk_start       = bit.band(buffer(1,1):uint(), 0x40) > 0
    local chunked           = bit.band(buffer(1,1):uint(), 0x80) > 0
    local length, length_sz = dissect_leb128(buffer, 3)

    local subtree = tree:add(gip, buffer(), "Microsoft GIP Data")
    local  header = subtree:add(gip, buffer(), "Header")
    local payload = subtree:add(gip, buffer(), "Payload")


    -- Header
    local command = buffer(0,1):uint()
    local direction = ""

    if pinfo.p2p_dir == 0 then
        direction = " out"
    elseif pinfo.p2p_dir == 1 then
        direction = " in"
    end

    if is_internal(buffer) then
        header:add(pf_gip_report, buffer(0,1))
        pinfo.cols.info = "GIP " .. ms_gip_reports[buffer(0,1):uint()] .. direction
    else
        header:add(pf_acc_report, buffer(0,1))
        pinfo.cols.info = "ACC " .. ms_acc_reports[buffer(0,1):uint()] .. direction
    end

    header:add(pf_client_id, buffer(1,1))
    header:add(pf_acknowledge, buffer(1,1))
    header:add(pf_report_type, buffer(1,1))
    header:add(pf_chunk_start, buffer(1,1))
    header:add(pf_chunk, buffer(1,1))
    header:add(pf_sequence, buffer(2,1))
    header:add(pf_length, buffer(3,length_sz)):append_text(" (" .. length .. ")")

    offset = offset + length_sz - 1

    -- Payload
    local mode = ""
    if chunked then
        local chunk_param, chunk_param_sz = dissect_leb128(buffer, offset)

        if chunk_start then
            payload:add(pf_chunk_total, buffer(offset,chunk_param_sz)):append_text(" (" .. chunk_param .. ")")
        else
            payload:add(pf_chunk_offset, buffer(offset,chunk_param_sz)):append_text(" (" .. chunk_param .. ")")
        end

        offset = offset + chunk_param_sz

        --TODO maybe reassemble packet stream? (used for TLS and audio)
        if chunked then
            mode = " (chunked)"
            if length == 0 then mode = " (end of chunks)" end
        end
    end

    if is_internal(buffer) and command == 0x03 then
        payload:add(pf_online, buffer(GIP_HDR_LEN,1))
        payload:add(pf_charging, buffer(GIP_HDR_LEN,1))
        payload:add(pf_psy_mode, buffer(GIP_HDR_LEN,1))
        payload:add(pf_capacity, buffer(GIP_HDR_LEN,1))
    elseif not is_internal(buffer) and command == 0x20 then
        payload:add(pf_btn_a, buffer(GIP_HDR_LEN,1))
        payload:add(pf_btn_b, buffer(GIP_HDR_LEN,1))
        payload:add(pf_btn_x, buffer(GIP_HDR_LEN,1))
        payload:add(pf_btn_y, buffer(GIP_HDR_LEN,1))
    elseif length > 0 then
        payload:add(pf_payload, buffer(offset,length)):append_text(mode)
    end
end

local function heuristic_checker(buffer, pinfo, tree)
    if buffer:len() < GIP_HDR_LEN then
        return false
    end

    -- internal flag set?
    if is_internal(buffer) then
        -- known internal command?
        local command = buffer(0,1):uint()
        if ms_gip_reports[command] == nil then return false end
    else
        -- known external command?
        -- TODO: need to check for detected product?
        local command = buffer(0,1):uint()
        if ms_acc_reports[command] == nil then return false end
    end

    -- calculate expected length with LEB128 fields
    local payload, payload_sz = dissect_leb128(buffer, 3)
    local      payload_offset = payload_sz + GIP_HDR_LEN - 1
    local            expected = payload_offset + payload

    local chunked = bit.band(buffer(1,1):uint(), 0x80) > 0
    if chunked then
        local chunk_param, chunk_param_sz = dissect_leb128(buffer, payload_offset)
        expected = expected + chunk_param_sz
    end

    -- length does match?
    if expected ~= buffer:len() then return false end

    -- seems to be a GIP conversation
    gip.dissector(buffer, pinfo, tree)
    --pinfo.conversation = gip

    return true
end

gip:register_heuristic("usb.interrupt", heuristic_checker)
