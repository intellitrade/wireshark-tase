--
-- Copyright (c) 2020, Amichai Rothman
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <https://www.gnu.org/licenses/>.
--

--
-- This script implements a Wireshark dissector for the Tel-Aviv Stock Exchange (TASE) MDIL (UDP) protocol.
--
-- To install this script, place it in the Wireshark personal or global Lua Plugins directory
-- (see Help -> About Wireshark -> Folders -> Personal/Global Lua Plugins to find the path on your system).
--
-- To manually dissect a packet, right-click on the packet, select 'Decode As...' 
-- and select the protocol from the drop-down list.
--
-- To apply dissect heuristics, i.e. auto-detect packets that use this protocol,
-- enable the "Heuristic Detection" option in the protocol preferences.
--
-- To dissect all packets with a predefined UDP port, set the Ports option in the protocol
-- preferences. Multiple comma-separated ports can be specified, as well as port ranges.
--


-- the plugin settings
local settings = {
    ports        = "",
    heur_enabled = true,
}


-- parses a port spec string and returns an iterator over the individual
-- port numbers defined in it. The port spec consists of comma separated
-- port numbers or ranges of port numbers.
-- Example: "2345,2440-2450,3456"
local function ports_iter(str)
    -- the iterator state (as closure)
    local matcher = str:gmatch("([^,]+)")
    local port = 0
    local last = 0
    -- the iterator function
    local function iter()
        -- if we're in a range, return the next port in the range
        if port < last then
            -- advance to next port in range
            port = port + 1
        else
            -- otherwise, find the next match
            local token = matcher()
            if token == nil then return nil end
            -- check if it's a range (contains a dash)
            local dash = token.find(token, "-", 1, true)
            if dash then
                -- parse first and last ports in range
                port = tonumber(token:sub(1, dash - 1))
                last = tonumber(token:sub(dash + 1))
            else
                -- parse single port
                port = tonumber(token)
                last = port
            end
        end
        return port
    end
    -- return the iterator function
    return iter
end

-- create Proto object
local mdil = Proto("mdil", "MDIL TASE Protocol")

-- define fields
local pf_packet_length      = ProtoField.uint16("mdil.packet.length", "Packet Length")
local pf_message_count      = ProtoField.uint8("mdil.message_count", "Message Count")
local pf_feed_type          = ProtoField.new("Feed Type", "mdil.feed_type", ftypes.CHAR)
local pf_seq                = ProtoField.uint32("mdil.sequence_number", "First MDIL Sequence Number")
local pf_next_seq           = ProtoField.uint32("mdil.next_sequence_number", "Next MDIL Sequence Number")
local pf_heartbeat          = ProtoField.bool("mdil.heartbeat", "Heartbeat Packet")

local pf_message            = ProtoField.bytes("mdil.message", "Message")
local pf_message_index      = ProtoField.uint16("mdil.message.index", "Index")
local pf_message_length     = ProtoField.uint16("mdil.message.length", "Length")
local pf_message_seq        = ProtoField.uint16("mdil.message.sequence_number", "MDIL Sequence Number")
local pf_message_feed_seq   = ProtoField.uint16("mdil.message.feed_sequence_number", "Feed Sequence Number")
local pf_message_body       = ProtoField.string("mdil.message.body", "Payload")
local pf_message_gap_fill   = ProtoField.bool("mdil.message.gap_fill", "Gap Fill (Empty) Message")

mdil.fields = { 
    pf_packet_length, pf_message_count, pf_feed_type,
    pf_seq, pf_next_seq, pf_heartbeat,
    pf_message, pf_message_index, pf_message_length,
    pf_message_seq, pf_message_feed_seq, pf_message_body, pf_message_gap_fill
}


-- prepare preferences
mdil.prefs.ports = Pref.string("Ports", settings.ports, "The UDP port(s) associated with MDIL")
mdil.prefs.heur  = Pref.bool("Heuristic detection", settings.heur_enabled, "Whether heuristic dissection (autodetect) is enabled or not")

-- handle preferences changes
mdil.prefs_changed = function()
    settings.heur_enabled = mdil.prefs.heur
    -- unregister old ports and register new ports
    if settings.ports ~= mdil.prefs.ports then
        for port in ports_iter(settings.ports) do
            DissectorTable.get("udp.port"):remove(port, mdil)
        end
        for port in ports_iter(mdil.prefs.ports) do
            DissectorTable.get("udp.port"):add(port, mdil)
        end
        settings.ports = mdil.prefs.ports
    end
end

-- define the dissector

-- this function is called for every packet that we should dissect.
-- parameters are a Tvb object, a Pinfo object, and a TreeItem object.
mdil.dissector = function(tvb, pinfo, root)

    -- set the protocol column to show our protocol name
    pinfo.cols.protocol:set("MDIL")

    -- get the packet data length (we can also use tvb:len() or tvb:reported_len() here)
    local len = tvb:reported_length_remaining()

    -- validate the packet header length
    if len < 8 then
--        tree:add_proto_expert_info(ef_packet_size)
        return
    end

    -- validate the packet length field
    local packet_length = tvb:range(0,2):le_uint()
    if len ~= packet_length then
--        tree:add_proto_expert_info(ef_packet_length)
        return
    end

    -- extract field values
    local message_count = tvb:range(2,1):uint()
    local feed = tvb:range(3,1):string()
    local seq = tvb:range(4,4):le_uint()

    -- validate feed field (known values are 'R', 'M', 'B' but better be future-proof)
    if feed < 'A' or feed > 'Z' then
        --tree:add_proto_expert_info(ef_message_feed)
        return
    end

    -- add a subtree encompassing the entire packet data
    local tree = root:add(mdil, tvb:range(0, len))

    -- add common packet header fields
    tree:add_le(pf_packet_length, tvb:range(0,2))
    tree:add(pf_message_count, tvb:range(2,1))
    tree:add(pf_feed_type, tvb:range(3,1))

    local suffix = ""

    -- handle heartbeat packets
    if len == 8 and message_count == 0 then
        suffix = " (Heartbeat)"
        tree:add(pf_heartbeat, true):set_generated()
        tree:add_le(pf_next_seq, tvb:range(4,4))
    else
        -- add additional common header fields for non-heartbeats
        tree:add_le(pf_seq, tvb:range(4,4))
    end

    -- set info column text
    local info = "Feed '" .. feed .. "', " ..
        "Seq " .. seq .. ", " ..
        message_count .. " Messages" ..
        suffix
    pinfo.cols.info:set(info)
    tree:append_text(suffix)

    -- add messages subtrees
    local pos = 8
    for index = 0, message_count - 1 do
        -- validate minimal message size
        if len - pos < 2 then
            --tree:add_proto_expert_info(ef_message_size)
            return
        end

        -- validate message length
        local message_length = tvb:range(pos, 2):le_uint()
        if pos + 2 + message_length > len then
            --tree:add_proto_expert_info(ef_message_size)
            return
        end

        -- add message fields
        local message_seq = seq + index
        --local message = tree:add(pf_message, tvb:range(pos, 2 + message_length))
        local message = tree:add("Message #" .. message_seq)
        --message:add_le(pf_message_index, index):set_generated()
        message:add_le(pf_message_length, tvb:range(pos, 2))
        message:add_le(pf_message_seq, message_seq):set_generated()
        pos = pos + 2
        if message_length > 0 then
            message:add_le(pf_message_feed_seq, tvb:range(pos, 4))
            message:add(pf_message_body, tvb:range(pos + 4, message_length - 4))
        else
            -- empty payload means it's a gap fill message
            message.append_text(" (Gap Fill)")
            message:add(pf_message_gap_fill, true):set_generated()
        end
        pos = pos + message_length
    end

    -- validate that there is no leftover data
    if pos < len then
        --tree:add_expert_info(PI_MALFORMED, PI_ERROR, message_count .. " message field(s) missing")
        return
    end

    -- return how much of tvb we dissected
    return pos
end

-- define a heuristic dissector, i.e. try to detect if this packet belongs to our protocol
-- we want to be as strict as possible, so we won't grab a packet that in fact belongs
-- to a different protocol.
-- For now, we do this by simply attempting a full dissect.
local function heur_dissect_mdil(tvb, pinfo, root)
    -- delegate to full dissector (if heuristic is enabled)
    local result = settings.heur_enabled and mdil.dissector(tvb, pinfo, root)
    if (result) then
        -- if successful, make other packets in this conversation use our dissector directly
        pinfo.conversation = mdil
        return true
    end

    return false
end

-- register the heuristic dissector into the udp heuristic list
mdil:register_heuristic("udp", heur_dissect_mdil)

-- our protocol (Proto) gets automatically registered after this script ends
