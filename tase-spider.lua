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
-- This script implements a Wireshark dissector for the Tel-Aviv Stock Exchange (TASE) Spider (TCP) protocol.
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
-- To dissect all packets with a predefined port, set the Ports option in the protocol
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
local spider = Proto("spider", "Spider TASE Protocol")

-- define fields
local COMPRESSION_FLAG_DESCRIPTION = {
    [0] = "Uncompressed Full Data",
    [1] = "Compressed Full Data",
    [2] = "Uncompressed Latest Updates",
    [3] = "Compressed Latest Updates"
}

local f = {
    type = ProtoField.new("Message Type", "spider.type", ftypes.CHAR),
    seq = ProtoField.uint32("spider.sequence_number", "Feed Sequence Number"),
    length = ProtoField.uint32("spider.length", "Message Length"),
    body = ProtoField.string("spider.body", "Payload"),
    
    userid = ProtoField.stringz("spider.login.userid", "User ID"),
    password = ProtoField.stringz("spider.login.password", "Password"),
    compression_flag = ProtoField.new("Compression Flag", "spider.login.compression_flag", ftypes.UINT8, COMPRESSION_FLAG_DESCRIPTION),
    reserved = ProtoField.new("Reserved", "spider.login.reserved", ftypes.NONE)
}
spider.fields = f


-- prepare preferences
spider.prefs.ports = Pref.string("Ports", settings.ports, "The TCP port(s) associated with Spider")
spider.prefs.heur  = Pref.bool("Heuristic detection", settings.heur_enabled, "Whether heuristic dissection (autodetect) is enabled or not")

-- handle preferences changes
spider.prefs_changed = function()
    settings.heur_enabled = spider.prefs.heur
    -- unregister old ports and register new ports
    if settings.ports ~= spider.prefs.ports then
        for port in ports_iter(settings.ports) do
            DissectorTable.get("tcp.port"):remove(port, spider)
        end
        for port in ports_iter(spider.prefs.ports) do
            DissectorTable.get("tcp.port"):add(port, spider)
        end
        settings.ports = spider.prefs.ports
    end
end

-- define the dissector

-- dissects a login message
local function dissect_login_message(tvb, pinfo, root)

    -- get the remaining number of bytes available
    local len = tvb:len()
    local message_length = 95

    -- if we got a partial broken packet then abort
    if len ~= tvb:reported_length_remaining() then
        return 0
    end

    -- validate message isn't too long (nothing sent beyond login message)
    if len > message_length then
        return 0
    end

    -- if we don't have enough bytes, return the number of missing bytes (negative)
    if len < message_length then
        return -message_length
    end

    -- extract field values
    local userid = tvb:range(0, 30):stringz()
    local seq = tvb:range(50, 4):uint()
    local flag = tvb:range(54, 1):uint()
    local reserved = tvb:raw(55, 40)

    -- validate flags
    if flag > 3 then return 0 end
    -- validate reserved bytes (all zeros)
    if not reserved:find("^\0+$") then return 0 end

    -- set the protocol column to show our protocol name
    pinfo.cols.protocol:set("Spider")

    -- add a subtree encompassing the entire message data
    local tree = root:add(spider, tvb:range(0, message_length))

    -- add message header fields
    tree:add(f.userid, tvb:range(0, 30))
    tree:add(f.password, tvb:range(30, 20)) -- we don't decrypt this for security reasons
    tree:add(f.seq, tvb:range(50, 4))
    tree:add(f.compression_flag, tvb:range(54, 1))
    tree:add(f.reserved, tvb:range(55, 40))

    -- set info column text
    local info = "Login User ID '" .. userid ..
        "', Seq " .. seq ..
        ", Flag " .. COMPRESSION_FLAG_DESCRIPTION[flag] .. " (" .. flag .. ")"
    pinfo.cols.info:set(info)
    tree:append_text(" (Login)")

    return message_length
end

-- dissects a message
local function dissect_message(tvb, pinfo, root, pos)

    -- get the remaining number of bytes available
    local len = tvb:len() - pos

    -- if we got a partial broken packet then abort
    if len ~= tvb:reported_length_remaining(pos) then
        return 0
    end

    -- if we don't even have a header, we don't know exactly how many bytes
    -- are missing in this message, so return a generic 'need more bytes' result (negative)
    if len < 9 then
        return -DESEGMENT_ONE_MORE_SEGMENT
    end

    -- convert tvb to be relative to current message's starting position
    tvb = tvb:range(pos)

    -- get message length field
    local body_length = tvb:range(5, 4):uint()
    local message_length = 9 + body_length

    -- validate message length is reasonable
    if message_length > 1000000 then
        return 0
    end

    -- if we know exactly how many bytes are in the message but don't
    -- have enough available, then request (negative) missing number of bytes
    if len < message_length then
        return -(message_length - len)
    end

    -- extract header field values
    local type = tvb:range(0, 1):string()
    local seq = tvb:range(1, 4):uint()

    -- validate message type
    if type ~= 'M' and type ~= 'E' then
        --tree:add_proto_expert_info(ef_message_feed)
        return 0
    end

    -- set the protocol column to show our protocol name
    pinfo.cols.protocol:set("Spider")

    -- add a subtree encompassing the entire message data
    local tree = root:add(spider, tvb:range(0, message_length), "Spider Message #" .. seq)

    -- add message header fields
    tree:add(f.type, tvb:range(0, 1))
    tree:add(f.seq, tvb:range(1, 4))
    tree:add(f.length, tvb:range(5, 4))
    tree:add(f.body, tvb:range(9, body_length))

    -- set info column text
    local suffix = type == 'E' and " (Error)" or ""
    local info = tostring(pinfo.cols.info)
    local first_seq = string.match(info, "Seq (%d+)")
    first_seq = first_seq and (first_seq .. "-") or ""
    pinfo.cols.info:clear_fence() -- prevents interference between multiple messages in same packet
    pinfo.cols.info:set("Seq " .. first_seq .. seq .. suffix)
    tree:append_text(suffix)

    -- return how much of tvb we dissected
    return message_length
end

-- this function is called for every packet that we should dissect.
-- parameters are a Tvb object, a Pinfo object, and a TreeItem object.
spider.dissector = function(tvb, pinfo, root)
    -- in the TCP stream there can be multiple messages in each packet
    -- or a single message split between two packets, so we have to
    -- try dissecting messages in a loop, passing the leftovers on to
    -- the next packet's processing via the desegment mechanism
    local len = tvb:len()
    local pos = 0

    -- dissect all other messages
    while pos < len do
        local result = dissect_message(tvb, pinfo, root, pos)
        -- result is positive bytes processed in message, or zero if error,
        -- or negative bytes missing from partial message
        if result > 0 then
            -- successfully dissected a message, continue to the next
            pos = pos + result
        elseif result == 0 then
            -- if we're at the beginning of a packet, and couldn't
            -- dissect the message, then perhaps it's a login message
            if pos == 0 then
                -- dissect login message
                return dissect_login_message(tvb, pinfo, root)
            end
            -- error during dissection, return error and abort
            return 0
        else -- negative result
            -- we have a partial message and need more bytes from stream -
            -- the next segment we'll be given to process will start
            -- at desegment_offset of the current buffer, and extend
            -- to desegment_len additional new bytes from the next packet
            pinfo.desegment_offset = pos
            pinfo.desegment_len = -result
            return len
        end
    end

    return pos
end

-- define a heuristic dissector, i.e. try to detect if this packet belongs to our protocol
-- we want to be as strict as possible, so we won't grab a packet that in fact belongs
-- to a different protocol.
-- For now, we do this by simply attempting a full dissect.
local function heur_dissect_spider(tvb, pinfo, root)
    -- delegate to full dissector (if heuristic is enabled)
    local result = settings.heur_enabled and spider.dissector(tvb, pinfo, root)
    if (result) then
        -- if successful, make other packets in this conversation use our dissector directly
        pinfo.conversation = spider
        return true
    end

    return false
end

-- register the heuristic dissector into the tcp heuristic list
spider:register_heuristic("tcp", heur_dissect_spider)

-- our protocol (Proto) gets automatically registered after this script ends
