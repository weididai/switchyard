#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''
from switchyard.lib.address import *
import sys
import os
import time
from dynamicroutingmessage import DynamicRoutingMessage
from collections import OrderedDict
from switchyard.lib.packet.util import *
from switchyard.lib.userlib import *
	
				
class Router(object):
	def __init__(self, net):
		self.net = net
		# other initialization stuff here
		# initialize an empty arp table
		arp_table = {}
		self.arp_table = arp_table

		# a list of list storing [IPv4Network (prefix/mask), next hop ip, interface name, current time]
		dynamic_routing_table = []
		DYNAMIX_ROUTING_TABLE_SIZE = 5

		forwarding_table = []
		# read forwarding_table.txt into forwarding_table 
		# [prefix/mask, next hop ip, port]
		with open("forwarding_table.txt") as text_file:
			for line in text_file:
				line_list = line.split()
				netaddr = IPv4Network(line_list[0] + "/" + line_list[1])
				forwarding_table.append([netaddr, line_list[2], line_list[3]])

		# construct forwarding table using interfaces
		interfaces = self.net.interfaces()
		for intf in interfaces:
			network_mask = IPv4Network(str(intf.ipaddr) + "/" + str(intf.netmask), strict = False)
			forwarding_table.append([network_mask, None, intf.name])

		# sort the forwarding_table by prefix length
		forwarding_table.sort(key = lambda x: x[0].prefixlen, reverse = True)
		print(forwarding_table)

		self.forwarding_table = forwarding_table
		self.dynamic_routing_table = dynamic_routing_table
		self.DYNAMIX_ROUTING_TABLE_SIZE = DYNAMIX_ROUTING_TABLE_SIZE


	def router_main(self):    
		'''
		Main method for router; we stay in a loop in this method, receiving
		packets until the end of time.
		'''


		# create a list for storing pending IP packets which is waiting for ARP reply
		# a list of list storing ip_packet, arp request, timestamp and number of requests. 
		# key is next hop ip address
		# next hop ip address: [a list of waiting ip packet, arp request packet, timestamp, num of sends, output port]
		# the list of waiiting ip packet is sorted from earliest to latest
		ip_packet_queue = OrderedDict() 

		interfaces = self.net.interfaces() # all interfaces for this router

		while True:
			gotpkt = True
			try:
				timestamp,input_port,pkt = self.net.recv_packet(timeout=1.0)
				print("packet is: ", pkt)	
			except NoPackets:
				log_debug("No packets available in recv_packet")
				gotpkt = False
			except Shutdown:
				log_debug("Got shutdown signal")
				break

			print("--------------------inside loop----------------")

			# remove inactive request in queue
			remove = [k for k in ip_packet_queue if ip_packet_queue[k][3] >= 3 and time.time()-ip_packet_queue[k][2] >= 1]
			for k in remove: del ip_packet_queue[k]

			
			for next_hop_ip in ip_packet_queue:
				# resend arp request
				if ip_packet_queue[next_hop_ip][3] <= 2 and time.time() - ip_packet_queue[next_hop_ip][2] >= 1:
					print("resend arp request")
					print(ip_packet_queue[next_hop_ip][1])
					self.net.send_packet(ip_packet_queue[next_hop_ip][4], ip_packet_queue[next_hop_ip][1])
					# change timestamp and number of requests
					ip_packet_queue[next_hop_ip][2] = time.time()
					ip_packet_queue[next_hop_ip][3] += 1
			print(ip_packet_queue)


			if gotpkt:
				log_debug("Got a packet: {}".format(str(pkt)))
			
				# For ARP 
				if pkt.has_header(Arp): 
					arp = pkt.get_header(Arp)
					
					# for ARP request
					if pkt.get_header(Arp).operation == ArpOperation.Request:
						# find the target interface with matching ip address
						target_intf = next((intf for intf in interfaces if intf.ipaddr == arp.targetprotoaddr), None) 
						# determine whether IP address destination is an IP addr assigned to interfaces of this router
						if target_intf != None:
							# if so, create and send an ARP reply to the same intf on which ARP request arrived
							print("target intf is: ", target_intf)
							arp_reply = create_ip_arp_reply(target_intf.ethaddr, arp.senderhwaddr, target_intf.ipaddr, arp.senderprotoaddr)
							print(arp_reply)
							self.net.send_packet(input_port, arp_reply)
				
					# For ARP reply
					if pkt.get_header(Arp).operation == ArpOperation.Reply:
						print("inside arp reply")
						# determine whether the target ip address is an Ip address of one of intfs on the router
						target_intf = next((intf for intf in interfaces if intf.ipaddr == arp.targetprotoaddr), None)
						if target_intf != None:
							# if so, add sender ip address and sender MAC address mapping into arp_table
							self.arp_table[arp.senderprotoaddr] = arp.senderhwaddr
							print(self.arp_table)
							# complete ethernet header for the IP packet to be forwarded and send
							# 1. find the correct IP packet in the queue
							ip_packet = None
							for next_hop_ip in ip_packet_queue:
								print(next_hop_ip)
								print(arp.senderprotoaddr)
								if str(arp.senderprotoaddr) == str(next_hop_ip):
									print("get the arp reply")		
									# a list containing waiting IP packet for this next hop ip							
									ip_packet_list = ip_packet_queue[next_hop_ip][0]
									print(ip_packet_list)
									# for each packet 
									for ip_packet in ip_packet_list:
										# 2. complete the ethernet header for this IP packet
										e = ip_packet.get_header(Ethernet)
										e.dst = arp.senderhwaddr
										complete_ip_packet = e + ip_packet.get_header(IPv4) + ip_packet.get_header(ICMP)
										# 3. send this complete IP packet
										self.net.send_packet(input_port, complete_ip_packet)
									# 4. remove this entry from ip_packet_queue dictionary
									del ip_packet_queue[next_hop_ip]
									print(ip_packet_queue)
									break
							
					print("--------------------------------------------------------------------")

				# for IPv4
				elif pkt.has_header(IPv4):
					ip = pkt.get_header(IPv4)
					# decrement the TTL field in the IP header
					ip.ttl -= 1
					
					if ip.dst in [intf.ipaddr for intf in interfaces]:
						print("inside exaclty match")
					# if dst ip exactly matches ip address of one of interfaces, just drop packets, do nothing
					if ip.dst not in [intf.ipaddr for intf in interfaces]:
						
						
						# find longest prefix match first in dynamic table then in forwarding table
						match_entry = None
						for entry in self.dynamic_routing_table:
							if ip.dst in entry[0]:
								print("inside dynamic table match")
								match_entry = entry
								break
					
						if match_entry == None:
							for entry in self.forwarding_table:
								if ip.dst in entry[0]:
									print("inside forwarding table match")
									match_entry = entry
									break

						if match_entry != None:
							print(str(ip.dst) + " and " + str(match_entry[0]))
							print(self.arp_table)
							print(match_entry[1])
							# if next hop ip address is none, change to dst ip addr
							next_hop_IP = match_entry[1]
							print(next_hop_IP)

							if next_hop_IP == None:
								# next hop is connected to this router, which is the dest IP addr of incoming packet
								next_hop_IP = ip.dst
								
							if ip_address(next_hop_IP) in self.arp_table: 
								# next hop ip address in arp table, no need for arp request, then send out ip packet
								print("inside arp match")
								print(match_entry)
								# complete the ether header
								e = ip_packet.get_header(Ethernet)
								e.dst = self.arp_table[ip.dst]
								complete_ip_packet = e + ip_packet.get_header(IPv4) + ip_packet.get_header(ICMP)
								self.net.send_packet(match_entry[2], complete_ip_packet)

							else:
								# send an ARP query in order to obtain Ethernet address corresponding to next hop IP addr
								next_hop_IP = match_entry[1]
								print(next_hop_IP)
								if next_hop_IP == None:
									# next hop is connected to this router, which is the dest IP addr of incoming packet
									next_hop_IP = ip.dst
								# if there is already a arp request for this next hop ip
								if next_hop_IP in ip_packet_queue:
									# no need to send arp request
									ip_packet_queue[next_hop_IP][0].append(pkt)
								else:
									# send arp request
									arp_request = create_ip_arp_request(self.net.interface_by_name(match_entry[2]).ethaddr, 
																		self.net.interface_by_name(match_entry[2]).ipaddr, next_hop_IP)
									print("apr request is " + str(arp_request))
									self.net.send_packet(match_entry[2], arp_request)
									# add this into our queue
									ip_packet_queue[next_hop_IP] = [[pkt], arp_request, time.time(), 1, match_entry[2]]
								print(ip_packet_queue)


				# for dynamic routing message
				elif pkt.has_header(DynamicRoutingMessage):
					if len(self.dynamic_routing_table) >= self.DYNAMIX_ROUTING_TABLE_SIZE:	
						self.dynamic_routing_table.sort(key = lambda x:x[3], reverse = True)	# sort by time.time()
						self.dynamic_routing_table.pop()
					# add new one tolist 
					self.dynamic_routing_table.append([IPv4Network(str(pkt.get_header(DynamicRoutingMessage)._advertised_prefix)
							+ "/" + str(pkt.get_header(DynamicRoutingMessage)._advertised_mask)), 
							pkt.get_header(DynamicRoutingMessage)._next_hop, input_port, time.time()])
					# sort by prefix length
					self.dynamic_routing_table.sort(key = lambda x: x[0].prefixlen, reverse = True)					
					
								
def main(net):
	'''
	Main entry point for router.  Just create Router
	object and get it going.
	'''
	r = Router(net)
	r.router_main()
	net.shutdown()
