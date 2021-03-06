#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''
from switchyard.lib.address import *
import sys
import os
import time

from collections import OrderedDict
from switchyard.lib.packet.util import *
from switchyard.lib.userlib import *
	
				
class Router(object):
	def __init__(self, net):
		self.net = net
		# other initialization stuff here
		# initialize an empty arp table
		arp_table = {}
		
		forwarding_table = []
		# read forwarding_table.txt into forwarding_table 
		# [prefix/mask, next hop ip (str), port]
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

		self.arp_table = arp_table
		self.forwarding_table = forwarding_table



	def router_main(self):    
		'''
		Main method for router; we stay in a loop in this method, receiving
		packets until the end of time.
		'''

		# create a list for storing pending IP packets which is waiting for ARP reply
		# a list of list storing ip_packet, arp request, timestamp and number of requests. 
		# key is next hop ip address
		# next hop ip address (str): [a list of waiting ip packet, arp request packet, timestamp, num of sends, output port]
		# the list of waiiting ip packet is sorted from earliest to latest
		ip_packet_queue = OrderedDict() 

		interfaces = self.net.interfaces() # all interfaces for this router

		while True:
			gotpkt = True
			try:
				timestamp,input_port,pkt = self.net.recv_packet(timeout=1.0)
			except NoPackets:
				log_debug("No packets available in recv_packet")
				gotpkt = False
			except Shutdown:
				log_debug("Got shutdown signal")
				break


			# remove inactive request in queue
			remove = [k for k in ip_packet_queue if ip_packet_queue[k][3] >= 3 and time.time()-ip_packet_queue[k][2] >= 1]
			for k in remove: del ip_packet_queue[k]

			
			for next_hop_ip in ip_packet_queue:
				# resend arp request
				if ip_packet_queue[next_hop_ip][3] <= 2 and time.time() - ip_packet_queue[next_hop_ip][2] >= 1:
					self.net.send_packet(ip_packet_queue[next_hop_ip][4], ip_packet_queue[next_hop_ip][1])
					# change timestamp and number of requests
					ip_packet_queue[next_hop_ip][2] = time.time()
					ip_packet_queue[next_hop_ip][3] += 1


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
							arp_reply = create_ip_arp_reply(target_intf.ethaddr, arp.senderhwaddr, target_intf.ipaddr, arp.senderprotoaddr)
							self.net.send_packet(input_port, arp_reply)
				
					# For ARP reply
					if pkt.get_header(Arp).operation == ArpOperation.Reply:
						# determine whether the target ip address is an Ip address of one of intfs on the router
						target_intf = next((intf for intf in interfaces if intf.ipaddr == arp.targetprotoaddr), None)
						if target_intf != None:
							# if so, add sender ip address and sender MAC address mapping into arp_table
							self.arp_table[str(arp.senderprotoaddr)] = arp.senderhwaddr
							# complete ethernet header for the IP packet to be forwarded and send
							# 1. find the correct IP packet in the queue
							ip_packet = None
							for next_hop_ip in ip_packet_queue:
								if str(arp.senderprotoaddr) == str(next_hop_ip):	
									# a list containing waiting IP packet for this next hop ip							
									ip_packet_list = ip_packet_queue[next_hop_ip][0]
									# for each packet 
									for ip_packet in ip_packet_list:
										# 2. complete the ethernet header for this IP packet
										e = ip_packet.get_header(Ethernet)
										e.dst = arp.senderhwaddr
										e.src = self.net.interface_by_name(input_port).ethaddr
										complete_ip_packet = e + ip_packet.get_header(IPv4) + ip_packet.get_header(ICMP)
										print("-------send ip packet---------")
										print(complete_ip_packet)
										# 3. send this complete IP packet
										self.net.send_packet(input_port, complete_ip_packet)
									# 4. remove this entry from ip_packet_queue dictionary
									del ip_packet_queue[next_hop_ip]
									break
							

				# for IPv4
				elif pkt.has_header(IPv4):
					ip = pkt.get_header(IPv4)
					# decrement the TTL field in the IP header
					ip.ttl -= 1

					# if dst ip exactly matches ip address of one of interfaces, just drop packets, do nothing
					if ip.dst not in [intf.ipaddr for intf in interfaces]:
						
						# find longest prefix match
						for entry in self.forwarding_table:
							# a match found in forwarding table	
							if ip.dst in entry[0]:
								# find a longest prefix match, then send ARP query in order to get Ethernet addr 
								# corresponding to the next hop IP address
								# if next hop ip address is none, change to dst ip addr
								next_hop_IP = entry[1]
								if next_hop_IP == None:
									# next hop is connected to this router, which is the dest IP addr of incoming packet
									next_hop_IP = str(ip.dst)
								# if next hop ip in arp table, no need for arp request, then send out ip packet
								if str(next_hop_IP) in self.arp_table: 
									# complete the ether header
									e = pkt.get_header(Ethernet)	
									# ether src is out port MAC addr, dst is next hop ip's mac addr
									e.dst = self.arp_table[str(next_hop_ip)]
									e.src = self.net.interface_by_name(entry[2]).ethaddr
									complete_ip_packet = e + pkt.get_header(IPv4) + pkt.get_header(ICMP)
									self.net.send_packet(entry[2], complete_ip_packet)

								# send an ARP query in order to obtain Ethernet address corresponding to next hop IP addr
								else:					
									# if there is already a arp request for this next hop ip, which means ip in ip_packet_queue
									if str(next_hop_IP) in ip_packet_queue:
										# no need to send arp request
										ip_packet_queue[str(next_hop_IP)][0].append(pkt)
									else:
										# send arp request
										arp_request = create_ip_arp_request(self.net.interface_by_name(entry[2]).ethaddr, 
																				self.net.interface_by_name(entry[2]).ipaddr, ip_address(next_hop_IP))
										self.net.send_packet(entry[2], arp_request)
										# add this into our queue
										ip_packet_queue[str(next_hop_IP)] = [[pkt], arp_request, time.time(), 1, entry[2]]
								# break out the find prefix loop
								break
								
								
					
								
def main(net):
	'''
	Main entry point for router.  Just create Router
	object and get it going.
	'''
	r = Router(net)
	r.router_main()
	net.shutdown()
