#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time

from switchyard.lib.packet.util import *
from switchyard.lib.userlib import *

class Router(object):
	def __init__(self, net):
		self.net = net
		# other initialization stuff here
		# initialize an empty arp table
		arp_table = {}


	def router_main(self):    
		'''
		Main method for router; we stay in a loop in this method, receiving
		packets until the end of time.
		'''
		while True:
			gotpkt = True
			try:
				timestamp,input_port,pkt = self.net.recv_packet(timeout=1.0)
				print("packet is: ", pkt)
				interfaces = self.net.interfaces() # all interfaces for this router
			except NoPackets:
				log_debug("No packets available in recv_packet")
				gotpkt = False
			except Shutdown:
				log_debug("Got shutdown signal")
				break

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
						# determine whether the target ip address is an Ip address of one of intfs on the router
						target_intf = next((intf for intf in interfaces if intf.ipaddr == arp.targetprotoaddr), None)
						if target_intf != None:
							# if so, add sender ip address and sender MAC address mapping into arp_table
							arp_table[arp.senderprotoaddr] = arp.senderhwaddr
					print("--------------------------------------------------------------------")
				
						
					
def main(net):
	'''
	Main entry point for router.  Just create Router
	object and get it going.
	'''
	r = Router(net)
	r.router_main()
	net.shutdown()
