#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import random
import time

def drop(percent):
    return random.randrange(100) < percent

def switchy_main(net):

	BLASTER_MAC = "10:00:00:00:00:01"
	BLASTEE_MAC = "20:00:00:00:00:01"
	MIDDLEBOX_MAC_BLASTER = "40:00:00:00:00:01"
	MIDDLEBOX_MAC_BLASTEE = "40:00:00:00:00:02"

	BLASTER_IP = "192.168.100.1"
	BLASTEE_IP = "192.168.200.1"
	MIDDLEBOX_IP_BLASTER = "192.168.100.2"
	MIDDLEBOX_IP_BLASTEE = "192.168.200.2"
	
		
	# extract seed and possibility from middlebox_params.txt
	text_file = open("middlebox_params.txt")
	first_line = text_file.readline()
	word_list = first_line.split()
	random_seed = int(word_list[1]) # seed after -s
	probability = int(word_list[3])
	
	# set the random_seed
	random.seed(random_seed) 

	my_intf = net.interfaces()
	mymacs = [intf.ethaddr for intf in my_intf]
	myips = [intf.ipaddr for intf in my_intf]


	count = 0
	while True:
		gotpkt = True
		try:
			timestamp,dev,pkt = net.recv_packet()
			log_debug("Device is {}".format(dev))
		except NoPackets:
			log_debug("No packets available in recv_packet")
			gotpkt = False
		except Shutdown:
			log_debug("Got shutdown signal")
			break

		if gotpkt:

			log_debug("I got a packet {}".format(pkt))
			# packet from baster
			if dev == "middlebox-eth0":
				count += 1
				log_debug("Received from blaster")
				# NOT drop the packet, modify headers and send 
				if drop(probability) == False: 
					# ether src is out port MAC addr, dst is next hop ip's mac addr
					pkt[Ethernet].src = MIDDLEBOX_MAC_BLASTEE
					pkt[Ethernet].dst = BLASTEE_MAC
					net.send_packet("middlebox-eth1", pkt)

			elif dev == "middlebox-eth1":
				log_debug("Received from blastee")
				pkt[Ethernet].src = MIDDLEBOX_MAC_BLASTER
				pkt[Ethernet].dst = BLASTER_MAC		
				net.send_packet("middlebox-eth0", pkt)
				
			else:
				log_debug("Oops :))")

	net.shutdown()
