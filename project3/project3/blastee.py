#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import time


'''
data packet
|	ETH Hdr	|	IP Hdr	|	UDP Hdr	|	seq num (32 bits)	|	length (16 bits)	|	variable length payload
'''

'''
ACK packet
|	ETH Hdr	|	IP Hdr	|	UDP Hdr	|	seq num (32 bits)	|	payload (8 bits)	|
'''




def switchy_main(net):


	BLASTER_MAC = "10:00:00:00:00:01"
	BLASTEE_MAC = "20:00:00:00:00:01"
	MIDDLEBOX_MAC_BLASTER = "40:00:00:00:00:01"
	MIDDLEBOX_MAC_BLASTEE = "40:00:00:00:00:02"

	BLASTER_IP = "192.168.100.1"
	BLASTEE_IP = "192.168.200.1"
	MIDDLEBOX_IP_BLASTER = "192.168.100.2"
	MIDDLEBOX_IP_BLASTEE = "192.168.200.2"


	my_interfaces = net.interfaces()
	mymacs = [intf.ethaddr for intf in my_interfaces]

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
			log_debug("I got a packet from {}".format(dev))
			log_debug("Pkt: {}".format(pkt))
			seq_num = int.from_bytes(pkt[3].data[:4], 'big')
			# modify the Ethernet and IPv4 header
			new_pkt = Ethernet() + IPv4() + UDP()
			new_pkt[Ethernet].src = BLASTEE_MAC
			new_pkt[Ethernet].dst = MIDDLEBOX_MAC_BLASTEE
			new_pkt[IPv4].protocol = IPProtocol.UDP
			new_pkt[IPv4].src = BLASTEE_IP
			new_pkt[IPv4].dst = BLASTER_IP
			# keep the sequence number and then extract Length field and keep 8 bits payload			

			new_pkt += seq_num.to_bytes(4, 'big')
			# length of varible size payload in data packet less than 8bytes, padding by zero
			length = int.from_bytes(pkt[3].data[4:6], 'big')
			if length < 8:
				new_pkt += bytes(pkt[3].data[6:].decode(), 'utf8')
				# pad with a 
				new_pkt += bytes("a" * (8-length), 'utf8')
			else:
				new_pkt += bytes(pkt[3].data[6:14].decode(), 'utf8')
			
		
			#TODO: less than 8 bits
			net.send_packet(dev, new_pkt)
		


	net.shutdown()
