#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from random import randint
import time

'''
BLASTER_MAC = "10:00:00:00:00:01"
	BLASTEE_MAC = "20:00:00:00:00:01"
	MIDDLEBOX_MAC_BLASTER = "40:00:00:00:00:01"
	MIDDLEBOX_MAC_BLASTEE = "40:00:00:00:00:02"

	BLASTER_IP = "192.168.100.1"
	BLASTEE_IP = "192.168.200.1"
	MIDDLEBOX_IP_BLASTER = "192.168.100.2"
	MIDDLEBOX_IP_BLASTEE = "192.168.200.2"
'''	
class Blaster(object):
	def __init__(self, net, filename):
		self.BLASTER_MAC = "10:00:00:00:00:01"
		self.MIDDLEBOX_MAC_BLASTER = "40:00:00:00:00:01"
		self.BLASTER_IP = "192.168.100.1"
		self.BLASTEE_IP = "192.168.200.1"

		self.net = net
		self.device = self.net.interfaces()[0].name
		self.retransmission = 0
		self.num_coarse_timeout = 0
		self.lhs = 1	# smallest numbered unacked packet of the window
		self.rhs = 1	# next packet to be transmitted
		# {sequence number}: [packet itself, time sent, acked or not]
		self.queue = dict()
		
		self.parse_params(filename)
		

	def parse_params(self, filename):
		with open(filename) as text_file:
			first_line = text_file.readline()
			word_list = first_line.split()
			self.num_pkt = int(word_list[1])		# number of pkts to be sent
			self.var_payload_len = int(word_list[3])		
			self.sender_window = int(word_list[5])	
			self.timeout = float(word_list[7])		# coarse timeout value in ms
			self.recv_timeout = int(word_list[9])/1000
	
	'''
	Construct a packet with sequence number specified. 
	|	ETH Hdr	|	IP Hdr	|	UDP Hdr	|	seq num (32b)	|	length (16b)	|	variable length payload		
	'''
	def construct_pkt(self, seq_num):
		pkt = Ethernet() + IPv4() + UDP()
		pkt[Ethernet].src = self.BLASTER_MAC
		pkt[Ethernet].dst = self.MIDDLEBOX_MAC_BLASTER
		pkt[IPv4].protocol = IPProtocol.UDP
		pkt[IPv4].src = self.BLASTER_IP
		pkt[IPv4].dst = self.BLASTEE_IP
		# append sequence number, length, variable length payload 
		pkt += seq_num.to_bytes(4, 'big')
		pkt += self.var_payload_len.to_bytes(2, 'big')
		pkt += bytes('a' * self.var_payload_len, 'utf8')
		return pkt


	'''
	Send a packet and record first packet sent time. Add this packet into queue and 
	increment rhs
	'''
	def send_pkt(self, seq_num):
		if seq_num == 1:
			self.first_packet_send_time = time.time()

		pkt = self.construct_pkt(seq_num)
		self.net.send_packet(self.device, pkt)
		# increment rhs
		self.rhs += 1
		# add this into our queue
		self.queue[seq_num] = [pkt, time.time(), False]

	
	''' 
	We only enter this method when rhs is unable to move because the conditions are not
	meet. 
	IMPORTANT: only send one packet per while loop (ie, send one packet per recv timeout 
	for both transmits and retransmits
	'''
	def check_timeout_and_resend(self):

		# get the earlist sent packet's seq num / key
		key_earlist = min(self.queue, key = lambda k:self.queue[k][1])
		# timeout, then resend only the first packet
		if time.time() - self.queue[key_earlist][1] > self.timeout / 1000:
			self.retransmission += 1
			self.num_coarse_timeout += 1
			self.net.send_packet(self.device, self.queue[key_earlist][0])
			self.queue[key_earlist][1] = time.time()
	
		
	'''
	Once we receive an ack, then we need to mark this packt as ack'ed in queue, or possibily 
	change lhs 
	'''
	def recv_ack(self, pkt):
		print("inside receive packet method")
		print(self.queue)
		contents = pkt[3]
		print(contents)
		seq_num = int.from_bytes((contents.data)[:4], 'big')
		print(seq_num)
		self.queue[seq_num][2] = True
		# remove this acked packet from queue
		if seq_num in self.queue:		
			del self.queue[seq_num]

		if len(self.queue) == 0:
			# TODO: test for corner case
			self.lhs = self.rhs		# queue empty, all sent packet is acked
			# last acked packet, all packets complete transmission
			if self.lhs == self.num_pkt + 1:
				self.last_packet_acked_time = time.time()
		else:
			# the lhs will be the smallest key in queue
			self.lhs = min(self.queue, key = lambda k:k)

		print(self.queue)

	def print_output(self):
		total_TX = self.last_packet_acked_time - self.first_packet_send_time
		# dividing total # sent bytes by total TX time, including all retransmissions, only consider variable length payload
		throughput = (self.num_pkt + self.retransmission) * self.var_payload_len / total_TX
		# same as before, but NOT include all retransmissions
		goodput = self.num_pkt * self.var_payload_len / total_TX
		print("Total TX time (s): " + str(total_TX))
		print("Number of reTX: " + str(self.retransmission))
		print("Number of coarse TOs: " + str(self.num_coarse_timeout))
		print("Throughput (Bps): " + str(throughput))
		print("Goodput (Bps): " + str(goodput))

	
	def blaster_main(self):
		print("inside blaster main")
		seq_num = 1

		while True:
			gotpkt = True
			try:
				#Timeout value will be parameterized!
				timestamp,dev,pkt = self.net.recv_packet(timeout = self.recv_timeout)
			except NoPackets:
				log_debug("No packets available in recv_packet")
				gotpkt = False
			except Shutdown:
				log_debug("Got shutdown signal")
				break

			if gotpkt:
				log_debug("I got a packet")
				# check if it is ACK packet from blastee
				#print("------------inside recv ack------------")
				print(pkt)
				self.recv_ack(pkt)	
				# check if transmission complete
				if self.lhs == self.num_pkt + 1:
					self.print_output()
					break	
			else:
				log_debug("Didn't receive anything")

			# send one packet per while loop 
			# check condition 1 and 2 meets, and there are more packets, then send packet
			if self.rhs - self.lhs < self.sender_window and seq_num <= self.num_pkt:
				print("blaster-inside send packet")
				self.send_pkt(seq_num)
				seq_num += 1	
				print(seq_num)
				print(self.queue)
			# condition does not meet, we need to check for timeout. 
			else: 
				self.check_timeout_and_resend()
		

	
def switchy_main(net):
	my_intf = net.interfaces()
	print(my_intf)
	mymacs = [intf.ethaddr for intf in my_intf]
	print(mymacs)
	myips = [intf.ipaddr for intf in my_intf]
	print(myips)
	print("inside switchy_main")
	blaster = Blaster(net, "blaster_params.txt")
	print("after read in parameters")
	blaster.blaster_main()
	net.shutdown()
