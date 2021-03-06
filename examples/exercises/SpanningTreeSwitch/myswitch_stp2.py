'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import time
import threading
from spanningtreemessage import SpanningTreeMessage
from threading import Thread


def main(net):


	''' A function for root node to generate and send STP packets every 2 seconds'''
	def generate_and_send_STPpackets():
		while rootID == switchID:
			print(time.ctime())
			# initialize spanningTreeMessage, the root is switch itself, and number of hops is 0
			spm = SpanningTreeMessage(root = switchID)
			# spanning tree packet
			spp = Ethernet(src = switchID, dst = "ff:ff:ff:ff:ff:ff", ethertype = 34825) + spm
			for intf in my_interfaces:
				net.send_packet(intf.name, spp)
			#t = threading.Timer(2, generate_and_send_STPpackets)
			time.sleep(2)
			'''print("rootI ", rootID)
			print("switchID ", switchID)'''
			'''if rootID == switchID:	#check if this switch is root
				print("inside thread")
				t.start()'''
	


	MAX_ENTRIES = 5
	INITIAL_MODE = 0
	FORWARDING_MODE = 1
	BLOCKING_MODE = 2
	
	

	# a list of interfaces that are configured on network devices
	my_interfaces = net.interfaces()	
	mymacs = [intf.ethaddr for intf in my_interfaces]

	# initialize all interfaces' mode to INITIAL MODE
	mode_dict = dict.fromkeys((intf.name for intf in my_interfaces), FORWARDING_MODE)
	print(mode_dict)


	# initialize the ID for this switch to be the smallest Ethernet address among all ports
	switchID = min(my_interfaces, key = lambda x:x.ethaddr.toStr()).ethaddr.toStr()
	rootID = switchID # initialize root ID to be itself
	hops_to_root = 0
	time_spm = 0 # time at which the last spm was received 
	root_interface = None #for non root node, which interface on which spm from perceived root arrives 

	generate_and_send_STPpackets()
	timerThread = threading.Thread(target = generate_and_send_STPpackets)
	timerThread.deamon = True
	timerThread.start()

	# this table contains 5 entries
	lookup_table = dict()
	

	while True:
		try:
			timestamp,input_port,packet = net.recv_packet()
			time_spm = time.ctime()
			print(str(packet))
			print(str(input_port))
			print(time_spm)
			print("packet length is ", packet.num_headers())
		except NoPackets:
			continue
		except Shutdown:
			return

		# for spanning tree packet, there is only 2 headers
		if packet.num_headers() == 2:
			# 5.1 if received packet root ID is smaller than current, change rootID, number of hoops, fowarding to all interfaces except the one received
			if packet[1].root.toStr() < rootID:
				root_interface = input_port
				rootID = packet[1].root.toStr()
				hops_to_root = packet[1].hops_to_root + 1	
				spm = SpanningTreeMessage(root = rootID, hops_to_root = hops_to_root)
				spp = Ethernet(src = switchID, dst = "ff:ff:ff:ff:ff:ff", ethertype = 34825) + spm
				for intf in my_interfaces:
					if input_port != intf.name:
						net.send_packet(intf.name, spp)
						mode_dict[intf.name] = FORWARDING_MODE
			elif packet[1].root.toStr() == rootID:
				# 5.2 hops to root + 1 is smaller than current number of hops, forward to all interfaces
				if packet[1].hops_to_root + 1 < hops_to_root:
					print("inside smaller hops")
					root_interface = input_port
					hops_to_root = packet[1].hops_to_root + 1
					spm = SpanningTreeMessage(root = rootID, hops_to_root = hops_to_root)
					spp = Ethernet(src = switchID, dst = "ff:ff:ff:ff:ff:ff", ethertype = 34825) + spm
					for intf in my_interfaces:
						if input_port != intf.name:
							net.send_packet(intf.name, spp)
							mode_dict[intf.name] = FORWARDING_MODE
				# number of hops is same, but switch recives spm from different interface, 
				# 5.3 change the interface on which this packet arrived to blocking mode
				elif packet[1].hops_to_root + 1 == hops_to_root and root_interface != input_port:
					mode_dict[input_port] = BLOCKING_MODE
			print(mode_dict)
			print(rootID)
			print(hops_to_root)
			print(root_interface)
			print("--------------------------------------------------------")

		# for normal packet
		elif packet.num_headers() == 3:
			# packet source does not in our lookup_table, add this into our table using LRU
			if packet[0].src not in lookup_table:
				# if no empty slot, using LRU to remove 
				if len(lookup_table.keys()) >= MAX_ENTRIES:
					sortedTable = sorted(lookup_table.items(), key=lambda x: x[1][1])
					print(sortedTable)
					print(sortedTable[0][0])
					lookup_table.pop(sortedTable[0][0])
				lookup_table[packet[0].src] = (input_port, time.time())
			# packet source dst in lookup_table		
			else:
				# check if incoming port for packet same as port info in table
				if input_port != lookup_table[packet[0].src][0]:
					lookup_table[packet[0].src] = (input_port, lookup_table[packet[0].dst][1])

			log_info("packet destination {}".format(packet[0].dst))

			print(type(packet[0].dst))
			log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
			if packet[0].dst in mymacs:
				log_debug ("Packet intended for me")	
			else:
				# destination is in our table, then update timestamp and send packet out the interface/port we previously learned
				if packet[0].dst in lookup_table:
					print("inside change dst timestamp")
					lookup_table[packet[0].dst] = (lookup_table[packet[0].dst][0], time.time())
					net.send_packet(lookup_table[packet[0].dst][0], packet)
				else:
					# floods packets to all ports whose mode in forwarding except input port 
					for intf in my_interfaces:
						if input_port != intf.name and mode_dict[intf.name] == FORWARDING_MODE:
							log_debug ("Flooding packet {} to {}".format(packet, intf.name))
							net.send_packet(intf.name, packet)
			print(timestamp)
			print(str(lookup_table))
			print("--------------------------------------------------")

	net.shutdown()
