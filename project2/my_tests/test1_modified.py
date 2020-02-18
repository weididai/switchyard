import struct
import time
from ipaddress import IPv4Address
from switchyard.lib.userlib import *
from switchyard.lib.packet import *

'''make IP packet'''
def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False, ttl = 64):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=ttl)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt


def router_tests():
	
	basic_tests()
	test_for_arp_table()
	test_for_exact_match_intf_ip()
	test_for_same_ip_arp_request()
	test_for_arp_request_not_respond()
	
	


def basic_tests():

	s = TestScenario("-----------------------------Basic Tests-------------------------------")
	# Initialize switch with 3 ports.
	s.add_interface('router-eth0', '10:00:00:00:00:01', ipaddr = '192.168.1.1', netmask = '255.255.255.252')
	s.add_interface('router-eth1', '10:00:00:00:00:02', ipaddr = '10.10.0.1', netmask = '255.255.0.0')
	s.add_interface('router-eth2', '10:00:00:00:00:03', ipaddr = '172.16.42.1', netmask = '255.255.255.0')
	
	# 1   IP packet to be forwarded to 172.16.42.2 should arrive on
	#     router-eth0
	#         Expected event: recv_packet Ethernet
	#         10:00:00:00:00:03->30:00:00:00:00:01 IP | IPv4
	#         192.168.1.100->172.16.42.2 ICMP | ICMP EchoRequest 0 42 (0
	#         data bytes) on router-eth0

	packet = mk_pkt(hwsrc = '10:00:00:00:00:03', hwdst =  'ff:ff:ff:ff:ff:ff', ipsrc  = '192.168.1.100', ipdst = '172.16.42.2') #next hop ip is 172.16.42.1
	s.expect(PacketInputEvent("router-eth0", packet), "IP packet to be forwarded to 172.16.42.2 should arrive on router-eth0")

	# 2   Router should send ARP request for 172.16.42.2 out router-
	#     eth2 interface
	#         Expected event: send_packet(s) Ethernet
	#         10:00:00:00:00:03->ff:ff:ff:ff:ff:ff ARP | Arp
	#         10:00:00:00:00:03:172.16.42.1 ff:ff:ff:ff:ff:ff:172.16.42.2
	#         out router-eth2

	arp_request  = create_ip_arp_request('10:00:00:00:00:03', '172.16.42.1', '172.16.42.2')
	s.expect(PacketOutputEvent("router-eth2", arp_request), "Router should send ARP request for 172.16.42.2 out router-eth2 interface")

	# 3   Router should receive ARP response for 172.16.42.2 on
	#     router-eth2 interface
	#         Expected event: recv_packet Ethernet
	#         30:00:00:00:00:01->10:00:00:00:00:03 ARP | Arp
	#         30:00:00:00:00:01:172.16.42.2 10:00:00:00:00:03:172.16.42.1
	#         on router-eth2

	arp_response = create_ip_arp_reply('30:00:00:00:00:01', '10:00:00:00:00:03',
                                       '172.16.42.2', '172.16.42.1')
	s.expect(PacketInputEvent("router-eth2", arp_response), "Router should receive ARP response for 172.16.42.2 on router-eth2 interface")


	# 4   IP packet should be forwarded to 172.16.42.2 out router-eth2
	#         Expected event: send_packet(s) Ethernet
	#         10:00:00:00:00:03->30:00:00:00:00:01 IP | IPv4
	#         192.168.1.100->172.16.42.2 ICMP | ICMP EchoRequest 0 42 (0
	#         data bytes) out router-eth2

	packet = mk_pkt(hwsrc='10:00:00:00:00:03', hwdst='30:00:00:00:00:01', ipsrc='192.168.1.100', ipdst='172.16.42.2', ttl=63)
	s.expect(PacketOutputEvent("router-eth2", packet), "IP packet should be forwarded to 172.16.42.2 out router-eth2")




def test_for_arp_table():
	s = TestScenario("---------------------Arp Table Tests-----------------------------")
	# Initialize switch with 3 ports.
	s.add_interface('router-eth0', '10:00:00:00:00:01', ipaddr = '192.168.1.1', netmask = '255.255.255.252')
	s.add_interface('router-eth1', '10:00:00:00:00:02', ipaddr = '10.10.0.1', netmask = '255.255.0.0')
	s.add_interface('router-eth2', '10:00:00:00:00:03', ipaddr = '172.16.42.1', netmask = '255.255.255.0')
	
	

	# 5 Arp table should have one entry MAC: 30:00:00:00:00:01 and IP: 172.16.42.2. Same packet as in test 1
	#			Expected event: recv_packet Ethernet
	#       	10:00:00:00:00:03->30:00:00:00:00:01 IP | IPv4
	#        192.168.1.100->172.16.42.2 ICMP | ICMP EchoRequest 0 42 (0
	#        data bytes) on router-eth0
	
	packet = mk_pkt(hwsrc = '10:00:00:00:00:03', hwdst =  'ff:ff:ff:ff:ff:ff', ipsrc  = '192.168.1.100', ipdst = '172.16.42.2') 
	s.expect(PacketInputEvent("router-eth0", packet), "IP packet to be forwarded to 172.16.42.2 should arrive on router-eth0")

	# 6   IP packet should be forwarded to 172.16.42.2 out router-eth2
	#         Expected event: send_packet(s) Ethernet
	#         10:00:00:00:00:03->30:00:00:00:00:01 IP | IPv4
	#         192.168.1.100->172.16.42.2 ICMP | ICMP EchoRequest 0 42 (0
	#         data bytes) out router-eth2

	packet = mk_pkt(hwsrc='10:00:00:00:00:03', hwdst='30:00:00:00:00:01', ipsrc='192.168.1.100', ipdst='172.16.42.2', ttl=63)
	s.expect(PacketOutputEvent("router-eth2", packet), "IP packet should be forwarded to 172.16.42.2 out router-eth2")


def test_for_exact_match_intf_ip():
		
	s = TestScenario("---------------------Exact Match IP dst Tests-----------------------------")
	# Initialize switch with 3 ports.
	s.add_interface('router-eth0', '10:00:00:00:00:01', ipaddr = '192.168.1.1', netmask = '255.255.255.252')
	s.add_interface('router-eth1', '10:00:00:00:00:02', ipaddr = '10.10.0.1', netmask = '255.255.0.0')
	s.add_interface('router-eth2', '10:00:00:00:00:03', ipaddr = '172.16.42.1', netmask = '255.255.255.0')

	# 7 exactly same match, just drop and do nothing 
	packet = mk_pkt(hwsrc = '10:00:00:00:00:03', hwdst =  'ff:ff:ff:ff:ff:ff', ipsrc  = '192.168.1.100', ipdst = '192.168.1.1') #next hop ip is 172.16.42.1
	s.expect(PacketInputEvent("router-eth0", packet), "exactly match, just drop, IP packet to be forwarded to 192.168.1.1 should arrive on router-eth0")


'''
if a packet arrives, then we send arp request, if another packet with same IP address dst arrives, we do NOT
send another arp request, and we do NOT change timestamp
'''
def test_for_same_ip_arp_request():
	
	s = TestScenario("---------------------Same Next Hop IP Tests-----------------------------")
	# Initialize switch with 3 ports.
	s.add_interface('router-eth0', '10:00:00:00:00:01', ipaddr = '192.168.1.1', netmask = '255.255.255.252')
	s.add_interface('router-eth1', '10:00:00:00:00:02', ipaddr = '10.10.0.1', netmask = '255.255.0.0')
	s.add_interface('router-eth2', '10:00:00:00:00:03', ipaddr = '172.16.42.1', netmask = '255.255.255.0')

	# 8 forward to 172.16.160.0, next hop ip is 10.10.0.254 and output port is eth1
	packet = mk_pkt(hwsrc = '10:00:00:00:00:03', hwdst =  'ff:ff:ff:ff:ff:ff', ipsrc  = '192.168.1.100', ipdst = '172.16.160.0') 
	#next hop ip is 10.10.0.254 and output port is eth1
	s.expect(PacketInputEvent("router-eth0", packet), "IP packet to be forwarded to 172.16.160.0 should arrive on router-eth0")

	# 9 arp packet out at eth1
	arp_request  = create_ip_arp_request('10:00:00:00:00:02', '10.10.0.1', '10.10.0.254')
	s.expect(PacketOutputEvent("router-eth1", arp_request), "Router should send ARP request for 10.10.0.254 out router-eth1 interface")

	# 10 forward to 172.16.176.2, next hop ip is 10.10.0.254 and output port is eth1
	packet = mk_pkt(hwsrc = '10:00:00:00:00:03', hwdst =  'ff:ff:ff:ff:ff:ff', ipsrc  = '192.168.1.100', ipdst = '172.16.176.2') 
	#next hop ip is 10.10.0.254 and output port is eth1
	s.expect(PacketInputEvent("router-eth0", packet), "IP packet to be forwarded to 172.16.176.2 should arrive on router-eth0")
	# no arp request should send 

	# 11 get arp reply 
	arp_response = create_ip_arp_reply('40:00:00:00:00:01', '10:00:00:00:00:02', '10.10.0.254', '10.10.0.1')
	s.expect(PacketInputEvent("router-eth1", arp_response), "Router should receive ARP response for 10.10.0.254 on router-eth1 interface")


	# 12 IP packet should be forwarded to 172.16.160.0 out router-eth1
	packet = mk_pkt(hwsrc='10:00:00:00:00:03', hwdst='40:00:00:00:00:01', ipsrc  = '192.168.1.100', ipdst = '172.16.160.0', ttl=63)
	s.expect(PacketOutputEvent("router-eth1", packet), "IP packet should be forwarded to 172.16.160.0 out router-eth1")

	
	# 13 IP packet should be forwarded to 172.16.176.2 out router-eth1
	packet = mk_pkt(hwsrc='10:00:00:00:00:03', hwdst='40:00:00:00:00:01', ipsrc  = '192.168.1.100', ipdst = '172.16.176.2', ttl=63)
	s.expect(PacketOutputEvent("router-eth1", packet), "IP packet should be forwarded to 172.16.176.2 out router-eth1")




def test_for_arp_request_not_respond():

	s = TestScenario("---------------------Arp Request Not Responding Tests-----------------------------")
	# Initialize switch with 3 ports.
	s.add_interface('router-eth0', '10:00:00:00:00:01', ipaddr = '192.168.1.1', netmask = '255.255.255.252')
	s.add_interface('router-eth1', '10:00:00:00:00:02', ipaddr = '10.10.0.1', netmask = '255.255.0.0')
	s.add_interface('router-eth2', '10:00:00:00:00:03', ipaddr = '172.16.42.1', netmask = '255.255.255.0')

	# 14 IP packet with unknown dst ip, send arp request for 192.168.100.2, port is eth0, next hop is 192.168.100.1
	#			Expected event: send packets Arp request 
	packet = mk_pkt(hwsrc = '30:00:00:00:00:01', hwdst =  'ff:ff:ff:ff:ff:ff', ipsrc  = '172.16.42.2', ipdst = '172.16.128.1') 
	s.expect(PacketInputEvent("router-eth1", packet), "IP packet to be forwarded to 172.16.128.1 should arrive on router-eth1")

	# 15 arp request for 192.168.100.2, first time
	arp_request  = create_ip_arp_request('10:00:00:00:00:02', '10.10.0.1', '10.10.0.254')
	s.expect(PacketOutputEvent("router-eth1", arp_request), "Router should send ARP request for 10.10.0.254 out router-eth1 interface, first")
	
	

	# 16 IP packet with unknown dst ip 10.100.2.2
	packet = mk_pkt(hwsrc = '30:00:00:00:00:01', hwdst =  'ff:ff:ff:ff:ff:ff', ipsrc  = '172.16.42.2', ipdst = '10.100.2.2') 
	s.expect(PacketInputEvent("router-eth1", packet), "IP packet to be forwarded to 10.100.2.2 should arrive on router-eth1")
	
		
	# 17 arp request for 172.16.42.2, first time
	arp_request  = create_ip_arp_request('10:00:00:00:00:03', '172.16.42.1', '172.16.42.2')
	s.expect(PacketOutputEvent("router-eth2", arp_request), "Router should send ARP request for 172.16.42.2 out router-eth1 interface, first")
	
	 
	time.sleep(0.9)
	# 18
	s.expect(PacketInputTimeoutEvent(1), "timeout")

	# 19 arp request for 192.168.100.2, second time, same packet for 8, second time
	arp_request  = create_ip_arp_request('10:00:00:00:00:02', '10.10.0.1', '10.10.0.254')
	s.expect(PacketOutputEvent("router-eth1", arp_request), "Router should send ARP request for 10.10.0.254 out router-eth1 interface, second")


	# 20 arp request for 172.16.42.2, second time
	arp_request  = create_ip_arp_request('10:00:00:00:00:03', '172.16.42.1', '172.16.42.2')
	s.expect(PacketOutputEvent("router-eth2", arp_request), "Router should send ARP request for 172.16.42.2 out router-eth1 interface, second")

	time.sleep(0.9)
	# 21
	s.expect(PacketInputTimeoutEvent(1), "timeout")
 
	# 22 arp request for 192.168.100.2, second time, same packet for 8, third time
	arp_request  = create_ip_arp_request('10:00:00:00:00:02', '10.10.0.1', '10.10.0.254')
	s.expect(PacketOutputEvent("router-eth1", arp_request), "Router should send ARP request for 10.10.0.254 out router-eth1 interface, third")


	# 23 arp request for 172.16.42.2, third time
	arp_request  = create_ip_arp_request('10:00:00:00:00:03', '172.16.42.1', '172.16.42.2')
	s.expect(PacketOutputEvent("router-eth2", arp_request), "Router should send ARP request for 172.16.42.2 out router-eth1 interface, third")

	time.sleep(0.9)
	# 24
	s.expect(PacketInputTimeoutEvent(1), "timeout") 

	# 25 packet should be dropped, ip_packet_queue should be empty, test that ip_packet_queue empty by send same ip packet as 14,
	# should send arp request
	packet = mk_pkt(hwsrc = '30:00:00:00:00:01', hwdst =  'ff:ff:ff:ff:ff:ff', ipsrc  = '172.16.42.2', ipdst = '172.16.128.1') 
	s.expect(PacketInputEvent("router-eth1", packet), "IP packet to be forwarded to 172.16.128.1 should arrive on router-eth1, test for ip packet empty")

	# 26 arp request for 192.168.100.2, first time
	arp_request  = create_ip_arp_request('10:00:00:00:00:02', '10.10.0.1', '10.10.0.254')
	s.expect(PacketOutputEvent("router-eth1", arp_request), "Router should send ARP request for 10.10.0.254 out router-eth1 interface, test for ip packet empty, resend request")
	


router_tests()
