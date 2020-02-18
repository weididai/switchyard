from switchyard.lib.userlib import *
from switchyard.lib.userlib import *

def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=32)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt


def tests():
	s = TestScenario("Switch Tests")
	s.add_interface('eth1', '20:00:00:00:00:01')
	s.add_interface('eth2', '20:00:00:00:00:02')
	s.add_interface('eth3', '20:00:00:00:00:03')
	s.add_interface('eth4', '20:00:00:00:00:04')	
	s.add_interface('eth5', '20:00:00:00:00:05')
	s.add_interface('eth6', '20:00:00:00:00:06')
	s.add_interface('eth7', '20:00:00:00:00:07')
	#(h1,h4)(h2,h1)(h3,h1)(h4,h1)(h5,h1)(h6,h7)(h4,h5)
	packet = mk_pkt("20:00:00:00:00:01", "20:00:00:00:00:04", '192.168.1.100', '172.16.42.2')
	s.expect(PacketInputEvent("eth1", packet, display=Ethernet),
             "An Ethernet frame from 60:00:00:00:00:00 to 70:00:00:00:00:01 should arrive on all")
	s.expect(PacketOutputEvent("eth2", packet, display=Ethernet),
             "Ethernet frame destined for 70:00:00:00:00:01 should be flooded out eth2")
	packet = mk_pkt("20:00:00:00:00:02", "20:00:00:00:00:01", '192.168.1.100', '172.16.42.2')
	packet = mk_pkt("20:00:00:00:00:03", "20:00:00:00:00:01", '192.168.1.100', '172.16.42.2')
	packet = mk_pkt("20:00:00:00:00:04", "20:00:00:00:00:01", '192.168.1.100', '172.16.42.2')
	packet = mk_pkt("20:00:00:00:00:05", "20:00:00:00:00:01", '192.168.1.100', '172.16.42.2')
	packet = mk_pkt("20:00:00:00:00:06", "20:00:00:00:00:07", '192.168.1.100', '172.16.42.2')
	packet = mk_pkt("20:00:00:00:00:04", "20:00:00:00:00:05", '192.168.1.100', '172.16.42.2')
	print("LRU list should be [h5,h6,h1,h4,h3]")
	return s

s = tests()
	
	
