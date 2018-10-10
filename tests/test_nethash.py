"""
nethash.py Unit Tests
"""

#*** Handle tests being in different directory branch to app code:
import sys
import struct

sys.path.insert(0, '../flowRecorder')

#*** For timestamps:
import datetime

import logging

# Import dpkt for packet parsing:
import dpkt

# flowRecorder imports:
import flowRecorder
import config
import flows as flows_module
import nethash

# test packet imports:
import http1 as pkts

logger = logging.getLogger(__name__)

# test packet imports:
import http1 as pkts

# Instantiate Config class:
config = config.Config()

# Test 5-Tuple:
IP_A = '192.168.0.1'
IP_B = '192.168.0.2'
TP_A = 12345
TP_B = 443
TCP = 6
TIMESTAMP = '1538857982.301350'

# Test packet capture files:
TEST_PCAP_HTTP1 = '../tests/packet_captures/http1.pcap'

#======================== nethash.py Unit Tests ============================
def test_hash_b6():
    """
    Test bidirectional 6-tuple hashing
    """
    # Test that TCP tuples of packets in both directions on
    # a flow generate the same hash:
    hash1 = nethash.hash_b6((IP_A, IP_B, TCP, TP_A, TP_B, TIMESTAMP))
    hash2 = nethash.hash_b6((IP_B, IP_A, TCP, TP_B, TP_A, TIMESTAMP))
    assert hash1 == hash2

def test_hash_b5():
    """
    Test bidirectional 5-tuple hashing
    """
    # Test that TCP tuples of packets in both directions on
    # a flow generate the same hash:
    hash1 = nethash.hash_b5((IP_A, IP_B, TCP, TP_A, TP_B))
    hash2 = nethash.hash_b5((IP_B, IP_A, TCP, TP_B, TP_A))
    assert hash1 == hash2

    # Test reading in a packet capture of a single flow and ensuring
    # all packets have same b5 flow hash:
    mode = 'b'
    flow_hash_packet_1 = 0
    packet_number = 1
    with open(TEST_PCAP_HTTP1, 'rb') as pcap_file:
        pcap_file_handle = dpkt.pcap.Reader(pcap_file)
        for timestamp, pcap_packet in pcap_file_handle:
            #*** Instantiate an instance of Packet class:
            packet = flows_module.Packet(logger, timestamp, pcap_packet, mode)
            if packet_number == 1:
                flow_hash_packet_1 = packet.flow_hash
            else:
                assert packet.flow_hash == flow_hash_packet_1
                logger.info("packet.flow_hash=%s, flow_hash_packet_1=%s",
                                          packet.flow_hash, flow_hash_packet_1)
            packet_number += 1

def test_hash_b4():
    """
    Test bidirectional 4-tuple hashing
    """
    # Test that TCP tuples of packets in both directions on
    # a flow generate the same hash:
    hash1 = nethash.hash_b4((IP_A, IP_B, TCP, TIMESTAMP))
    hash2 = nethash.hash_b4((IP_B, IP_A, TCP, TIMESTAMP))
    assert hash1 == hash2
    
    # TBD: more tests here...

def test_hash_b3():
    """
    Test bidirectional 3-tuple hashing
    """
    # Test that TCP tuples of packets in both directions on
    # a flow generate the same hash:
    hash1 = nethash.hash_b3((IP_A, IP_B, TCP))
    hash2 = nethash.hash_b3((IP_B, IP_A, TCP))
    assert hash1 == hash2

    # Test reading in a packet capture of a single flow and ensuring
    # all packets have same b3 flow hash 

    # TBD: needs a non-TCP or UDP packet capture of a flow (i.e. IPsec
    #   or similar...

def test_hash_u6():
    """
    Test unidirectional 6-tuple hashing
    """
    # Test that TCP tuples of packets in both directions on
    # a flow generate the same hash:
    hash1 = nethash.hash_u6((IP_A, IP_B, TCP, TP_A, TP_B, TIMESTAMP))
    hash2 = nethash.hash_u6((IP_B, IP_A, TCP, TP_B, TP_A, TIMESTAMP))
    assert hash1 != hash2

def test_hash_u5():
    """
    Test unidirectional 5-tuple hashing
    """
    # Test that TCP tuples of packets in both directions on
    # a flow generate the same hash:
    hash1 = nethash.hash_u5((IP_A, IP_B, TCP, TP_A, TP_B))
    hash2 = nethash.hash_u5((IP_B, IP_A, TCP, TP_B, TP_A))
    assert hash1 != hash2

    # Test reading in a packet capture of a single flow and ensuring
    # all packets have same u5 flow hash per direction:
    mode = 'u'
    flow_hash_packet_1 = 0
    packet_number = 1
    with open(TEST_PCAP_HTTP1, 'rb') as pcap_file:
        pcap_file_handle = dpkt.pcap.Reader(pcap_file)
        for timestamp, pcap_packet in pcap_file_handle:
            #*** Instantiate an instance of Packet class:
            packet = flows_module.Packet(logger, timestamp, pcap_packet, mode)
            if packet_number == 1:
                flow_hash_packet_forward = packet.flow_hash
            elif packet_number == 2:
                flow_hash_packet_backward = packet.flow_hash
            else:
                if pkts.DIRECTION[packet_number - 1] == 'c2s':
                    assert packet.flow_hash == flow_hash_packet_forward
                else:
                    assert packet.flow_hash == flow_hash_packet_backward
            packet_number += 1

def test_hash_u4():
    """
    Test unidirectional 4-tuple hashing
    """
    # Test that TCP tuples of packets in both directions on
    # a flow generate the same hash:
    hash1 = nethash.hash_u4((IP_A, IP_B, TCP, TIMESTAMP))
    hash2 = nethash.hash_u4((IP_B, IP_A, TCP, TIMESTAMP))
    assert hash1 != hash2
    
    # TBD: more tests here...

def test_hash_u3():
    """
    Test unidirectional 3-tuple hashing
    """
    # Test that TCP tuples of packets in both directions on
    # a flow generate the same hash:
    hash1 = nethash.hash_u3((IP_A, IP_B, TCP))
    hash2 = nethash.hash_u3((IP_B, IP_A, TCP))
    assert hash1 != hash2

    # Test reading in a packet capture of a single flow and ensuring
    # all packets per direction have same u3 flow hash 

    # TBD: needs a non-TCP or UDP packet capture of a flow (i.e. IPsec
    #   or similar...


