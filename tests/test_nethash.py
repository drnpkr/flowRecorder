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

# Instantiate Config class:
config = config.Config()

# Test 5-Tuple:
IP_A = '192.168.0.1'
IP_B = '192.168.0.2'
TP_A = 12345
TP_B = 443
TCP = 6

# Test packet capture files:
TEST_PCAP_HTTP1 = '../tests/packet_captures/http1.pcap'

#======================== nethash.py Unit Tests ============================
def test_hash_b5():
    """
    Test flow counts for packet retransmissions. For flow packets
    (i.e. TCP), all retx should be counted (if from same DPID)

    For non-flow packets, the flow packet count should always be 1
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



