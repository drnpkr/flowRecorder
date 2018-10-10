"""
flows module unit tests
"""

# Handle tests being in different directory branch to app code:
import sys
import struct

sys.path.insert(0, '../flowRecorder')

import logging

# Import dpkt for packet parsing:
import dpkt

# flowRecorder imports:
import flowRecorder
import config
import flows as flows_module

# test packet imports:
import http1 as pkts

# Instantiate Config class:
config = config.Config()

logger = logging.getLogger(__name__)

TEST_PCAP_HTTP1 = '../tests/packet_captures/http1.pcap'

#======================== data.py Unit Tests ============================

def test_packet():
    """
    Test packet class works correctly
    """
    # For each packet in the pcap process the contents:
    mode = 'b'
    packet_number = 1
    with open(TEST_PCAP_HTTP1, 'rb') as pcap_file:
        pcap_file_handle = dpkt.pcap.Reader(pcap_file)
        for timestamp, pcap_packet in pcap_file_handle:
            #*** Instantiate an instance of Packet class:
            packet = flows_module.Packet(logger, timestamp, pcap_packet, mode)
            pkt_test(packet, pkts, packet_number)
            packet_number += 1
    
    # TBD: check mode=u

def test_packet_dir():
    """
    Test Flow class packet_dir method works correctly
    """
    # For each packet in the pcap process the contents:
    mode = 'b'
    packet_number = 1
    flows_instance = flows_module.Flows(config, mode)
    with open(TEST_PCAP_HTTP1, 'rb') as pcap_file:
        pcap_file_handle = dpkt.pcap.Reader(pcap_file)
        for timestamp, pcap_packet in pcap_file_handle:
            #*** Instantiate an instance of Packet class:
            packet = flows_module.Packet(logger, timestamp, pcap_packet, mode)
            flows_instance.flow.update(packet)
            flow_dict = flows_instance.flow_cache[packet.flow_hash]
            logger.info("flow ip_src=%s", flow_dict['src_ip'])
            logger.info("pkt=%s ground_truth=%s", packet_number - 1, pkts.DIRECTION[packet_number - 1])
            logger.info("packet_dir=%s", flows_instance.flow.packet_dir(packet, flow_dict))
            if pkts.DIRECTION[packet_number - 1] == 'c2s':
                assert flows_instance.flow.packet_dir(packet, flow_dict) == 'f'
            else:
                assert flows_instance.flow.packet_dir(packet, flow_dict) == 'b'
            packet_number += 1

    # TBD: check mode=u

#================= HELPER FUNCTIONS ===========================================

def pkt_test(packet, pkts, pkt_num):
    """
    Passed a Packet object, a packets file and packet number
    and check parameters match
    """
    assert packet.length == pkts.LEN[pkt_num - 1]
    assert packet.ip_src == pkts.IP_SRC[pkt_num - 1]
    assert packet.ip_dst == pkts.IP_DST[pkt_num - 1]
    assert packet.proto == pkts.PROTO[pkt_num - 1]
    assert packet.tp_src == pkts.TP_SRC[pkt_num - 1]
    assert packet.tp_dst == pkts.TP_DST[pkt_num - 1]
    assert packet.tp_seq_src == pkts.TP_SEQ_SRC[pkt_num - 1]
    assert packet.tp_seq_dst == pkts.TP_SEQ_DST[pkt_num - 1]
    assert packet.tcp_syn() == pkts.TCP_SYN[pkt_num - 1]
    assert packet.tcp_fin() == pkts.TCP_FIN[pkt_num - 1]
    assert packet.tcp_rst() == pkts.TCP_RST[pkt_num - 1]
    assert packet.tcp_psh() == pkts.TCP_PSH[pkt_num - 1]
    assert packet.tcp_ack() == pkts.TCP_ACK[pkt_num - 1]

def mac_addr(address):
    """
    Convert a MAC address to a readable/printable string
    """
    return ':'.join('%02x' % ord(b) for b in address)

def _ipv4_t2i(ip_text):
    """
    Turns an IPv4 address in text format into an integer.
    Borrowed from rest_router.py code
    """
    if ip_text == 0:
        return ip_text
    assert isinstance(ip_text, str)
    return struct.unpack('!I', addrconv.ipv4.text_to_bin(ip_text))[0]
