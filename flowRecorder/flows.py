# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
flows.py

This data library represents network flows

It stores cummulative information (not individual packets)
about flows in a MongoDB collection
"""

import sys
import os

# For packet methods:
import socket

# For time conversions:
from datetime import datetime
import calendar

# mongodb Database Import:
import pymongo
from pymongo import MongoClient

# Import dpkt for packet parsing:
import dpkt

# For logging configuration:
from baseclass import BaseClass

# For flow hashing:
import nethash

class Flows(BaseClass):
    """
    The Flows class represents cummulative information about flows
    (not individual packets)
    """
    def __init__(self, config):
        """ Initialise the Flows Class """
        #*** Required for BaseClass:
        self.config = config
        #*** Set up Logging with inherited base class method:
        self.configure_logging(__name__, "flows_logging_level_s",
                                       "flows_logging_level_c")

        # Get MongoDB parameters from config:
        mongo_addr = config.get_value("mongo_addr")
        mongo_port = config.get_value("mongo_port")
        mongo_dbname = config.get_value("mongo_dbname")

        # Start PyMongo connection to MongoDB:
        self.logger.info("Connecting to MongoDB database...")
        mongo_client = MongoClient(mongo_addr, mongo_port)

        #*** Connect to MongoDB database:
        db = mongo_client[mongo_dbname]

        #*** Set up MongoDB flows collection:
        self.logger.debug("Deleting flows MongoDB collection...")
        db.flows.drop()
        #*** Create the flows collection:
        self.flows_col = db.create_collection('flows')

        # TBD CREATE MongoDB INDEXES:

        # Create indexes on raw_data collection to improve searching:
        #self.flows_col.create_index([('flow_hash', pymongo.DESCENDING),
        #                            ], unique=False)

    def ingest_pcap(self, dpkt_reader, mode):
        """
        ingest packet data from dpkt reader of pcap file
        into flows.

        Args:
           dpkt_reader: dpkt pcap reader object (dpkt.pcap.Reader)
           mode: the mode in which the packets should be organised
             into flow records. 'u' is for unidirectional, 'b' is for
             bidirectional.

        """
        # Create a Flow object for flow operations:
        flow = Flow(self.logger, self.flows_col)

        # For each packet in the pcap process the contents:
        for timestamp, packet in dpkt_reader:
            #*** Instantiate an instance of Packet class with packet info:
            packet = Packet(timestamp, packet, mode)

        # Update the flow with packet info:
        flow.update(packet)
        


    def get_flows(self):
        """
        Returns a list of all flows in the data set
        """
        flows_result = []
        flows_cursor = self.flows_col.find({})
        self.logger.debug("Found %s flows", flows_cursor.count())
        if flows_cursor.count():
            for flow in flows_cursor:
                self.logger.debug("Found flow=%s", flow)
                flows_result.append(flow)
        return flows_result


class Flow(object):
    """
    An object that represents summary for an individual flow

    Flow parameters:
        flow_id,
        src_ip,src_port,dst_ip,dst_port,proto,
        pktTotalCount,octetTotalCount,
        min_ps,max_ps,avg_ps,std_dev_ps,
        flowStart,flowEnd,flowDuration,
        min_piat,max_piat,avg_piat,std_dev_piat

    Designed to be instantiated by the Flows class
    """
    def __init__(self, logger, flows_col):
        """
        Pass it references to logger and flows_col MongoDB collection
        """
        self.logger = logger
        self.flows_col = flows_col
        # Initialise flow variables:
        self.flow_hash = 0
        self.pktTotalCount = 0

    def db_dict(self):
        """
        Return a dictionary object of selected flow
        parameters for storing in the database
        """
        dbdictresult = {}
        dbdictresult['flow_hash'] = self.flow_hash
        dbdictresult['pktTotalCount'] = self.packet_count
        return dbdictresult

    def update(self, flow_hash, pkt):
        """
        Add or update flow in flows db collection
        """
        spkt = self.spkt
        self.flow_hash = flow_hash

        # Look up flow hash in DB col:
        db_query = {'flow_hash': flow_hash}
        flow_doc = self.flows_col.find_one(db_query)

        if flow_doc:
            # Found existing flow doc in DB:
            self.packet_count = flow_doc['packet_count'] + 1
            self.packet_lengths = flow_doc['packet_lengths']
            self.packet_lengths.append(spkt.frame_len(pkt))
            # Reuse original packet headers (retain first packet direction):
            self.eth_src = flow_doc['eth_src']
            self.eth_dst = flow_doc['eth_dst']
            self.ip_src = flow_doc['ip_src']
            self.ip_dst = flow_doc['ip_dst']
            # Update document in DB collection:
            self.flows_col.update(db_query, self.db_dict())
        else:
            # No flow doc in DB so create new:
            self.packet_count = 1
            self.packet_lengths.append(spkt.frame_len(pkt))
            # Read packet headers from supplied packet:
            self.eth_src = spkt.eth_src(pkt)
            self.eth_dst = spkt.eth_dst(pkt)
            self.ip_src = spkt.ip_src(pkt)
            self.ip_dst = spkt.ip_dst(pkt)
            # Write to DB collection:
            self.flows_col.insert_one(self.db_dict())

class Packet(object):
    """
    An object that represents a packet
    """
    def __init__(self, timestamp, packet, mode):
        """
        Parameters:
            timestamp: when packet was recorded
            packet: dpkt object
            mode: b (bidirectional) or u (unidirectional). Used for
            hash calculation
        """
        #*** Initialise packet variables:
        self.flow_hash = 0
        self.timestamp = 0
        self.length = len(packet)
        self.ip_src = 0
        self.ip_dst = 0
        self.proto = 0
        self.tp_src = 0
        self.tp_dst = 0
        self.tp_flags = 0
        self.tp_seq_src = 0
        self.tp_seq_dst = 0

        # Read packet into dpkt to parse headers:
        eth = dpkt.ethernet.Ethernet(packet)

        # Ignore if non-IP packet:
        if not (isinstance(eth.data, dpkt.ip.IP) or isinstance(eth.data, dpkt.ip6.IP6)):
            print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
            return

        ip = eth.data
        # Handle IPv4 and IPv6:
        try:
            self.ip_src = socket.inet_ntop(socket.AF_INET, ip.src)
            self.ip_dst = socket.inet_ntop(socket.AF_INET, ip.dst)
        except ValueError:
            self.ip_src = socket.inet_ntop(socket.AF_INET6, ip.src)
            self.ip_dst = socket.inet_ntop(socket.AF_INET6, ip.dst)
        # Transport layer:
        self.proto = ip.p
        if ip.p == 6:
            # TCP
            tcp = ip.data
            self.tp_src = tcp.sport
            self.tp_dst = tcp.dport
            self.tp_flags = tcp.flags
            self.tp_seq_src = tcp.seq
            self.tp_seq_dst = tcp.ack
        elif ip.p == 17:
            # UDP
            udp = ip.data
            self.tp_src = udp.sport
            self.tp_dst = udp.dport
            self.tp_flags = ""
            self.tp_seq_src = 0
            self.tp_seq_dst = 0
        else:
            # Not a transport layer that we understand:
            pass

        if mode == 'b':
            if self.proto == 6 or self.proto == 17:
                # Generate a directional 5-tuple flow_hash:
                self.flow_hash = nethash.hash_b5((self.ip_src,
                                        self.ip_dst, self.proto, self.tp_src,
                                        self.tp_dst))
            else:
                # Generate a directional 3-tuple flow_hash:
                self.flow_hash = nethash.hash_b3((self.ip_src,
                                        self.ip_dst, self.proto))
        elif mode == 'u':
            # TBD:
            logger.critical("unsupported mode=%s - not written yet", mode)
            pass
        else:
            logger.critical("unsupported mode=%s", mode)
            sys.exit()

    def dbdict(self):
        """
        Return a dictionary object of metadata
        parameters of current packet
        for storing in database
        """
        dbdictresult = {}
        dbdictresult['flow_hash'] = self.flow_hash
        dbdictresult['timestamp'] = self.timestamp
        dbdictresult['length'] = self.length
        dbdictresult['ip_src'] = self.ip_src
        dbdictresult['ip_dst'] = self.ip_dst
        dbdictresult['proto'] = self.proto
        dbdictresult['tp_src'] = self.tp_src
        dbdictresult['tp_dst'] = self.tp_dst
        dbdictresult['tp_flags'] = self.tp_flags
        dbdictresult['tp_seq_src'] = self.tp_seq_src
        dbdictresult['tp_seq_dst'] = self.tp_seq_dst
        return dbdictresult

    def tcp_fin(self):
        """
        Does the current packet have the TCP FIN flag set?
        """
        return self.tp_flags & dpkt.tcp.TH_FIN != 0

    def tcp_syn(self):
        """
        Does the current packet have the TCP SYN flag set?
        """
        return self.tp_flags & dpkt.tcp.TH_SYN != 0

    def tcp_rst(self):
        """
        Does the current packet have the TCP RST flag set?
        """
        return self.tp_flags & dpkt.tcp.TH_RST != 0

    def tcp_psh(self):
        """
        Does the current packet have the TCP PSH flag set?
        """
        return self.tp_flags & dpkt.tcp.TH_PUSH != 0

    def tcp_ack(self):
        """
        Does the current packet have the TCP ACK flag set?
        """
        return self.tp_flags & dpkt.tcp.TH_ACK != 0

    def tcp_urg(self):
        """
        Does the current packet have the TCP URG flag set?
        """
        return self.tp_flags & dpkt.tcp.TH_URG != 0

    def tcp_ece(self):
        """
        Does the current packet have the TCP ECE flag set?
        """
        return self.tp_flags & dpkt.tcp.TH_ECE != 0

    def tcp_cwr(self):
        """
        Does the current packet have the TCP CWR flag set?
        """
        return self.tp_flags & dpkt.tcp.TH_CWR != 0

