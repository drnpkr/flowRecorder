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
# For Python 2.x compatibility: 
from __future__ import print_function
from __future__ import division

# General imports:
import time
import sys
import os

# For packet methods:
import socket

# For time conversions:
from datetime import datetime
import calendar

# For math operations:
import numpy as np

# Import runstats for code performance statistics:
# Install with: pip install runstats --user
from runstats import Statistics

from collections import defaultdict

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
        # Required for BaseClass:
        self.config = config
        # Set up Logging with inherited base class method:
        self.configure_logging(__name__, "flows_logging_level_s",
                                       "flows_logging_level_c")

        # Python dictionary to hold flows:
        self.flow_cache = defaultdict(dict)

        # Create a Flow object for flow operations:
        self.flow = Flow(self.logger, self.flow_cache)

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
        # For each packet in the pcap process the contents:
        for timestamp, packet in dpkt_reader:
            #time0 = time.time()
            #*** Instantiate an instance of Packet class with packet info:
            packet = Packet(self.logger, timestamp, packet, mode)
            #time1 = time.time()
            # Update the flow with packet info:
            self.flow.update(packet)
            #time2 = time.time()
            #self.logger.debug("Packet time is %s flow time is %s", time1 - time0, time2 - time1)

    def get_flows(self):
        """
        Returns a CSV-format list of all flows in the data set:
            flow_id,
            src_ip,src_port,dst_ip,dst_port,proto,
            pktTotalCount,octetTotalCount,
            min_ps,max_ps,avg_ps,std_dev_ps,
            flowStart,flowEnd,flowDuration,
            min_piat,max_piat,avg_piat,std_dev_piat
        """
        flows_result = []
        flow_csv = ""
        for key, flow_dict in self.flow_cache.iteritems():
            flow_csv += str(key) + ','
            flow_csv += str(flow_dict['src_ip']) + ','
            flow_csv += str(flow_dict['src_port']) + ','
            flow_csv += str(flow_dict['dst_ip']) + ','
            flow_csv += str(flow_dict['dst_port']) + ','
            flow_csv += str(flow_dict['proto']) + ','
            flow_csv += str(flow_dict['pktTotalCount']) + ','
            flow_csv += str(flow_dict['octetTotalCount']) + ','
            flow_csv += str(flow_dict['min_ps']) + ','
            flow_csv += str(flow_dict['max_ps']) + ','
            flow_csv += str(flow_dict['avg_ps']) + ','
            flow_csv += str(flow_dict['std_dev_ps']) + ','
            flow_csv += str(flow_dict['flowStart']) + ','
            flow_csv += str(flow_dict['flowEnd']) + ','
            flow_csv += str(flow_dict['flowDuration']) + ','
            flow_csv += str(flow_dict['min_piat']) + ','
            flow_csv += str(flow_dict['max_piat']) + ','
            flow_csv += str(flow_dict['avg_piat']) + ','
            flow_csv += str(flow_dict['std_dev_piat'])
            flows_result.append(flow_csv)
        return flows_result

    def get_flows_old(self):
        """
        Returns a list of all flows in the data set
        (OLD - MongoDB)
        """
        flows_result = []
        flows_cursor = self.flows_col.find({})
        self.logger.debug("Found %s flows", flows_cursor.count())
        if flows_cursor.count():
            for flow in flows_cursor:
                self.logger.debug("Found flow=%s", flow)
                flows_result.append(flow)
        return flows_result

    def get_flows_perf(self):
        """
        Prints out stats for performance of this module
        """
        print("Flow lookup:")
        stats = self.flow.stats_lookup_found
        _min = "{0:.4f}".format(stats.minimum())
        _mean = "{0:.4f}".format(stats.mean())
        _max = "{0:.4f}".format(stats.maximum())
        print("     Found:", _min, "(Min), ", _mean, "(Mean), ", _max, "(Max)")
        stats = self.flow.stats_lookup_notfound
        _min = "{0:.4f}".format(stats.minimum())
        _mean = "{0:.4f}".format(stats.mean())
        _max = "{0:.4f}".format(stats.maximum())
        print("  NotFound:", _min, "(Min), ", _mean, "(Mean), ", _max, "(Max)")
        print("Flow write:")
        stats = self.flow.stats_update_existing
        _min = "{0:.4f}".format(stats.minimum())
        _mean = "{0:.4f}".format(stats.mean())
        _max = "{0:.4f}".format(stats.maximum())
        print("  Existing:", _min, "(Min), ", _mean, "(Mean), ", _max, "(Max)")
        stats = self.flow.stats_write_new
        _min = "{0:.4f}".format(stats.minimum())
        _mean = "{0:.4f}".format(stats.mean())
        _max = "{0:.4f}".format(stats.maximum())
        print("       New:", _min, "(Min), ", _mean, "(Mean), ", _max, "(Max)")

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

    Designed to be instantiated once by the Flows class
    """
    def __init__(self, logger, flow_cache):
        """
        Initialise with references to logger and flow_cache dictionary
        """
        self.logger = logger
        self.flow_cache = flow_cache
        # Instantiate classes for recording perf timing stats:
        self.stats_lookup_found = Statistics()
        self.stats_lookup_notfound = Statistics()
        self.stats_update_existing = Statistics()
        self.stats_write_new = Statistics()

    def update(self, packet):
        """
        Add or update flow in flows_col database collection
        """
        flow_hash = packet.flow_hash
        time0 = time.time()

        if flow_hash in self.flow_cache:
            # Found existing flow in dict
            flow_dict = self.flow_cache[flow_hash]            
            time1 = time.time()
            self.stats_lookup_found.push(time1 - time0)
            # Store size of this packet:
            flow_dict['packet_lengths'][flow_dict['pktTotalCount'] + 1] = packet.length
            # Update the count of packets and octets:
            flow_dict['pktTotalCount'] += 1
            flow_dict['octetTotalCount'] += packet.length
            # Update the min/max/avg/std_dev of the packet sizes:
            flow_dict['min_ps'] = min(flow_dict['packet_lengths'].values())
            flow_dict['max_ps'] = max(flow_dict['packet_lengths'].values())
            flow_dict['avg_ps'] = flow_dict['octetTotalCount'] / flow_dict['pktTotalCount']
            flow_dict['std_dev_ps'] = np.std(list(flow_dict['packet_lengths'].values()))
            # Store the timestamps of the newly captured packets:
            flow_dict['times'][flow_dict['pktTotalCount']] = packet.timestamp
            # As we have now at least 2 packets in the flow, we can calculate the packet-inter-arrival-time.
            # We decrement the packet counter every single time, otherwise it would start from 2
            # The first piat will be the current timestamp minus the timestamp of the previous packet:
            flow_dict['iats'][flow_dict['pktTotalCount']-1] = \
                flow_dict['times'][flow_dict['pktTotalCount']] \
                - flow_dict['times'][flow_dict['pktTotalCount']-1]
            # Update the flow end/duration (the start does not change)
            flow_dict['flowEnd'] = packet.timestamp
            flow_dict['flowDuration'] = (packet.timestamp - flow_dict['flowStart'])
            # at last update the min/max/avg/std_dev of packet-inter-arrival-times
            flow_dict['min_piat'] = min(flow_dict['iats'].values())
            flow_dict['max_piat'] = max(flow_dict['iats'].values())
            flow_dict['avg_piat'] = sum(flow_dict['iats'].values()) / flow_dict['pktTotalCount']
            flow_dict['std_dev_piat'] = np.std(list(flow_dict['iats'].values()))
            time2 = time.time()
            self.stats_update_existing.push(time2 - time1)
        else:
            # Create new key etc in flow dict for this flow:
            time1 = time.time()
            self.stats_lookup_notfound.push(time1 - time0)
            # Initialise the new flow key:
            self.flow_cache[flow_hash] = {}
            flow_dict = self.flow_cache[flow_hash]
            # Store the flow parameters for packet header values:
            flow_dict['src_ip'] = packet.ip_src
            flow_dict['dst_ip'] = packet.ip_dst
            flow_dict['proto'] = packet.proto
            flow_dict['src_port'] = packet.tp_src
            flow_dict['dst_port'] = packet.tp_dst
            # Store the size of the first packet:
            flow_dict['packet_lengths'] = {}
            flow_dict['packet_lengths'][1] = packet.length
            # Store the packet size and number of octets:
            flow_dict['pktTotalCount'] = 1
            flow_dict['octetTotalCount'] = packet.length
            # Set the min/max/avg/std_dev of packet sizes
            # (in case there will be no more packets belonging to the flow):
            flow_dict['min_ps'] = packet.length
            flow_dict['max_ps'] = packet.length
            flow_dict['avg_ps'] = packet.length
            flow_dict['std_dev_ps'] = np.std(list(flow_dict['packet_lengths'].values()))
            # Store the timestamps of the packets:
            flow_dict['times'] = {}
            flow_dict['times'][1] = packet.timestamp
            flow_dict['iats'] = {}
            # store the flow start/end/duration
            flow_dict['flowStart'] = packet.timestamp
            flow_dict['flowEnd'] = packet.timestamp
            flow_dict['flowDuration'] = 0
            # Set the min/max/avg/std_dev of packet-inter arrival times
            # (in case there will be no more packets belonging to the flow):
            flow_dict['min_piat'] = 0
            flow_dict['max_piat'] = 0
            flow_dict['avg_piat'] = 0
            flow_dict['std_dev_piat'] = 0
            # Record time for performance measurement:
            time2 = time.time()
            self.stats_write_new.push(time2 - time1)

class Packet(object):
    """
    An object that represents a packet
    """
    def __init__(self, logger, timestamp, packet, mode):
        """
        Parameters:
            timestamp: when packet was recorded
            packet: dpkt object
            mode: b (bidirectional) or u (unidirectional). Used for
            hash calculation
        """
        self.logger = logger
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
            self.logger.debug("Non IP Packet type not supported %s", eth.data.__class__.__name__)
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

