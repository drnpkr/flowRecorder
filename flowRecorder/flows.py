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
from __future__ import division

# General imports:
import sys

# For CSV operations:
import csv

# For packet methods:
import socket

# For flows dictionary:
from collections import OrderedDict

# For math operations:
import numpy as np

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
    def __init__(self, config, mode):
        """
        Initialise the Flows Class
        Args:
           config: Config class object
           mode: the mode in which the packets should be organised
             into flow records. 'u' is for unidirectional, 'b' is for
             bidirectional.
        """
        # Required for BaseClass:
        self.config = config
        # Set up Logging with inherited base class method:
        self.configure_logging(__name__, "flows_logging_level_s",
                                       "flows_logging_level_c")
        # Mode is u for unidirectional or b for bidirectional:
        self.mode = mode
        # Python dictionaries to hold current and archived flow records:
        self.flow_cache = OrderedDict()
        self.flow_archive = OrderedDict()

        # Create a Flow object for flow operations:
        self.flow = Flow(config, self.logger, self.flow_cache, self.flow_archive, mode)

        # Counter for packets that we ignored for various reasons:
        self.packets_ignored = 0

        # Counter for all the processed packets:
        self.packets_processed = 0

    def ingest_pcap(self, dpkt_reader):
        """
        ingest packet data from dpkt reader of pcap file
        into flows.
        Args:
           dpkt_reader: dpkt pcap reader object (dpkt.pcap.Reader)
        """

        status_info_frequency = self.config.get_value("status_info_frequency")

        # Process each packet in the pcap:
        for timestamp, packet in dpkt_reader:
            # Instantiate an instance of Packet class with packet info:
            packet = Packet(self.logger, timestamp, packet, self.mode)
            if packet.ingested:
                # Update the flow with packet info:
                self.flow.update(packet)
                self.packets_processed += 1
                if self.packets_processed % status_info_frequency == 0:
                    self.logger.info("Already processed %d packets", self.packets_processed)
            else:
                self.packets_ignored += 1

    def ingest_pcap_inc_save(self, dpkt_reader, output_filename):
        """
        ingest packet data from dpkt reader of pcap file
        into flows. Store the contents of the flow records incrementally.
        Args:
           dpkt_reader: dpkt pcap reader object (dpkt.pcap.Reader)
           output_filename: name of the file to store the flows
        """

        status_info_frequency = self.config.get_value("status_info_frequency")
        incremental_save_frequency = self.config.get_value("incremental_save_frequency")

        # Process each packet in the pcap:
        for timestamp, packet in dpkt_reader:
            # Instantiate an instance of Packet class with packet info:
            packet = Packet(self.logger, timestamp, packet, self.mode)
            if packet.ingested:
                # Update the flow with packet info:
                self.flow.update(packet)
                self.packets_processed += 1
                if self.packets_processed % status_info_frequency == 0:
                    self.logger.info("Already processed %d packets", self.packets_processed)
                if self.packets_processed % incremental_save_frequency == 0:
                    # self.logger.info("%s packets have been processed", self.packets_processed)
                    self.logger.info("Saving data into %s", output_filename + '-' + str(self.packets_processed) +'.csv')
                    self.write(output_filename + '-' + str(self.packets_processed))
            else:
                self.packets_ignored += 1

    def ingest_packet(self, hdr, packet):
        """
        ingest a packet from pcapy (live capture) into flows.
        """
        # Get timestamp from header:
        sec, ms = hdr.getts()
        timestamp = sec + ms / 1000000

        # Instantiate an instance of Packet class with packet info:
        packet = Packet(self.logger, timestamp, packet, self.mode)

        status_info_frequency = self.config.get_value("status_info_frequency")

        if packet.ingested:
            # Update the flow with packet info:
            self.flow.update(packet)
            self.packets_processed += 1
            if self.packets_processed % status_info_frequency == 0:
                self.logger.info("Already processed %d packets", self.packets_processed)
        else:
            self.packets_ignored += 1

    def write(self, file_name):
        """
        Write all flow records out to CSV file
        """
        with open(file_name+'.csv', mode='w') as csv_file:
            if self.mode == 'u':
                # Unidirectional fields:
                fieldnames = ['src_ip', 'src_port', 'dst_ip', 'dst_port',
                            'proto', 'pktTotalCount', 'octetTotalCount',
                            'min_ps', 'max_ps', 'avg_ps', 'std_dev_ps',
                            'flowStart', 'flowEnd', 'flowDuration',
                            'min_piat', 'max_piat', 'avg_piat', 'std_dev_piat']
            else:
                # Bidirectional fields:
                fieldnames = ['src_ip', 'src_port', 'dst_ip', 'dst_port',
                            'proto', 'pktTotalCount', 'octetTotalCount',
                            'min_ps', 'max_ps', 'avg_ps', 'std_dev_ps',
                            'flowStart', 'flowEnd', 'flowDuration',
                            'min_piat', 'max_piat', 'avg_piat', 'std_dev_piat',
                            'f_pktTotalCount', 'f_octetTotalCount',
                            'f_min_ps', 'f_max_ps', 'f_avg_ps', 'f_std_dev_ps',
                            'f_flowStart', 'f_flowEnd', 'f_flowDuration',
                            'f_min_piat', 'f_max_piat', 'f_avg_piat',
                            'f_std_dev_piat',
                            'b_pktTotalCount', 'b_octetTotalCount',
                            'b_min_ps', 'b_max_ps', 'b_avg_ps', 'b_std_dev_ps',
                            'b_flowStart', 'b_flowEnd', 'b_flowDuration',
                            'b_min_piat', 'b_max_piat', 'b_avg_piat',
                            'b_std_dev_piat'
                            ]
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames, extrasaction='ignore')
            # Write header:
            writer.writeheader()
            # Write archive flows as rows:
            for flow_dict in self.flow_archive.items():
                writer.writerow(flow_dict[1])
            # Write current flows as rows:
            for flow_dict in self.flow_cache.items():
                writer.writerow(flow_dict[1])

    def stats(self):
        """
        Log the stats for flows
        """
        self.logger.info("Result statistics")
        self.logger.info("-----------------")
        self.logger.info("Flow Records: %s", len(self.flow_cache))
        self.logger.info("Additional Archived Flow Records: %s", len(self.flow_archive))
        self.logger.info("Ignored Packets: %s", self.packets_ignored)
        self.logger.info("Processed Packets: %s", self.packets_processed)

class Flow(object):
    """
    An object that represents summary for an individual flow
    Designed to be instantiated once by the Flows class
    and set to different flow context by packet object
    """
    def __init__(self, config, logger, flow_cache, flow_archive, mode):
        """
        Initialise with references to logger and flow_cache dictionary
        and mode of operation.
        Parameters:
            logger: logger object
            flow_cache: reference to dictionary of flows
            mode: b (bidirectional) or u (unidirectional).
        """
        self.logger = logger
        self.flow_cache = flow_cache
        self.flow_archive = flow_archive
        self.mode = mode
        # Get value from config:
        self.flow_expiration = config.get_value("flow_expiration")
        self.logger.info("Flows will expire after %s seconds of inactivity", self.flow_expiration)
        self.logger.debug("Flow object instantiated in mode=%s", mode)

    def update(self, packet):
        """
        Add or update flow in in flow_cache dictionary
        """
        if packet.flow_hash in self.flow_cache:
            # Found existing flow in dict, update it:
            if self._is_current_flow(packet, self.flow_cache[packet.flow_hash]):
                # Update standard flow parameters:
                self._update_found(packet)
                if self.mode == 'b':
                    # Also update bidirectional flow parameters:
                    self._update_found_bidir(packet)
            else:
                # Expired flow so archive it:
                self._archive_flow(packet)
                # Delete from dict:
                self.flow_cache.pop(packet.flow_hash, None)
                # Now create as a new flow based on current packet:
                self._create_new(packet)
                if self.mode == 'b':
                    self._create_new_bidir(packet)
        else:
            # Flow doesn't exist yet, create it:
            self._create_new(packet)
            if self.mode == 'b':
                self._create_new_bidir(packet)

    def _update_found(self, packet):
        """
        Update existing flow in flow_cache dictionary with standard
        (non-bidirectional) parameters
        """
        flow_hash = packet.flow_hash
        flow_dict = self.flow_cache[flow_hash]
        # Store size of this packet:
        flow_dict['length'].append(packet.length)
        # Update the count of packets and octets:
        flow_dict['pktTotalCount'] += 1
        flow_dict['octetTotalCount'] += packet.length
        # Update the min/max/avg/std_dev of the packet sizes:
        flow_dict['min_ps'] = min(flow_dict['length'])
        flow_dict['max_ps'] = max(flow_dict['length'])
        flow_dict['avg_ps'] = flow_dict['octetTotalCount'] / flow_dict['pktTotalCount']
        flow_dict['std_dev_ps'] = np.std(flow_dict['length'])
        # Store the timestamps of the newly captured packet:
        flow_dict['times'].append(packet.timestamp)
        # As we have now at least 2 packets in the flow, we can calculate the packet-inter-arrival-time.
        # We decrement the packet counter every single time, otherwise it would start from 2
        # The first piat will be the current timestamp minus the timestamp of the previous packet:
        flow_dict['iats'].append(flow_dict['times'][-1] \
            - flow_dict['times'][-2])
        # Update the flow end/duration (the start does not change)
        flow_dict['flowEnd'] = packet.timestamp
        flow_dict['flowDuration'] = (packet.timestamp - flow_dict['flowStart'])
        # at last update the min/max/avg/std_dev of packet-inter-arrival-times
        flow_dict['min_piat'] = min(flow_dict['iats'])
        flow_dict['max_piat'] = max(flow_dict['iats'])
        flow_dict['avg_piat'] = sum(flow_dict['iats']) / (flow_dict['pktTotalCount'] - 1)
        flow_dict['std_dev_piat'] = np.std(flow_dict['iats'])

    def _update_found_bidir(self, packet):
        """
        Update existing flow in flow_cache dictionary with
        bidirectional parameters (separately to standard parameters)
        """
        flow_hash = packet.flow_hash
        flow_dict = self.flow_cache[flow_hash]
        # Determine packet direction (f=forward, r=reverse):
        direction = self.packet_dir(packet, flow_dict)
        # Update keys dependant on the direction (f or b):
        if direction == 'f':
            # Forward (f) direction
            # Store size of this packet:
            flow_dict['f_length'].append(packet.length)
            # Update the count of packets and octets:
            flow_dict['f_pktTotalCount'] += 1
            flow_dict['f_octetTotalCount'] += packet.length
            # Update the min/max/avg/std_dev of the packet sizes:
            flow_dict['f_min_ps'] = min(flow_dict['f_length'])
            flow_dict['f_max_ps'] = max(flow_dict['f_length'])
            flow_dict['f_avg_ps'] = flow_dict['f_octetTotalCount'] / flow_dict['f_pktTotalCount']
            flow_dict['f_std_dev_ps'] = np.std(flow_dict['f_length'])
            # Store the timestamps of the newly captured packets:
            flow_dict['f_times'].append(packet.timestamp)
            # Do inter-packet arrival time if have at least 2 packets:
            if (flow_dict['f_pktTotalCount'] > 1):
                flow_dict['f_iats'].append(flow_dict['f_times'][-1] \
                        - flow_dict['f_times'][-2])
            # Update the flow end/duration (the start does not change)
            flow_dict['f_flowEnd'] = packet.timestamp
            flow_dict['f_flowDuration'] = (packet.timestamp - flow_dict['f_flowStart'])
            # at last update the min/max/avg/std_dev of packet-inter-arrival-times
            flow_dict['f_min_piat'] = min(flow_dict['f_iats'])
            flow_dict['f_max_piat'] = max(flow_dict['f_iats'])
            flow_dict['f_avg_piat'] = sum(flow_dict['f_iats']) / (flow_dict['f_pktTotalCount'] - 1)
            flow_dict['f_std_dev_piat'] = np.std(flow_dict['f_iats'])
        else:
            # Backward (b) direction
            # Note: this may be the first time we've see backwards dir packet.
            # Store size of this packet:
            flow_dict['b_length'].append(packet.length)
            # Update the count of packets and octets:
            flow_dict['b_pktTotalCount'] += 1
            flow_dict['b_octetTotalCount'] += packet.length
            # Update the min/max/avg/std_dev of the packet sizes:
            flow_dict['b_min_ps'] = min(flow_dict['b_length'])
            flow_dict['b_max_ps'] = max(flow_dict['b_length'])
            flow_dict['b_avg_ps'] = flow_dict['b_octetTotalCount'] / flow_dict['b_pktTotalCount']
            flow_dict['b_std_dev_ps'] = np.std(flow_dict['b_length'])
            # Store the timestamps of the newly captured packets:
            flow_dict['b_times'].append(packet.timestamp)
            # Do inter-packet arrival time if have at least 2 packets:
            if (flow_dict['b_pktTotalCount'] < 2):
                # First time, so set some stuff:
                flow_dict['b_flowStart'] = packet.timestamp
            else:
                # Not first time:
                flow_dict['b_iats'].append(flow_dict['b_times'][-1] \
                    - flow_dict['b_times'][-2])
                flow_dict['b_flowDuration'] = (packet.timestamp - flow_dict['b_flowStart'])
                # Update the min/max/avg/std_dev of packet-inter-arrival-times:
                flow_dict['b_min_piat'] = min(flow_dict['b_iats'])
                flow_dict['b_max_piat'] = max(flow_dict['b_iats'])
                flow_dict['b_avg_piat'] = sum(flow_dict['b_iats']) / (flow_dict['b_pktTotalCount'] - 1)
                flow_dict['b_std_dev_piat'] = np.std(flow_dict['b_iats'])
            # Update the flow end/duration (the start does not change):
            flow_dict['b_flowEnd'] = packet.timestamp

    def _create_new(self, packet):
        """
        Create new flow in flow_cache dictionary with standard
        (non-bidirectional) parameters
        """
        flow_hash = packet.flow_hash
        # Create new key etc in flow dict for this flow:
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
        flow_dict['length'] = []
        flow_dict['length'].append(packet.length)
        # Store the packet size and number of octets:
        flow_dict['pktTotalCount'] = 1
        flow_dict['octetTotalCount'] = packet.length
        # Set the min/max/avg/std_dev of packet sizes
        # (in case there will be no more packets belonging to the flow):
        flow_dict['min_ps'] = packet.length
        flow_dict['max_ps'] = packet.length
        flow_dict['avg_ps'] = packet.length
        flow_dict['std_dev_ps'] = np.std(flow_dict['length'])
        # Store the timestamps of the packets:
        flow_dict['times'] = []
        flow_dict['times'].append(packet.timestamp)
        flow_dict['iats'] = []
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

    def _create_new_bidir(self, packet):
        """
        Add bidir parameters to new flow in flow_cache dictionary
        """
        flow_hash = packet.flow_hash
        flow_dict = self.flow_cache[flow_hash]
        # Set up keys in preparation:
        flow_dict['f_length'] = []
        flow_dict['f_times'] = []
        flow_dict['f_iats'] = []
        flow_dict['b_length'] = []
        flow_dict['b_times'] = []
        flow_dict['b_iats'] = []
        flow_dict['b_pktTotalCount'] = 0
        flow_dict['b_octetTotalCount'] = 0
        flow_dict['b_min_ps'] = 0
        flow_dict['b_max_ps'] = 0
        flow_dict['b_avg_ps'] = 0
        flow_dict['b_std_dev_ps'] = 0
        flow_dict['b_flowStart'] = 0
        flow_dict['b_flowEnd'] = 0
        flow_dict['b_flowDuration'] = 0
        flow_dict['b_min_piat'] = 0
        flow_dict['b_max_piat'] = 0
        flow_dict['b_avg_piat'] = 0
        flow_dict['b_std_dev_piat'] = 0
        # Determine packet direction (f=forward, r=reverse):
        direction = self.packet_dir(packet, flow_dict)
        # Update keys dependant on the direction (f or b):
        if direction == 'f':
            # Forward (f) direction
            # Store the size of the first packet:
            flow_dict['f_length'].append(packet.length)
            # Store the packet size and number of octets:
            flow_dict['f_pktTotalCount'] = 1
            flow_dict['f_octetTotalCount'] = packet.length
            # Set the min/max/avg/std_dev of packet sizes
            # (in case there will be no more packets belonging to the flow):
            flow_dict['f_min_ps'] = packet.length
            flow_dict['f_max_ps'] = packet.length
            flow_dict['f_avg_ps'] = packet.length
            flow_dict['f_std_dev_ps'] = np.std(flow_dict['f_length'])
            # Store the timestamps of the packets:
            flow_dict['f_times'].append(packet.timestamp)
            # store the flow start/end/duration
            flow_dict['f_flowStart'] = packet.timestamp
            flow_dict['f_flowEnd'] = packet.timestamp
            flow_dict['f_flowDuration'] = 0
            # Set the min/max/avg/std_dev of packet-inter arrival times
            # (in case there will be no more packets belonging to the flow):
            flow_dict['f_min_piat'] = 0
            flow_dict['f_max_piat'] = 0
            flow_dict['f_avg_piat'] = 0
            flow_dict['f_std_dev_piat'] = 0
        else:
            # Backward (b) direction
            # Store the size of the first packet:
            flow_dict['b_length'].append(packet.length)
            # Store the packet size and number of octets:
            flow_dict['b_pktTotalCount'] = 1
            flow_dict['b_octetTotalCount'] = packet.length
            # Set the min/max/avg/std_dev of packet sizes
            # (in case there will be no more packets belonging to the flow):
            flow_dict['b_min_ps'] = packet.length
            flow_dict['b_max_ps'] = packet.length
            flow_dict['b_avg_ps'] = packet.length
            flow_dict['b_std_dev_ps'] = np.std(flow_dict['b_length'])
            # Store the timestamps of the packets:
            flow_dict['b_times'].append(packet.timestamp)
            # store the flow start/end/duration
            flow_dict['b_flowStart'] = packet.timestamp
            flow_dict['b_flowEnd'] = packet.timestamp
            flow_dict['b_flowDuration'] = 0
            # Set the min/max/avg/std_dev of packet-inter arrival times
            # (in case there will be no more packets belonging to the flow):
            flow_dict['b_min_piat'] = 0
            flow_dict['b_max_piat'] = 0
            flow_dict['b_avg_piat'] = 0
            flow_dict['b_std_dev_piat'] = 0

    def _is_current_flow(self, packet, flow_dict):
        """
        Check if flow is current or has expired.
        Only check if the flow hash is already known
        True = flow has not expired
        False = flow has expired, i.e. PIAT from previous packet
        in flow is greater than flow expiration threshold
        """
        if flow_dict['iats']:
            if (packet.timestamp - flow_dict['times'][-1]) > self.flow_expiration:
                # Flow has expired:
                return False
            else:
                # Flow has not expired:
                return True
        elif flow_dict['pktTotalCount'] == 1:
            # Was only 1 packet so no PIAT so use packet timestamp
            if (packet.timestamp - flow_dict['flowStart']) > self.flow_expiration:
                # Flow has expired:
                return False
            else:
                # Flow has not expired:
                return True
        else:
            # No packets???
            self.logger.warning("Strange condition...")
            return True

    def _archive_flow(self, packet):
        """
        Move a flow record to archive dictionary, indexed by a
        longer more unique key
        """
        flow_hash = packet.flow_hash
        flow_dict = self.flow_cache[flow_hash]
        start_timestamp = flow_dict['flowStart']
        ip_src = flow_dict['src_ip']
        ip_dst = flow_dict['dst_ip']
        proto = flow_dict['proto']
        tp_src = flow_dict['src_port']
        tp_dst = flow_dict['dst_port']
        # Create new more-specific hash key for archiving:
        if self.mode == 'b':
            if proto == 6 or proto == 17:
                # Generate a directional 6-tuple flow_hash:
                new_hash = nethash.hash_b6((ip_src,
                                        ip_dst, proto, tp_src,
                                        tp_dst, start_timestamp))
            else:
                # Generate a directional 4-tuple flow_hash:
                new_hash = nethash.hash_b4((ip_src,
                                        ip_dst, proto,
                                        start_timestamp))
        elif self.mode == 'u':
            if proto == 6 or proto == 17:
                # Generate a directional 6-tuple flow_hash:
                new_hash = nethash.hash_u6((ip_src,
                                        ip_dst, proto, tp_src,
                                        tp_dst, start_timestamp))
            else:
                # Generate a directional 4-tuple flow_hash:
                new_hash = nethash.hash_u4((ip_src,
                                        ip_dst, proto,
                                        start_timestamp))
        # Check key isn't already used in archive:
        if new_hash in self.flow_archive:
            self.logger.warning("archive duplicate flow key=%s", new_hash)
            return
        # Copy to flow archive:
        self.flow_archive[new_hash] = flow_dict
        
        # Delete from current flows:
        

    def packet_dir(self, packet, flow_dict):
        """
        Determine packet direction (f=forward, r=reverse)
        """
        if packet.ip_src == flow_dict['src_ip']:
            return 'f'
        elif packet.ip_src == flow_dict['dst_ip']:
            return 'b'
        else:
            self.logger.critical("Uh oh, something went wrong. Exiting")
            sys.exit()

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
        self.timestamp = timestamp
        # self.length = len(packet)
        self.ip_src = 0
        self.ip_dst = 0
        self.proto = 0
        self.tp_src = 0
        self.tp_dst = 0
        self.tp_flags = 0
        self.tp_seq_src = 0
        self.tp_seq_dst = 0
        self.ingested = False

        try:
            # Read packet into dpkt to parse headers:
            eth = dpkt.ethernet.Ethernet(packet)
        except:
            # Skip Packet if unable to parse:
            self.logger.error("failed to unpack packet, skipping...")
            return

        # Get the IP packet
        ip = eth.data

        # Get the length of IPv4 packet:
        if isinstance(eth.data, dpkt.ip.IP):
            self.length = ip.len
        # Get the length of IPv6 packet:
        elif isinstance(eth.data, dpkt.ip6.IP6):
            self.length = len(ip.data)
        # Ignore if non-IP packet:
        else:
            return

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
            # Not a transport layer that we understand, keep going:
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
            if self.proto == 6 or self.proto == 17:
                # Generate a directional 5-tuple flow_hash:
                self.flow_hash = nethash.hash_u5((self.ip_src,
                                        self.ip_dst, self.proto, self.tp_src,
                                        self.tp_dst))
            else:
                # Generate a directional 3-tuple flow_hash:
                self.flow_hash = nethash.hash_u3((self.ip_src,
                                        self.ip_dst, self.proto))
        else:
            logger.critical("unsupported mode=%s", mode)
            sys.exit()
        # Yay, packet has been ingested:
        self.ingested = True

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

