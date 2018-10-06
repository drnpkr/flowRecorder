#    Copyright 2018 Adrian Pekar
# 
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
# 
#        http://www.apache.org/licenses/LICENSE-2.0
# 
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import time
"""
Use DPKT to read in a pcap file, organise packets into flows, and print out the flow records
"""
import dpkt
import pcapy
import socket
import hashlib
import pandas as pd
import numpy as np
from collections import defaultdict
from dpkt.compat import compat_ord
# from openpyxl import Workbook


def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)



def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)



def is_flow_record_present(key,flow_cache):
    """Checks whether there is any existing flow record in the flow cache for the packet

           Args:
               key (float): flowID calculated based on the 5-tuple
           Returns:
               bool: The return value. True for success, False otherwise.
    """

    if key in flow_cache:
        # print('Flow Record is present in the Flow Cache')
        return True
    else:
        # print('Flow Record is NOT present in the Flow Cache')
        return False



################################################
##### UNIDIRECTIONAL
################################################



# build the flow record
def create_flow_record(flow_id, flow_cache, timestamp, ip, packets):
    """
    Function for creating the flow record when organizing packet into flows in one direction

    :param flow_id: the flowID of the actually processed packet that was computed based on the 5-tuple
    :param flow_cache: a global variable (flow cache) that holds stores all the flow records
    :param timestamp: the timestamp of the actually processed packet
    :param ip: the ip packet
    :param packets: another global variable that is used to store packet related information to calculate min/max/avg/std_dev of packet sizes (PS) and  packet inter-arrival-times (PIATs)
    """

    # print('Creating the flow record')
    # flow_cache[flow_id]['bwd_pkt_flow_id'] = bwd_id

    # store the flow keys
    flow_cache[flow_id]['src_ip'] = inet_to_str(ip.src)
    flow_cache[flow_id]['src_port'] = ip.data.sport
    flow_cache[flow_id]['dst_ip'] = inet_to_str(ip.dst)
    flow_cache[flow_id]['dst_port'] = ip.data.dport
    flow_cache[flow_id]['proto'] = ip.p

    # store the size of the first packet
    packets[flow_id]['length'][1] = ip.len

    # store the packet size and number of octets
    flow_cache[flow_id]['pktTotalCount'] = 1
    flow_cache[flow_id]['octetTotalCount'] = ip.len

    # set the min/max/avg/std_dev of packet sizes
    # (in case there will be no more packets belonging to the flow)
    flow_cache[flow_id]['min_ps'] = ip.len
    flow_cache[flow_id]['max_ps'] = ip.len
    flow_cache[flow_id]['avg_ps'] = flow_cache[flow_id]['octetTotalCount'] / flow_cache[flow_id]['pktTotalCount']
    flow_cache[flow_id]['std_dev_ps'] = np.std(list(packets[flow_id]['length'].values()))

    # store the timestamps of the packets
    packets[flow_id]['times'][1] = timestamp

    # store the flow start/end/duration
    flow_cache[flow_id]['flowStart'] = timestamp
    flow_cache[flow_id]['flowEnd'] = timestamp
    flow_cache[flow_id]['flowDuration'] = (timestamp - flow_cache[flow_id]['flowStart'])

    # set the min/max/avg/std_dev of packet-inter arrival times
    # (in case there will be no more packets belonging to the flow)
    flow_cache[flow_id]['min_piat'] = 0
    flow_cache[flow_id]['max_piat'] = 0
    flow_cache[flow_id]['avg_piat'] = 0
    flow_cache[flow_id]['std_dev_piat'] = 0



# update the flow record
def update_flow_record(flow_id, flow_cache, timestamp, ip, packets):
    """
    Function for updating the flow records in the flow cache when organizing packet into flows in one direction

    :param flow_id: the flowID of the actually processed packet that was computed based on the 5-tuple
    :param flow_cache: a global variable (flow cache) that holds stores all the flow records
    :param timestamp: the timestamp of the actually processed packet
    :param ip: the ip packet
    :param packets: another global variable that is used to store packet related information to calculate min/max/avg/std_dev of packet sizes (PS) and  packet inter-arrival-times (PIATs)
    """
    # print('Updating the flow record')

    # store the sizes of the newly captured packets
    packets[flow_id]['length'][flow_cache[flow_id]['pktTotalCount']] = ip.len

    # update the count of packets and octets
    flow_cache[flow_id]['pktTotalCount'] += 1
    flow_cache[flow_id]['octetTotalCount'] += ip.len

    # update the min/max/avg/std_dev of the packet sizes
    flow_cache[flow_id]['min_ps'] = min(packets[flow_id]['length'].values())
    flow_cache[flow_id]['max_ps'] = max(packets[flow_id]['length'].values())
    flow_cache[flow_id]['avg_ps'] = flow_cache[flow_id]['octetTotalCount'] / flow_cache[flow_id]['pktTotalCount']
    flow_cache[flow_id]['std_dev_ps'] = np.std(list(packets[flow_id]['length'].values()))

    # store the timestamps of the newly captured packets
    packets[flow_id]['times'][flow_cache[flow_id]['pktTotalCount']] = timestamp

    # as we have now at least 2 packets in the flow, we can caluclate the packet-inter-arrival-time.
    # we decrement the packet counter every single time, otherwise it would start from 2
    # the first piat will be the current timestamp minus the timestamp of the previous packet
    packets[flow_id]['iats'][flow_cache[flow_id]['pktTotalCount']-1] = \
        packets[flow_id]['times'][flow_cache[flow_id]['pktTotalCount']] \
        - packets[flow_id]['times'][flow_cache[flow_id]['pktTotalCount']-1]

    # update the flow end/duration (the start does not change)
    flow_cache[flow_id]['flowEnd'] = timestamp
    flow_cache[flow_id]['flowDuration'] = (timestamp - flow_cache[flow_id]['flowStart'])

    # at last update the min/max/avg/std_dev of packet-inter-arrival-times
    flow_cache[flow_id]['min_piat'] = min(packets[flow_id]['iats'].values())
    flow_cache[flow_id]['max_piat'] = max(packets[flow_id]['iats'].values())
    flow_cache[flow_id]['avg_piat'] = sum(packets[flow_id]['iats'].values()) / flow_cache[flow_id]['pktTotalCount']
    flow_cache[flow_id]['std_dev_piat'] = np.std(list(packets[flow_id]['iats'].values()))



################################################
##### BIDIRECTIONAL
################################################



# build the flow record
def create_biflow_record(flow_id, flow_cache, timestamp, ip, bwd_id, packets):
    """
     Function for creating the flow record when organizing packet into flows in bidirection

     :param flow_id: the flowID of the actually processed packet that was computed based on the 5-tuple
     :param flow_cache: a global variable (flow cache) that holds stores all the flow records
     :param timestamp: the timestamp of the actually processed packet
     :param ip: the ip packet
     :param bwd_id: the backward flowID of the actually processed packet that was computed based on the 5-tuple
     :param packets: another global variable that is used to store packet related information to calculate min/max/avg/std_dev of packet sizes (PS) and  packet inter-arrival-times (PIATs)
     """

    # print('Creating the flow record')
    # store the backward flow id
    flow_cache[flow_id]['bwd_pkt_flow_id'] = bwd_id

    # store the flow keys
    flow_cache[flow_id]['src_ip'] = inet_to_str(ip.src)
    flow_cache[flow_id]['src_port'] = ip.data.sport
    flow_cache[flow_id]['dst_ip'] = inet_to_str(ip.dst)
    flow_cache[flow_id]['dst_port'] = ip.data.dport
    flow_cache[flow_id]['proto'] = ip.p

    # calcualte the number of packets and bytes (packet lengths) in the flow
    flow_cache[flow_id]['bi_pktTotalCount'] = 1
    flow_cache[flow_id]['bi_octetTotalCount'] = ip.len

    # store the packet size
    packets[flow_id]['bi_length'][1] = ip.len

    # calculate the min/max/avg/std_dev in the case there is going to be only 1 packet in the flow
    flow_cache[flow_id]['bi_min_ps'] = ip.len
    flow_cache[flow_id]['bi_max_ps'] = ip.len
    flow_cache[flow_id]['bi_avg_ps'] = flow_cache[flow_id]['bi_octetTotalCount'] / flow_cache[flow_id]['bi_pktTotalCount']
    flow_cache[flow_id]['bi_std_dev_ps'] = np.std(list(packets[flow_id]['bi_length'].values()))

    # store the timestamp of the packet
    packets[flow_id]['bi_times'][1] = timestamp

    # calculate the flow start/end/duration
    flow_cache[flow_id]['bi_flowStart'] = timestamp
    flow_cache[flow_id]['bi_flowEnd'] = timestamp
    flow_cache[flow_id]['bi_flowDuration'] = (timestamp - flow_cache[flow_id]['bi_flowStart'])

    # as at this point we have only 1 packet int the flow, all the packet-inter-arrival-times are set to 0
    flow_cache[flow_id]['bi_min_piat'] = 0
    flow_cache[flow_id]['bi_max_piat'] = 0
    flow_cache[flow_id]['bi_avg_piat'] = 0
    flow_cache[flow_id]['bi_std_dev_piat'] = 0

    # now calculate the same in forward direction
    packets[flow_id]['f_length'][1] = ip.len

    flow_cache[flow_id]['f_pktTotalCount'] = 1
    flow_cache[flow_id]['f_octetTotalCount'] = ip.len

    flow_cache[flow_id]['f_min_ps'] = ip.len
    flow_cache[flow_id]['f_max_ps'] = ip.len
    flow_cache[flow_id]['f_avg_ps'] = flow_cache[flow_id]['f_octetTotalCount'] / flow_cache[flow_id]['f_pktTotalCount']
    flow_cache[flow_id]['f_std_dev_ps'] = np.std(list(packets[flow_id]['f_length'].values()))

    packets[flow_id]['f_times'][1] = timestamp

    flow_cache[flow_id]['f_flowStart'] = timestamp
    flow_cache[flow_id]['f_flowEnd'] = timestamp
    flow_cache[flow_id]['f_flowDuration'] = (timestamp - flow_cache[flow_id]['f_flowStart'])

    flow_cache[flow_id]['f_min_piat'] = 0
    flow_cache[flow_id]['f_max_piat'] = 0
    flow_cache[flow_id]['f_avg_piat'] = 0
    flow_cache[flow_id]['f_std_dev_piat'] = 0

    # now calculate the same in backward direction
    # packets[flow_id]['b_length'][1] = 0

    flow_cache[flow_id]['b_pktTotalCount'] = 0
    flow_cache[flow_id]['b_octetTotalCount'] = 0

    flow_cache[flow_id]['b_min_ps'] = 0
    flow_cache[flow_id]['b_max_ps'] = 0
    flow_cache[flow_id]['b_avg_ps'] = 0
    flow_cache[flow_id]['b_std_dev_ps'] = 0

    flow_cache[flow_id]['b_flowStart'] = 0
    flow_cache[flow_id]['b_flowEnd'] = 0
    flow_cache[flow_id]['b_flowDuration'] = 0

    flow_cache[flow_id]['b_min_piat'] = 0
    flow_cache[flow_id]['b_max_piat'] = 0
    flow_cache[flow_id]['b_avg_piat'] = 0
    flow_cache[flow_id]['b_std_dev_piat'] = 0



# update the flow record
def update_biflow_record(flow_id,flow_cache,timestamp,ip, dir, packets):
    """
     Function for updating the flow record when organizing packet into flows in bidirection

     :param flow_id: the flowID of the actually processed packet that was computed based on the 5-tuple
     :param flow_cache: a global variable (flow cache) that holds stores all the flow records
     :param timestamp: the timestamp of the actually processed packet
     :param ip: the ip packet
     :param bwd_id: the backward flowID of the actually processed packet that was computed based on the 5-tuple
     :param packets: another global variable that is used to store packet related information to calculate min/max/avg/std_dev of packet sizes (PS) and  packet inter-arrival-times (PIATs)
     """

    # print('Updating the flow record')

    # update the number of packets and bytes (packets sizes) in the flow
    flow_cache[flow_id]['bi_pktTotalCount'] += 1
    flow_cache[flow_id]['bi_octetTotalCount'] += ip.len

    # store the size of the newly observerd (captured) packets
    packets[flow_id]['bi_length'][flow_cache[flow_id]['bi_pktTotalCount']] = ip.len

    # re-calcualte the min/max/avg/std_dev of packet sizes
    flow_cache[flow_id]['bi_min_ps'] = min(packets[flow_id]['bi_length'].values())
    flow_cache[flow_id]['bi_max_ps'] = max(packets[flow_id]['bi_length'].values())
    flow_cache[flow_id]['bi_avg_ps'] = flow_cache[flow_id]['bi_octetTotalCount'] / flow_cache[flow_id]['bi_pktTotalCount']
    flow_cache[flow_id]['bi_std_dev_ps'] = np.std(list(packets[flow_id]['bi_length'].values()))

    # store the timestamp of newly observed (captured) packets
    packets[flow_id]['bi_times'][flow_cache[flow_id]['bi_pktTotalCount']] = timestamp

    # update the flow end (the flow start does not change) and the flow duration
    flow_cache[flow_id]['bi_flowEnd'] = timestamp
    flow_cache[flow_id]['bi_flowDuration'] = (timestamp - flow_cache[flow_id]['bi_flowStart'])

    # as we have now at least 2 packets in the flow, we can caluclate the packet-inter-arrival-time.
    # we decrement the packet counter every single time, otherwise it would start from 2
    # the first piat will be the current timestamp minus the timestamp of the previous packet
    packets[flow_id]['bi_iats'][flow_cache[flow_id]['bi_pktTotalCount'] - 1] = \
        packets[flow_id]['bi_times'][flow_cache[flow_id]['bi_pktTotalCount']] \
        - packets[flow_id]['bi_times'][flow_cache[flow_id]['bi_pktTotalCount'] - 1]

    # new we recalcualte the min/max/avg/std_dev of the PIATs
    flow_cache[flow_id]['bi_min_piat'] = min(packets[flow_id]['bi_iats'].values())
    flow_cache[flow_id]['bi_max_piat'] = max(packets[flow_id]['bi_iats'].values())
    flow_cache[flow_id]['bi_avg_piat'] = sum(packets[flow_id]['bi_iats'].values()) / flow_cache[flow_id]['bi_pktTotalCount']
    flow_cache[flow_id]['bi_std_dev_piat'] = np.std(list(packets[flow_id]['bi_iats'].values()))

    # now do the same for forward and backward directions
    if dir == 'f':

        flow_cache[flow_id]['f_pktTotalCount'] += 1
        flow_cache[flow_id]['f_octetTotalCount'] += ip.len

        # store the size and timestamp of the newly observerd (captured) packet
        packets[flow_id]['f_length'][flow_cache[flow_id]['f_pktTotalCount']] = ip.len

        # re-calcualte the min/max/avg/std_dev of packet sizes
        flow_cache[flow_id]['f_min_ps'] = min(packets[flow_id]['f_length'].values())
        flow_cache[flow_id]['f_max_ps'] = max(packets[flow_id]['f_length'].values())
        flow_cache[flow_id]['f_avg_ps'] = flow_cache[flow_id]['f_octetTotalCount'] / flow_cache[flow_id][
            'f_pktTotalCount']
        flow_cache[flow_id]['f_std_dev_ps'] = np.std(list(packets[flow_id]['f_length'].values()))

        flow_cache[flow_id]['f_flowEnd'] = timestamp
        flow_cache[flow_id]['f_flowDuration'] = (timestamp - flow_cache[flow_id]['f_flowStart'])

        packets[flow_id]['f_times'][flow_cache[flow_id]['f_pktTotalCount']] = timestamp

        packets[flow_id]['f_iats'][flow_cache[flow_id]['f_pktTotalCount'] - 1] = \
            packets[flow_id]['f_times'][flow_cache[flow_id]['f_pktTotalCount']] \
            - packets[flow_id]['f_times'][flow_cache[flow_id]['f_pktTotalCount'] - 1]

        flow_cache[flow_id]['f_min_piat'] = min(packets[flow_id]['f_iats'].values())
        flow_cache[flow_id]['f_max_piat'] = max(packets[flow_id]['f_iats'].values())
        flow_cache[flow_id]['f_avg_piat'] = sum(packets[flow_id]['f_iats'].values()) / flow_cache[flow_id][
            'bi_pktTotalCount']
        flow_cache[flow_id]['f_std_dev_piat'] = np.std(list(packets[flow_id]['f_iats'].values()))

    else:

        flow_cache[flow_id]['b_pktTotalCount'] += 1
        flow_cache[flow_id]['b_octetTotalCount'] += ip.len

        packets[flow_id]['b_length'][flow_cache[flow_id]['b_pktTotalCount']] = ip.len

        # re-calcualte the min/max/avg/std_dev of packet sizes
        flow_cache[flow_id]['b_min_ps'] = min(packets[flow_id]['b_length'].values())
        flow_cache[flow_id]['b_max_ps'] = max(packets[flow_id]['b_length'].values())
        flow_cache[flow_id]['b_avg_ps'] = flow_cache[flow_id]['b_octetTotalCount'] / flow_cache[flow_id][
            'b_pktTotalCount']
        flow_cache[flow_id]['b_std_dev_ps'] = np.std(list(packets[flow_id]['b_length'].values()))

        if flow_cache[flow_id]['b_flowStart'] == 0:
            flow_cache[flow_id]['b_flowStart'] = timestamp
        flow_cache[flow_id]['b_flowEnd'] = timestamp
        flow_cache[flow_id]['b_flowDuration'] = (timestamp - flow_cache[flow_id]['b_flowStart'])

        packets[flow_id]['b_times'][flow_cache[flow_id]['b_pktTotalCount']] = timestamp

        packets[flow_id]['b_iats'][flow_cache[flow_id]['b_pktTotalCount'] - 1] = \
            packets[flow_id]['b_times'][flow_cache[flow_id]['b_pktTotalCount']] \
            - packets[flow_id]['b_times'][flow_cache[flow_id]['b_pktTotalCount'] - 1]

        flow_cache[flow_id]['b_min_piat'] = min(packets[flow_id]['b_iats'].values())
        flow_cache[flow_id]['b_max_piat'] = max(packets[flow_id]['b_iats'].values())
        flow_cache[flow_id]['b_avg_piat'] = sum(packets[flow_id]['b_iats'].values()) / flow_cache[flow_id][
            'b_pktTotalCount']
        flow_cache[flow_id]['b_std_dev_piat'] = np.std(list(packets[flow_id]['b_iats'].values()))


def convert_f_cache_to_dataframe(f_cache):
    """
    Function that converts the flow cahce (nested dictionary) to a pandas dataframe
    :param f_cache: the flow cache (a nested dictionary) that is going to be converted into a DF
    :return: the pandas dataframe
    """
    df = pd.DataFrame.from_dict(f_cache, orient='index')
    df.index.name = 'flow_id'
    df.reset_index(inplace=True)
    df.replace(0, np.NAN, inplace=True)
    return df


# Print the contents of the flow cache
def show_flow_cache(df):
    """
    Function that prints the dataframe
    :param df: the DF to print
    """
    # for f_id, f_info in f_cache.items():
    #     print("\nFlow ID            :", f_id)
    #     for key in f_info:
    #         print('{:<19s}: {}'.format(key, str(f_info[key])))

    pd.options.display.float_format = '{:.6f}'.format
    print(df)



def save_flow_cache(df, file_out):
    """
    Function that stores the dataframe
    :param df: dataframe to be stored as CSV
    :param file_out: the name of the CSV file

    """

    # write into CSV file
    df.to_csv(file_out)

    # write into XLSX file
    # writer = pd.ExcelWriter(file_out)
    # df.to_excel(writer, 'Sheet1')
    # writer.save()



def process_packets(pcap,mode,file_name):
    """Organises each packet in a pcap into a flow record (flow cache)

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
           mode: the mode in which the packets should be organised into flow records. 'u' is for unidirectional, 'b' is for bidirectional. These variables are entered as program arguments when executing the code.
       Returns:
           flow_cache: a nested dictionary storing the flow records
           packet_details: the packet details that have been used to calculate the min/max/avg/std_dev of PS and PIATs
    """

    # Create an empty flow cache (nested dictionary)
    flow_cache = defaultdict(dict)
    packets_details = defaultdict(lambda: defaultdict(dict))

    counter = 0

    # For each packet in the pcap process the contents
    for timestamp, pkt in pcap:

        # print(timestamp, len(pkt))

        # Print out the timestamp in UTC
        # print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))

        # Store preliminary data after processing 500K packets
        counter += 1
        if counter % 100000 == 0:
            print('Already processed %d packets' % counter)
        if counter % 500000 == 0:
            print('%s packets have been processed\n' % counter)
            df = convert_f_cache_to_dataframe(flow_cache)
            name = file_name + '-' + str(counter)
            print('Saving data into %s.csv' % name)
            save_flow_cache(df, name)

        # Parse IP/Port/Proto Information
        try:
            # Unpack the Ethernet frame
            eth = dpkt.ethernet.Ethernet(pkt)
            # print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst))

            # # Now unpack the data within the Ethernet frame (the IP packet)
            ip = eth.data

            # Make sure the Ethernet data contains an IP packet otherwise just skip processing
            # Only handle IP4/6
            if type(ip) == dpkt.ip.IP:
                proto = ip.p
            # elif type(pkt.data) == dpkt.ip6.IP6:
            #     proto = pkt.data.nxt
            else:
                continue

            # Only process packet if the used protocol is TCP or UDP
            if proto == dpkt.ip.IP_PROTO_TCP or proto == dpkt.ip.IP_PROTO_UDP:
                # addr = (
                #        proto, pkt.data.src, pkt.data.data.sport, pkt.data.dst, pkt.data.data.dport)
            # else:
            #     addr = (proto, pkt.data.src, None, pkt.data.dst, None)

            # calculate the flow ID and backward flow ID
                flow_id = (hashlib.md5(
                    (inet_to_str(ip.src) + ' ' + str(ip.data.sport) + ' ' + inet_to_str(ip.dst) + ' ' + str(
                        ip.data.dport) + ' ' + str(ip.p)).encode(
                        'utf-8'))).hexdigest()

                bwd_pkt_flow_id = (hashlib.md5(
                    (inet_to_str(ip.dst) + ' ' + str(ip.data.dport) + ' ' + inet_to_str(ip.src) + ' ' + str(
                        ip.data.sport) + ' ' + str(ip.p)).encode(
                        'utf-8'))).hexdigest()

                if mode == "u":
                    if is_flow_record_present(flow_id, flow_cache) == True:
                        update_flow_record(flow_id, flow_cache, timestamp, ip, packets_details)
                    else:
                        create_flow_record(flow_id, flow_cache, timestamp, ip, packets_details)
                elif mode == "b":
                    if is_flow_record_present(flow_id, flow_cache) == True:
                        update_biflow_record(flow_id, flow_cache, timestamp, ip, 'f', packets_details)
                    elif is_flow_record_present(bwd_pkt_flow_id, flow_cache) == True:
                        update_biflow_record(bwd_pkt_flow_id, flow_cache, timestamp, ip, 'b', packets_details)
                    else:
                        create_biflow_record(flow_id, flow_cache, timestamp, ip, bwd_pkt_flow_id, packets_details)
        except (KeyboardInterrupt):
            print("\n\nSIGINT (Ctrl-c) detected.\n")
            return flow_cache, packets_details
        except:
            continue  # Skip Packet if unable to parse

    return flow_cache, packets_details


# def sniff(interface, mode):
#     """
#     Function that sniffs the packets from a NIC and processes them based on the selected mode (uni/bidirectional)
#     :param interface: the interface from which the packets are going to be captured
#     :param mode: the directionality of organizing packets into flows
#     :return: flow_cache: a nested dictionary storing the flow records
#     :return: packet_details: the packet details that have been used to calculate the min/max/avg/std_dev of PS and PIATs
#     """
#
#     global flow_cache
#     flow_cache = defaultdict(dict)
#
#     global packets_details
#     packets_details = defaultdict(lambda: defaultdict(dict))
#
#     # dev = 'en0'
#     dev = interface
#     maxlen = 65535  # max size of packet to capture
#     promiscuous = 1  # promiscuous mode?
#     read_timeout = 100  # in milliseconds
#     sniffer = pcapy.open_live(dev, maxlen, promiscuous, read_timeout)
#
#     # filter = 'udp or tcp'
#              # 'ip proto \\tcp'
#     # cap.setfilter(filter)
#
#     if mode == "u":
#         try:
#             while True:
#                 # Grab the next header and packet buffer
#                 # header, raw_buf = sniffer.next()
#                 # while header is not None:
#                 #     process_packet(header, raw_buf, mode)
#                 #     header, raw_buf = sniffer.next()
#                 sniffer.loop(0, process_packet_u)
#         except KeyboardInterrupt:
#             print("\n\nSIGINT (Ctrl-c) detected. Exitting...")
#             pass
#     else:
#         try:
#             while True:
#                 # Grab the next header and packet buffer
#                 # header, raw_buf = sniffer.next()
#                 # while header is not None:
#                 #     process_packet(header, raw_buf, mode)
#                 #     header, raw_buf = sniffer.next()
#                 sniffer.loop(0, process_packet_b)
#         except KeyboardInterrupt:
#             print("\n\nSIGINT (Ctrl-c) detected. Exitting...")
#             pass
#
#     # show_flow_cache(flow_cache)
#     # df = pd.DataFrame.from_dict(flow_cache, orient='index')
#     # df.index.name = 'flow_id'
#     # df.reset_index(inplace=True)
#     # df.replace(0, np.NAN, inplace=True)
#     # print(df)
#
#     return flow_cache, packets_details

def process_packet_u(hdr, buf):
    """
    Function that  extracts the details of the packet and passes them to create/update the flow record in one direction
    :param hdr: the header of the packet
    :param buf: the packet
    """

    global flow_cache
    global packets_details

    sec, ms = hdr.getts()
    # print(sec, ms)
    timestamp = sec + ms / 1000000
    # print(timestamp)


    # Parse IP/Port/Proto Information
    try:
        # Unpack the Ethernet frame
        eth = dpkt.ethernet.Ethernet(buf)
        # print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst))

        # Now unpack the data within the Ethernet frame (the IP packet)
        ip = eth.data

        # Make sure the Ethernet data contains an IP packet otherwise just skip processing
        # Only handle IP4/6
        if type(ip) == dpkt.ip.IP:
            proto = ip.p
        # elif type(pkt.data) == dpkt.ip6.IP6:
        #     proto = pkt.data.nxt
        else:
            return

        # Only process packet if the used protocol is TCP or UDP
        if proto == dpkt.ip.IP_PROTO_TCP or proto == dpkt.ip.IP_PROTO_UDP:
            # addr = (
            #        proto, pkt.data.src, pkt.data.data.sport, pkt.data.dst, pkt.data.data.dport)
        # else:
        #     addr = (proto, pkt.data.src, None, pkt.data.dst, None)

        # calculate the flow ID and backward flow ID
            flow_id = (hashlib.md5(
                (inet_to_str(ip.src) + ' ' + str(ip.data.sport) + ' ' + inet_to_str(ip.dst) + ' ' + str(
                    ip.data.dport) + ' ' + str(ip.p)).encode(
                    'utf-8'))).hexdigest()

            bwd_pkt_flow_id = (hashlib.md5(
                (inet_to_str(ip.dst) + ' ' + str(ip.data.dport) + ' ' + inet_to_str(ip.src) + ' ' + str(
                    ip.data.sport) + ' ' + str(ip.p)).encode(
                    'utf-8'))).hexdigest()

            # if mode == "u":
            if is_flow_record_present(flow_id, flow_cache) == True:
                update_flow_record(flow_id, flow_cache, timestamp, ip, packets_details)
            else:
                create_flow_record(flow_id, flow_cache, timestamp, ip, packets_details)
            # elif mode == "b":
            #     if is_flow_record_present(flow_id, flow_cache) == True:
            #         update_biflow_record(flow_id, flow_cache, timestamp, ip, 'f', packets_details)
            #     elif is_flow_record_present(bwd_pkt_flow_id, flow_cache) == True:
            #         update_biflow_record(bwd_pkt_flow_id, flow_cache, timestamp, ip, 'b', packets_details)
            #     else:
            #         create_biflow_record(flow_id, flow_cache, timestamp, ip, bwd_pkt_flow_id, packets_details)

    except:
        return  # Skip Packet if unable to parse



def process_packet_b(hdr, buf):
    """
    Function that  extracts the details of the packet and passes them to create/update the flow record in two directions
    :param hdr: the header of the packet
    :param buf: the packet
    """
    global flow_cache
    global packets_details

    sec, ms = hdr.getts()
    # print(sec, ms)
    timestamp = sec + ms / 1000000
    # print(timestamp)

    # Parse IP/Port/Proto Information
    try:
        # Unpack the Ethernet frame
        eth = dpkt.ethernet.Ethernet(buf)
        # print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst))

        # # Now unpack the data within the Ethernet frame (the IP packet)
        ip = eth.data

        # Make sure the Ethernet data contains an IP packet otherwise just skip processing
        # Only handle IP4/6
        if type(ip) == dpkt.ip.IP:
            proto = ip.p
        # elif type(pkt.data) == dpkt.ip6.IP6:
        #     proto = pkt.data.nxt
        else:
            return

        # Only process packet if the used protocol is TCP or UDP
        if proto == dpkt.ip.IP_PROTO_TCP or proto == dpkt.ip.IP_PROTO_UDP:
            # addr = (
            #        proto, pkt.data.src, pkt.data.data.sport, pkt.data.dst, pkt.data.data.dport)
        # else:
        #     addr = (proto, pkt.data.src, None, pkt.data.dst, None)

        # calculate the flow ID and backward flow ID
            flow_id = (hashlib.md5(
                (inet_to_str(ip.src) + ' ' + str(ip.data.sport) + ' ' + inet_to_str(ip.dst) + ' ' + str(
                    ip.data.dport) + ' ' + str(ip.p)).encode(
                    'utf-8'))).hexdigest()

            bwd_pkt_flow_id = (hashlib.md5(
                (inet_to_str(ip.dst) + ' ' + str(ip.data.dport) + ' ' + inet_to_str(ip.src) + ' ' + str(
                    ip.data.sport) + ' ' + str(ip.p)).encode(
                    'utf-8'))).hexdigest()

            if is_flow_record_present(flow_id, flow_cache) == True:
                update_biflow_record(flow_id, flow_cache, timestamp, ip, 'f', packets_details)
            elif is_flow_record_present(bwd_pkt_flow_id, flow_cache) == True:
                update_biflow_record(bwd_pkt_flow_id, flow_cache, timestamp, ip, 'b', packets_details)
            else:
                create_biflow_record(flow_id, flow_cache, timestamp, ip, bwd_pkt_flow_id, packets_details)

    except:
        return  # Skip Packet if unable to parse



# def process_packet(hdr, buf):
#
#     global flow_cache
#     global packets_details
#
#     # print (hdr)
#     # print('%s: captured %d bytes, truncated to %d bytes'
#     #       % (datetime.datetime.now(), hdr.getlen(), hdr.getcaplen()))
#
#     sec, ms = hdr.getts()
#     # print(sec, ms)
#     timestamp = sec + ms / 1000000
#     # print(timestamp)
#
#
#     eth = dpkt.ethernet.Ethernet(buf)
#     ip = eth.data
#
#     # Make sure the Ethernet data contains an IP packet otherwise just stop processing
#     if not isinstance(ip, dpkt.ip.IP):
#         # print('%s packet type is not supported\n' % eth.data.__class__.__name__)
#         return
#
#     # Now check if this is an ICMP packet
#     if isinstance(ip.data, dpkt.icmp.ICMP):
#         print('ICMP packet detected. Skipping parsing.\n')
#         return
#
#     # Now check if this is an ICMP packet
#     if isinstance(ip.data, dpkt.igmp.IGMP):
#         print('IGMP packet detected. Skipping parsing.\n')
#         return
#
#     # calculate the flow ID and backward flow ID
#     flow_id = (hashlib.md5(
#         (inet_to_str(ip.src) + ' ' + str(ip.data.sport) + ' ' + inet_to_str(ip.dst) + ' ' + str(ip.data.dport) + ' ' + str(ip.p)).encode(
#             'utf-8'))).hexdigest()
#
#     bwd_pkt_flow_id = (hashlib.md5(
#         (inet_to_str(ip.dst) + ' ' + str(ip.data.dport) + ' ' + inet_to_str(ip.src) + ' ' + str(ip.data.sport) + ' ' + str(ip.p)).encode(
#             'utf-8'))).hexdigest()
#
#     # if is_flow_record_present(flow_id, flow_cache) == True:
#     #     update_flow_record(flow_id, flow_cache, timestamp, ip, packets_details)
#     # else:
#     #     create_flow_record(flow_id, flow_cache, timestamp, ip, packets_details)
#
#
#     if mode == "u":
#         if is_flow_record_present(flow_id, flow_cache) == True:
#             update_flow_record(flow_id, flow_cache, timestamp, ip, packets_details)
#         else:
#             create_flow_record(flow_id, flow_cache, timestamp, ip, packets_details)
#     elif mode == "b":
#         if is_flow_record_present(flow_id, flow_cache) == True:
#             update_biflow_record(flow_id, flow_cache, timestamp, ip, 'f', packets_details)
#         elif is_flow_record_present(bwd_pkt_flow_id, flow_cache) == True:
#             update_biflow_record(bwd_pkt_flow_id, flow_cache, timestamp, ip, 'b', packets_details)
#         else:
#             create_biflow_record(flow_id, flow_cache, timestamp, ip, bwd_pkt_flow_id, packets_details)




def show_calculation_details(key1,key2,packets):
    """
    Function that based on a flowID shows the details for the calculation of min/max/avg/std_dev of PS and PIATs
    :param key1: the FlowID that was is based on the 5-tuple
    :param key2: a second key that can be either length, times or iats
    :param packets: the nested dict that stores all the information
    """

    # print("\nItems : ", packets[key1][key2])
    print("\nNumber of items   : ", len(packets[key1][key2]))
    print("Values            : ", list(packets[key1][key2].values()))
    print("Min               : ", min(packets[key1][key2].values()))
    print("Max               : ", max(packets[key1][key2].values()))
    # print(sum(s_dict[key1][key2].values()))
    # print(len(s_dict[key1][key2].values()))
    # print(float(len(s_dict[key1][key2])))
    print("Avg               : ", sum(packets[key1][key2].values()) / len(packets[key1][key2].values()))
    print("Std_dev           : ", np.std(list(packets[key1][key2].values())))



if __name__ == '__main__':

    import click

    # global control
    # global flow_cache

    global flow_cache
    flow_cache = defaultdict(dict)

    global packets_details
    packets_details = defaultdict(lambda: defaultdict(dict))

    @click.command()
    @click.option('-d', '--direction', 'direction', help='The directionality of measurement.')
    @click.option('-i', '--interface', 'interface', help='The interface for live packet capture.')
    @click.option('-f', '--file', 'file_in', help='PCAP file for parsing.')
    @click.option('-o', '--out', 'file_out', help='Name of the file in which the data will be stored.')


    def main(direction, interface, file_in, file_out):
        """
            A packet parser tool. It parses the packets and organize them into flow records. The tool can work in two modes:

            1. Live packet capture from a NIC
            2. Parsing packets from a PCAP file.

            The program can take a number of arguments:
            -d, --dricetion  sets whether the packets will be organised into flows in uni- or bidirection
            -i, --interface sets the networking interface card from which the packets will be sniffed
            -f, --file sets the name of the PCAP file
            -o, --out sets the name of the CSV file into which the results will be saved

            Examples:
                1) To read in a PCAP file and process the packets into flows in one direction, and save the results into a CSV file the following command can be used:
                    python3 flowRecorder.py -d u -f p.pcap -o results.csv
                2) To start caputring the packets from a NIC and organize them into flow records in bidirection, the following command can be used:
                    python3 flowRecorder.py -d b -i en0 -o results.csv
           """


        if direction not in ['u', 'b']:
            print("Invalid or wrong input for the directionality of measurement.\n")

        if interface is None:
            pass
        else:

            dev = interface
            maxlen = 65535  # max size of packet to capture
            promiscuous = 1  # promiscuous mode?
            read_timeout = 100  # in milliseconds
            sniffer = pcapy.open_live(dev, maxlen, promiscuous, read_timeout)

            # filter = 'udp or tcp'
            # sniffer.setfilter(filter)

            # start sniffing
            if direction == "u":
                while True:
                    print("Start sniffing on interface %s" % interface)
                    print("Sniffing can be aborted via pressing Ctrl-c")
                    try:
                        sniffer.loop(0, process_packet_u)
                    except (KeyboardInterrupt, SystemExit):
                        print("\n\nSIGINT (Ctrl-c) detected.\n")
                        df = convert_f_cache_to_dataframe(flow_cache)
                        # show_flow_cache(df)
                        print('Writing the contents of the flow cache into %s\n' % file_out)
                        save_flow_cache(df, file_out)
                        # f_cache, packet_details = sniff(interface, direction)
                        raise
            elif direction == "b":
                while True:
                    print("Start sniffing on interface %s" % interface)
                    print("Sniffing can be aborted via pressing Ctrl-c")
                    try:
                        sniffer.loop(0, process_packet_b)
                    except (KeyboardInterrupt, SystemExit):
                        print("\n\nSIGINT (Ctrl-c) detected.\n")
                        df = convert_f_cache_to_dataframe(flow_cache)
                        # show_flow_cache(df)
                        print('Writing the contents of the flow cache into %s\n' % file_out)
                        save_flow_cache(df, file_out)
                        # f_cache, packet_details = sniff(interface, direction)
                        raise

        if file_in is None:
            pass
        else:
            time0 = time.time()
            with open(file_in, 'rb') as file:
                pcap = dpkt.pcap.Reader(file)
                time1 = time.time()
                print("Open file time is", time1 - time0)
                print("Start processing the packets in the PCAP file.")
                print("Parsing can be aborted via pressing Ctrl-c.")

                # process packets
                f_cache, packet_details = process_packets(pcap, direction,file_out)
                time2 = time.time()
                print("Process packets time is", time2 - time1)

            df = convert_f_cache_to_dataframe(f_cache)
            # show_flow_cache(df)
            save_flow_cache(df, file_out)
            time3 = time.time()
            print("Total elapsed time is", time3 - time0)

            # show_calculation_details('03ebfd4bf44b3ec00980a5d96bf9833e', 'bi_length', packet_details)
            # show_calculation_details('03ebfd4bf44b3ec00980a5d96bf9833e', 'f_length', packet_details)
            # show_calculation_details('03ebfd4bf44b3ec00980a5d96bf9833e', 'b_length', packet_details)

            # show_calculation_details('03ebfd4bf44b3ec00980a5d96bf9833e','bi_times',packet_details)
            # show_calculation_details('03ebfd4bf44b3ec00980a5d96bf9833e','f_times',packet_details)
            # show_calculation_details('03ebfd4bf44b3ec00980a5d96bf9833e','b_times',packet_details)

            # show_calculation_details('03ebfd4bf44b3ec00980a5d96bf9833e', 'bi_iats', packet_details)
            # show_calculation_details('03ebfd4bf44b3ec00980a5d96bf9833e', 'f_iats', packet_details)
            # show_calculation_details('03ebfd4bf44b3ec00980a5d96bf9833e', 'b_iats', packet_details)

    main()
