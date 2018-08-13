#!/usr/bin/env python
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
  if key in flow_cache:
      # print('Flow Record is present in the Flow Cache')
      return True
  else:
      # print('Flow Record is NOT present in the Flow Cache')
      return False



# build the flow record
def create_flow_record(flow_id,flow_cache,timestamp, ip, packets):
    # print('Creating the flow record')
    # flow_cache[flow_id]['bwd_pkt_flow_id'] = bwd_id
    flow_cache[flow_id]['src_ip'] = inet_to_str(ip.src)
    flow_cache[flow_id]['src_port'] = ip.data.sport
    flow_cache[flow_id]['dst_ip'] = inet_to_str(ip.dst)
    flow_cache[flow_id]['dst_port'] = ip.data.dport
    flow_cache[flow_id]['proto'] = ip.p
    flow_cache[flow_id]['flowStart'] = timestamp
    flow_cache[flow_id]['flowEnd'] = timestamp
    flow_cache[flow_id]['flowDuration'] = (timestamp - flow_cache[flow_id]['flowStart'])
    flow_cache[flow_id]['pktTotalCount'] = 1
    flow_cache[flow_id]['octetTotalCount'] = ip.len
    packets[flow_id]['times'][flow_cache[flow_id]['pktTotalCount']] = timestamp
    packets[flow_id]['length'][flow_cache[flow_id]['pktTotalCount']] = ip.len
    flow_cache[flow_id]['size_min'] = ip.len
    flow_cache[flow_id]['size_max'] = ip.len
    flow_cache[flow_id]['size_avg'] = flow_cache[flow_id]['octetTotalCount'] / flow_cache[flow_id]['pktTotalCount']
    flow_cache[flow_id]['size_std_dev'] = np.std(list(packets[flow_id]['length'].values()))

    flow_cache[flow_id]['iat_min'] = 0
    flow_cache[flow_id]['iat_max'] = 0
    flow_cache[flow_id]['iat_avg'] = 0
    flow_cache[flow_id]['iat_std_dev'] = 0


# update the flow record
def update_flow_record(flow_id,flow_cache,timestamp,ip,packets):
    # print('Updating the flow record')
    flow_cache[flow_id]['flowEnd'] = timestamp
    flow_cache[flow_id]['flowDuration'] = (timestamp - flow_cache[flow_id]['flowStart'])
    flow_cache[flow_id]['pktTotalCount'] += 1
    flow_cache[flow_id]['octetTotalCount'] += ip.len
    packets[flow_id]['length'][flow_cache[flow_id]['pktTotalCount']] = ip.len
    packets[flow_id]['times'][flow_cache[flow_id]['pktTotalCount']] = timestamp
    flow_cache[flow_id]['size_min'] = min(packets[flow_id]['length'].values())
    flow_cache[flow_id]['size_max'] = max(packets[flow_id]['length'].values())
    flow_cache[flow_id]['size_avg'] = flow_cache[flow_id]['octetTotalCount'] / flow_cache[flow_id]['pktTotalCount']
    flow_cache[flow_id]['size_std_dev'] = np.std(list(packets[flow_id]['length'].values()))

    packets[flow_id]['iats'][flow_cache[flow_id]['pktTotalCount']-1] = packets[flow_id]['times'][flow_cache[flow_id]['pktTotalCount']] - packets[flow_id]['times'][flow_cache[flow_id]['pktTotalCount']-1]

    flow_cache[flow_id]['iat_min'] = min(packets[flow_id]['iats'].values())
    flow_cache[flow_id]['iat_max'] = max(packets[flow_id]['iats'].values())
    flow_cache[flow_id]['iat_avg'] = sum(packets[flow_id]['iats'].values()) / flow_cache[flow_id]['pktTotalCount']
    flow_cache[flow_id]['iat_std_dev'] = np.std(list(packets[flow_id]['iats'].values()))


# build the flow record
def create_biflow_record(flow_id,flow_cache,timestamp, ip, bwd_id):
    # print('Creating the flow record')
    flow_cache[flow_id]['bwd_pkt_flow_id'] = bwd_id
    flow_cache[flow_id]['src_ip'] = inet_to_str(ip.src)
    flow_cache[flow_id]['dst_ip'] = inet_to_str(ip.dst)
    flow_cache[flow_id]['src_port'] = ip.data.sport
    flow_cache[flow_id]['dst_port'] = ip.data.dport
    flow_cache[flow_id]['proto'] = ip.p

    flow_cache[flow_id]['BI_flowStart'] = timestamp
    flow_cache[flow_id]['BI_flowEnd'] = timestamp
    flow_cache[flow_id]['BI_flowDuration'] = (timestamp - flow_cache[flow_id]['BI_flowStart'])
    flow_cache[flow_id]['BI_pktTotalCount'] = 1
    flow_cache[flow_id]['BI_octetTotalCount'] = ip.len

    flow_cache[flow_id]['F_flowStart'] = timestamp
    flow_cache[flow_id]['F_flowEnd'] = timestamp
    flow_cache[flow_id]['F_flowDuration'] = (timestamp - flow_cache[flow_id]['F_flowStart'])
    flow_cache[flow_id]['F_pktTotalCount'] = 1
    flow_cache[flow_id]['F_octetTotalCount'] = ip.len

    flow_cache[flow_id]['B_flowStart'] = 0
    flow_cache[flow_id]['B_flowEnd'] = 0
    flow_cache[flow_id]['B_flowDuration'] = 0
    flow_cache[flow_id]['B_pktTotalCount'] = 0
    flow_cache[flow_id]['B_octetTotalCount'] = 0



# update the flow record
def update_biflow_record(flow_id,flow_cache,timestamp,ip, dir):
    # print('Updating the flow record')
    flow_cache[flow_id]['BI_flowEnd'] = timestamp
    flow_cache[flow_id]['BI_flowDuration'] = (timestamp - flow_cache[flow_id]['BI_flowStart'])
    flow_cache[flow_id]['BI_pktTotalCount'] += 1
    flow_cache[flow_id]['BI_octetTotalCount'] += ip.len
    if dir == 'f':
        flow_cache[flow_id]['F_flowEnd'] = timestamp
        flow_cache[flow_id]['F_flowDuration'] = (timestamp - flow_cache[flow_id]['F_flowStart'])
        flow_cache[flow_id]['F_pktTotalCount'] += 1
        flow_cache[flow_id]['F_octetTotalCount'] += ip.len
    else:
        if flow_cache[flow_id]['B_flowStart'] == 0:
            flow_cache[flow_id]['B_flowStart'] = timestamp
        flow_cache[flow_id]['B_flowEnd'] = timestamp
        flow_cache[flow_id]['B_flowDuration'] = (timestamp - flow_cache[flow_id]['B_flowStart'])
        flow_cache[flow_id]['B_pktTotalCount'] += 1
        flow_cache[flow_id]['B_octetTotalCount'] += ip.len



# Print the contents of the flow cache
def show_flow_cache(f_cache):
    for f_id, f_info in f_cache.items():
        print("\nFlow ID            :", f_id)
        for key in f_info:
            print('{:<19s}: {}'.format(key, str(f_info[key])))



def process_packets(pcap,mode):
    """Organises each packet in a pcap into a flow record (flow cache)

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """

    # Create an empty flow cache (nested dictionary)
    flow_cache = defaultdict(dict)
    packets_details = defaultdict(lambda: defaultdict(dict))

    # For each packet in the pcap process the contents
    for timestamp, pkt in pcap:

        # print(timestamp, len(pkt))

        # Print out the timestamp in UTC
        # print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))

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
                        update_biflow_record(flow_id, flow_cache, timestamp, ip, 'f')
                    elif is_flow_record_present(bwd_pkt_flow_id, flow_cache) == True:
                        update_biflow_record(bwd_pkt_flow_id, flow_cache, timestamp, ip, 'b')
                    else:
                        create_biflow_record(flow_id, flow_cache, timestamp, ip, bwd_pkt_flow_id)

        except:
            continue  # Skip Packet if unable to parse


    return flow_cache, packets_details


def sniff(interface):

    global flow_cache
    flow_cache = defaultdict(dict)

    global packets_details
    packets_details = defaultdict(lambda: defaultdict(dict))

    # dev = 'en0'
    dev = interface
    maxlen = 65535  # max size of packet to capture
    promiscuous = 1  # promiscuous mode?
    read_timeout = 100  # in milliseconds
    sniffer = pcapy.open_live(dev, maxlen, promiscuous, read_timeout)

    # filter = 'udp or tcp'
             # 'ip proto \\tcp'
    # cap.setfilter(filter)

    try:
        while True:
            # Grab the next header and packet buffer
            # header, raw_buf = sniffer.next()
            # process_packet(header, raw_buf)
            sniffer.loop(0, process_packet)
    except KeyboardInterrupt:
        print("\n\nSIGINT (Ctrl-c) detected. Exitting...")
        pass

    # show_flow_cache(flow_cache)
    # df = pd.DataFrame.from_dict(flow_cache, orient='index')
    # df.index.name = 'flow_id'
    # df.reset_index(inplace=True)
    # df.replace(0, np.NAN, inplace=True)
    # print(df)

    return flow_cache, packets_details



def process_packet(hdr, buf):

    global flow_cache
    global packets_details

    # print (hdr)
    # print('%s: captured %d bytes, truncated to %d bytes'
    #       % (datetime.datetime.now(), hdr.getlen(), hdr.getcaplen()))

    sec, ms = hdr.getts()
    # print(sec, ms)
    timestamp = sec + ms / 1000000
    # print(timestamp)


    eth = dpkt.ethernet.Ethernet(buf)
    ip = eth.data

    # Make sure the Ethernet data contains an IP packet otherwise just stop processing
    if not isinstance(ip, dpkt.ip.IP):
        # print('%s packet type is not supported\n' % eth.data.__class__.__name__)
        return

    # Now check if this is an ICMP packet
    if isinstance(ip.data, dpkt.icmp.ICMP):
        print('ICMP packet detected. Skipping parsing.\n')
        return

    # Now check if this is an ICMP packet
    if isinstance(ip.data, dpkt.igmp.IGMP):
        print('IGMP packet detected. Skipping parsing.\n')
        return

    # calculate the flow ID and backward flow ID
    flow_id = (hashlib.md5(
        (inet_to_str(ip.src) + ' ' + str(ip.data.sport) + ' ' + inet_to_str(ip.dst) + ' ' + str(ip.data.dport) + ' ' + str(ip.p)).encode(
            'utf-8'))).hexdigest()

    bwd_pkt_flow_id = (hashlib.md5(
        (inet_to_str(ip.dst) + ' ' + str(ip.data.dport) + ' ' + inet_to_str(ip.src) + ' ' + str(ip.data.sport) + ' ' + str(ip.p)).encode(
            'utf-8'))).hexdigest()

    if is_flow_record_present(flow_id, flow_cache) == True:
        update_flow_record(flow_id, flow_cache, timestamp, ip, packets_details)
    else:
        create_flow_record(flow_id, flow_cache, timestamp, ip, packets_details)

def show_calculation_details(key1,key2,packets):

    print("\nItems : ", packets[key1][key2])
    print("Values: ", list(packets[key1][key2].values()))
    print("Min   : ", min(packets[key1][key2].values()))
    print("Max   : ", max(packets[key1][key2].values()))
    # print(sum(s_dict[key1][key2].values()))
    # print(len(s_dict[key1][key2].values()))
    # print(float(len(s_dict[key1][key2])))
    print("Mean  : ", sum(packets[key1][key2].values()) / len(packets[key1][key2].values()))
    print("Std_d : ", np.std(list(packets[key1][key2].values())))



if __name__ == '__main__':

    import click

    # global control
    # global flow_cache

    @click.command()
    @click.option('-d', '--direction', 'direction', help='The directionality of measurement.')
    @click.option('-i', '--interface', 'interface', help='The interface for live packet capture.')
    @click.option('-f', '--file', 'file', help='PCAP file for parsing.')


    def main(direction, interface, file):
        """
            A packet parser tool. It parses the packets and organize them into flow records. The tool has two options.

            1. Live packet capture from an interface card.
            2. Parsing packet in a PCAP file.
           """

        if direction not in ['u', 'b']:
            print("Invalid or wrong input for flow directionality.\n"
              "Packets will be organized into flows in one-direction.\n")
            dir = 'u'
        else:
            if direction == "u":
                print("Packets will be organized into flows in one-direction.\n")
            if direction == "b":
                print("Packets will be organized into flows in bi-direction.\n")
            dir = direction

        if interface is None:
            pass
        else:

            f_cache, packet_details = sniff(interface)

            df = pd.DataFrame.from_dict(f_cache, orient='index')
            df.index.name = 'flow_id'
            df.reset_index(inplace=True)
            df.replace(0, np.NAN, inplace=True)

            pd.options.display.float_format = '{:.6f}'.format

            print(df)


        if file is None:
            pass
        else:
            with open(file, 'rb') as file:
                pcap = dpkt.pcap.Reader(file)

                # process packets
                # 'u' is for unidirectional flows, 'b' is for bidirectional flows
                f_cache, packet_details = process_packets(pcap,dir)

            # show_flow_cache(f_cache)
            df = pd.DataFrame.from_dict(f_cache, orient='index')
            df.index.name = 'flow_id'
            df.reset_index(inplace=True)
            df.replace(0, np.NAN, inplace=True)

            print(df)
            # print(df.dtypes)

            # show_calculation_details('ffaaba4798330f4687f246bedc444b7a','iats',packet_details)

            # write into CSV file
            df.to_csv('out.csv')

            # write into XLSX file
            # writer = pd.ExcelWriter('output.xlsx')
            # df.to_excel(writer, 'Sheet1')
            # writer.save()

    main()
