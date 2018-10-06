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
Packets with metadata to use in testing of flowRecorder

This flow is a single TCP SYN packet

    To create test packet data, capture packet in Wireshark and:

      For the packet summary:
        Right-click packet in top pane, Copy -> Summary (text).
        Edit pasted text as appropriate

      For the packet hex:
        Right-click packet in top pane, Copy -> Bytes -> Hex Stream

      For the packet timestamp:
        Expand 'Frame' in the middle pane,
        right-click 'Epoch Time' Copy -> Value

Packet capture file is 'tcp_syn_only.pcap'
"""

import binascii

name = 'groundtruth_tcp_syn_only.py'
capture_file = 'tcp_syn_only.pcap'

#======================== Initiate Lists ======================
#*** Raw packet data:
RAW = []
#*** Packet on the wire lengths in bytes:
LEN = []
#*** Ethernet parameters:
ETH_SRC = []
ETH_DST = []
ETH_TYPE = []
#*** IP addresses:
IP_SRC = []
IP_DST = []
#*** IP protocol number in decimal:
PROTO = []
#*** Transport-layer protocol numbers in decimal:
TP_SRC = []
TP_DST = []
#*** Transport-layer sequence numbers in decimal:
TP_SEQ_SRC = []
TP_SEQ_DST = []
#*** TCP FLAGS:
TCP_SYN = []
TCP_FIN = []
TCP_RST = []
TCP_PSH = []
TCP_ACK = []
#*** HEX-encoded payload
PAYLOAD = []
#*** Packet direction, c2s (client to server) or s2c
DIRECTION = []

# Unidir Flow values:
UNIDIR_SRC_IP = []
UNIDIR_SRC_PORT = []
UNIDIR_DST_IP = []
UNIDIR_DST_PORT = []
UNIDIR_PROTO = []
UNIDIR_PKTTOTALCOUNT = []
UNIDIR_OCTETTOTALCOUNT = []
UNIDIR_MIN_PS = []
UNIDIR_MAX_PS = []
UNIDIR_AVG_PS = []
UNIDIR_STD_DEV_PS = []
UNIDIR_FLOWSTART = []
UNIDIR_FLOWEND = []
UNIDIR_FLOWDURATION = []
UNIDIR_MIN_PIAT = []
UNIDIR_MAX_PIAT = []
UNIDIR_AVG_PIAT = []
UNIDIR_STD_DEV_PIAT = []
# Bidirectional:
# Combined Flow values:
BIDIR_SRC_IP = []
BIDIR_SRC_PORT = []
BIDIR_DST_IP = []
BIDIR_DST_PORT = []
BIDIR_PROTO = []
BIDIR_PKTTOTALCOUNT = []
BIDIR_OCTETTOTALCOUNT = []
BIDIR_MIN_PS = []
BIDIR_MAX_PS = []
BIDIR_AVG_PS = []
BIDIR_STD_DEV_PS = []
BIDIR_FLOWSTART = []
BIDIR_FLOWEND = []
BIDIR_FLOWDURATION = []
BIDIR_MIN_PIAT = []
BIDIR_MAX_PIAT = []
BIDIR_AVG_PIAT = []
BIDIR_STD_DEV_PIAT = []
# Forward Flow values:
BIDIR_F_SRC_IP = []
BIDIR_F_SRC_PORT = []
BIDIR_F_DST_IP = []
BIDIR_F_DST_PORT = []
BIDIR_F_PROTO = []
BIDIR_F_PKTTOTALCOUNT = []
BIDIR_F_OCTETTOTALCOUNT = []
BIDIR_F_MIN_PS = []
BIDIR_F_MAX_PS = []
BIDIR_F_AVG_PS = []
BIDIR_F_STD_DEV_PS = []
BIDIR_F_FLOWSTART = []
BIDIR_F_FLOWEND = []
BIDIR_F_FLOWDURATION = []
BIDIR_F_MIN_PIAT = []
BIDIR_F_MAX_PIAT = []
BIDIR_F_AVG_PIAT = []
BIDIR_F_STD_DEV_PIAT = []
# Backward Flow values:
BIDIR_B_SRC_IP = []
BIDIR_B_SRC_PORT = []
BIDIR_B_DST_IP = []
BIDIR_B_DST_PORT = []
BIDIR_B_PROTO = []
BIDIR_B_PKTTOTALCOUNT = []
BIDIR_B_OCTETTOTALCOUNT = []
BIDIR_B_MIN_PS = []
BIDIR_B_MAX_PS = []
BIDIR_B_AVG_PS = []
BIDIR_B_STD_DEV_PS = []
BIDIR_B_FLOWSTART = []
BIDIR_B_FLOWEND = []
BIDIR_B_FLOWDURATION = []
BIDIR_B_MIN_PIAT = []
BIDIR_B_MAX_PIAT = []
BIDIR_B_AVG_PIAT = []
BIDIR_B_STD_DEV_PIAT = []

#*** Packet 1 - TCP SYN
# 1 1538798807.496015 10.0.2.15 10.0.2.2 TCP 74 49440 443 [SYN] Seq=0 Win=29200 Len=0 MSS=1460 SACK_PERM=1 TSval=3618186009 TSecr=0 WS=128
RAW.append(binascii.unhexlify("525400123502080027fc133d08004510003c410440004006e1970a00020f0a000202c12001bbcaf098b800000000a0027210183f0000020405b40402080ad7a923190000000001030307"))
LEN.append(74)
ETH_SRC.append('08:00:27:fc:13:3d')
ETH_DST.append('52:54:00:12:35:02')
ETH_TYPE.append(2048)
IP_SRC.append('10.0.2.15')
IP_DST.append('10.0.2.2')
PROTO.append(6)
TP_SRC.append(49440)
TP_DST.append(443)
TP_SEQ_SRC.append(0)
TP_SEQ_DST.append(0)
TCP_SYN.append(1)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(0)
PAYLOAD.append("")
DIRECTION.append("c2s")

#*** Metadata for whole flow:
FLOW_IP_CLIENT = '10.0.2.15'
FLOW_IP_SERVER = '10.0.2.2'

# Unidirectional flow values:
# Flow 1:
UNIDIR_SRC_IP.append('10.0.2.15')
UNIDIR_SRC_PORT.append('49440')
UNIDIR_DST_IP.append('10.0.2.2')
UNIDIR_DST_PORT.append('443')
UNIDIR_PROTO.append('6')
UNIDIR_PKTTOTALCOUNT.append('1')
UNIDIR_OCTETTOTALCOUNT.append('74')
UNIDIR_MIN_PS.append('74')
UNIDIR_MAX_PS.append('74')
UNIDIR_AVG_PS.append('74')
UNIDIR_STD_DEV_PS.append('0')
UNIDIR_FLOWSTART.append('1538798807.496015')
UNIDIR_FLOWEND.append('1538798807.496015')
UNIDIR_FLOWDURATION.append('0')
UNIDIR_MIN_PIAT.append('0')
UNIDIR_MAX_PIAT.append('0')
UNIDIR_AVG_PIAT.append('0')
UNIDIR_STD_DEV_PIAT.append('0')
# Bidirectional Combined Flow 1:
BIDIR_SRC_IP.append('10.0.2.15')
BIDIR_SRC_PORT.append('49440')
BIDIR_DST_IP.append('10.0.2.2')
BIDIR_DST_PORT.append('443')
BIDIR_PROTO.append('6')
BIDIR_PKTTOTALCOUNT.append('1')
BIDIR_OCTETTOTALCOUNT.append('74')
BIDIR_MIN_PS.append('74')
BIDIR_MAX_PS.append('74')
BIDIR_AVG_PS.append('74')
BIDIR_STD_DEV_PS.append('0')
BIDIR_FLOWSTART.append('1538798807.496015')
BIDIR_FLOWEND.append('1538798807.496015')
BIDIR_FLOWDURATION.append('0')
BIDIR_MIN_PIAT.append('0')
BIDIR_MAX_PIAT.append('0')
BIDIR_AVG_PIAT.append('0')
BIDIR_STD_DEV_PIAT.append('0')
BIDIR_F_PKTTOTALCOUNT.append('1')
BIDIR_F_OCTETTOTALCOUNT.append('74')
BIDIR_F_MIN_PS.append('74')
BIDIR_F_MAX_PS.append('74')
BIDIR_F_AVG_PS.append('74')
BIDIR_F_STD_DEV_PS.append('0')
BIDIR_F_FLOWSTART.append('1538798807.496015')
BIDIR_F_FLOWEND.append('1538798807.496015')
BIDIR_F_FLOWDURATION.append('0')
BIDIR_F_MIN_PIAT.append('0')
BIDIR_F_MAX_PIAT.append('0')
BIDIR_F_AVG_PIAT.append('0')
BIDIR_F_STD_DEV_PIAT.append('0')
BIDIR_B_PKTTOTALCOUNT.append('0')
BIDIR_B_OCTETTOTALCOUNT.append('0')
BIDIR_B_MIN_PS.append('0')
BIDIR_B_MAX_PS.append('0')
BIDIR_B_AVG_PS.append('0')
BIDIR_B_STD_DEV_PS.append('0')
BIDIR_B_FLOWSTART.append('0')
BIDIR_B_FLOWEND.append('0')
BIDIR_B_FLOWDURATION.append('0')
BIDIR_B_MIN_PIAT.append('0')
BIDIR_B_MAX_PIAT.append('0')
BIDIR_B_AVG_PIAT.append('0')
BIDIR_B_STD_DEV_PIAT.append('0')





