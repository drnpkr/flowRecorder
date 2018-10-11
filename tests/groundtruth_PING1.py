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

This flow is two separate ICMP echo request/reply (PING) pairs
between same source and destination

    To create test packet data, capture packet in Wireshark and:

      For the packet summary:
        Right-click packet in top pane, Copy -> Summary (text).
        Edit pasted text as appropriate

      For the packet hex:
        Right-click packet in top pane, Copy -> Bytes -> Hex Stream

      For the packet timestamp:
        Expand 'Frame' in the middle pane,
        right-click 'Epoch Time' Copy -> Value

Packet capture file is 'http1.pcap'
"""

import binascii

name = 'groundtruth_PING1.py'
capture_file = 'PING1.pcap'

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

#*** Packet 1 - Echo Request
# 1	0.000000000	10.0.2.15	10.0.2.2	ICMP	98	Echo (ping) request  id=0x1ac1, seq=1/256, ttl=64 (reply in 2)
RAW.append(binascii.unhexlify("525400123502080027fc133d080045000054ec934000400136050a00020f0a0002020800c96c1ac10001b4c8b55b00000000e2d9080000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"))
LEN.append(84)
ETH_SRC.append('08:00:27:fc:13:3d')
ETH_DST.append('52:54:00:12:35:02')
ETH_TYPE.append(2048)
IP_SRC.append('10.0.2.15')
IP_DST.append('10.0.2.2')
PROTO.append(1)
TP_SRC.append(0)
TP_DST.append(0)
TP_SEQ_SRC.append(0)
TP_SEQ_DST.append(0)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(0)
PAYLOAD.append("")
DIRECTION.append("c2s")

#*** Packet 2 - Echo Reply
# 2	0.000188156	10.0.2.2	10.0.2.15	ICMP	98	Echo (ping) reply    id=0x1ac1, seq=1/256, ttl=64 (request in 1)
RAW.append(binascii.unhexlify("080027fc133d525400123502080045000054c47b400040015e1d0a0002020a00020f0000d16c1ac10001b4c8b55b00000000e2d9080000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"))
LEN.append(84)
ETH_SRC.append('52:54:00:12:35:02')
ETH_DST.append('08:00:27:fc:13:3d')
ETH_TYPE.append(2048)
IP_SRC.append('10.0.2.2')
IP_DST.append('10.0.2.15')
PROTO.append(1)
TP_SRC.append(0)
TP_DST.append(0)
TP_SEQ_SRC.append(0)
TP_SEQ_DST.append(0)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(0)
PAYLOAD.append("")
DIRECTION.append("s2c")

#*** Packet 3 - Echo Request
# 3	1.018124169	10.0.2.15	10.0.2.2	ICMP	98	Echo (ping) request  id=0x1ac1, seq=2/512, ttl=64 (reply in 4)
RAW.append(binascii.unhexlify("525400123502080027fc133d080045000054ed734000400135250a00020f0a00020208000d251ac10002b5c8b55b000000009d20090000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"))
LEN.append(84)
ETH_SRC.append('08:00:27:fc:13:3d')
ETH_DST.append('52:54:00:12:35:02')
ETH_TYPE.append(2048)
IP_SRC.append('10.0.2.15')
IP_DST.append('10.0.2.2')
PROTO.append(1)
TP_SRC.append(0)
TP_DST.append(0)
TP_SEQ_SRC.append(0)
TP_SEQ_DST.append(0)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(0)
PAYLOAD.append("")
DIRECTION.append("c2s")

#*** Packet 4 - Echo Reply
# 4	1.018347117	10.0.2.2	10.0.2.15	ICMP	98	Echo (ping) reply    id=0x1ac1, seq=2/512, ttl=64 (request in 3)
RAW.append(binascii.unhexlify("080027fc133d525400123502080045000054c47c400040015e1c0a0002020a00020f000015251ac10002b5c8b55b000000009d20090000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637"))
LEN.append(84)
ETH_SRC.append('52:54:00:12:35:02')
ETH_DST.append('08:00:27:fc:13:3d')
ETH_TYPE.append(2048)
IP_SRC.append('10.0.2.2')
IP_DST.append('10.0.2.15')
PROTO.append(1)
TP_SRC.append(0)
TP_DST.append(0)
TP_SEQ_SRC.append(0)
TP_SEQ_DST.append(0)
TCP_SYN.append(0)
TCP_FIN.append(0)
TCP_RST.append(0)
TCP_PSH.append(0)
TCP_ACK.append(0)
PAYLOAD.append("4745540d0a")
DIRECTION.append("s2c")

#*** Metadata for whole flow:
FLOW_IP_CLIENT = '10.0.2.15'
FLOW_IP_SERVER = '10.0.2.2'

# Unidirectional flow values:
# Flow 1:
UNIDIR_SRC_IP.append('10.0.2.15')
UNIDIR_SRC_PORT.append('0')
UNIDIR_DST_IP.append('10.0.2.2')
UNIDIR_DST_PORT.append('0')
UNIDIR_PROTO.append('1')
UNIDIR_PKTTOTALCOUNT.append('2')
UNIDIR_OCTETTOTALCOUNT.append('168')
UNIDIR_MIN_PS.append('84')
UNIDIR_MAX_PS.append('84')
UNIDIR_AVG_PS.append('84')
UNIDIR_STD_DEV_PS.append('0')
UNIDIR_FLOWSTART.append('1538640052.580081')
UNIDIR_FLOWEND.append('1538640053.598205')
UNIDIR_FLOWDURATION.append('1.01812')
UNIDIR_MIN_PIAT.append('1.01812005')
UNIDIR_MAX_PIAT.append('1.01812005')
UNIDIR_AVG_PIAT.append('1.01812005')
UNIDIR_STD_DEV_PIAT.append('0')
# Flow 2:
UNIDIR_SRC_IP.append('10.0.2.2')
UNIDIR_SRC_PORT.append('0')
UNIDIR_DST_IP.append('10.0.2.15')
UNIDIR_DST_PORT.append('0')
UNIDIR_PROTO.append('1')
UNIDIR_PKTTOTALCOUNT.append('2')
UNIDIR_OCTETTOTALCOUNT.append('168')
UNIDIR_MIN_PS.append('84')
UNIDIR_MAX_PS.append('84')
UNIDIR_AVG_PS.append('84')
UNIDIR_STD_DEV_PS.append('0')
UNIDIR_FLOWSTART.append('1538640052.580269')
UNIDIR_FLOWEND.append('1538640053.598428')
UNIDIR_FLOWDURATION.append('1.018159')
UNIDIR_MIN_PIAT.append('1.018159866')
UNIDIR_MAX_PIAT.append('1.018159866')
UNIDIR_AVG_PIAT.append('1.018159866')
UNIDIR_STD_DEV_PIAT.append('0')
# Bidirectional Combined Flow 1:
BIDIR_SRC_IP.append('10.0.2.15')
BIDIR_SRC_PORT.append('0')
BIDIR_DST_IP.append('10.0.2.2')
BIDIR_DST_PORT.append('0')
BIDIR_PROTO.append('1')
BIDIR_PKTTOTALCOUNT.append('4')
BIDIR_OCTETTOTALCOUNT.append('336')
BIDIR_MIN_PS.append('84')
BIDIR_MAX_PS.append('84')
BIDIR_AVG_PS.append('84')
BIDIR_STD_DEV_PS.append('0')
BIDIR_FLOWSTART.append('1538640052.580081')
BIDIR_FLOWEND.append('1538640053.598428')
BIDIR_FLOWDURATION.append('1.018339')
BIDIR_MIN_PIAT.append('0.000180006')
BIDIR_MAX_PIAT.append('1.017940044')
BIDIR_AVG_PIAT.append('0.339446624')
BIDIR_STD_DEV_PIAT.append('0.479767299')
BIDIR_F_PKTTOTALCOUNT.append('2')
BIDIR_F_OCTETTOTALCOUNT.append('168')
BIDIR_F_MIN_PS.append('84')
BIDIR_F_MAX_PS.append('84')
BIDIR_F_AVG_PS.append('84')
BIDIR_F_STD_DEV_PS.append('0')
BIDIR_F_FLOWSTART.append('1538640052.580081')
BIDIR_F_FLOWEND.append('1538640053.598205')
BIDIR_F_FLOWDURATION.append('1.018120')
BIDIR_F_MIN_PIAT.append('1.01812005')
BIDIR_F_MAX_PIAT.append('1.01812005')
BIDIR_F_AVG_PIAT.append('1.01812005')
BIDIR_F_STD_DEV_PIAT.append('0')
BIDIR_B_PKTTOTALCOUNT.append('2')
BIDIR_B_OCTETTOTALCOUNT.append('168')
BIDIR_B_MIN_PS.append('84')
BIDIR_B_MAX_PS.append('84')
BIDIR_B_AVG_PS.append('84')
BIDIR_B_STD_DEV_PS.append('0')
BIDIR_B_FLOWSTART.append('1538640052.580269')
BIDIR_B_FLOWEND.append('1538640053.598428')
BIDIR_B_FLOWDURATION.append('1.018159')
BIDIR_B_MIN_PIAT.append('1.018159866')
BIDIR_B_MAX_PIAT.append('1.018159866')
BIDIR_B_AVG_PIAT.append('1.018159866')
BIDIR_B_STD_DEV_PIAT.append('0')





