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
This module provides functions for hashing packets and flows to
unique identifiers
"""

# For hashing flow 5-tuples:
import hashlib

def hash_b6(flow_6_tuple):
    """
    Generate a predictable bidirectional flow_hash for a TCP or UDP
    6-tuple that includes timestamp for flow start. The hash is the
    same no matter which direction the traffic is travelling for all
    packets that are part of that flow.

    Pass this function a 6-tuple:
    (ip_src, ip_dst, ip_proto, tp_src, tp_dst, timestamp)
    """
    ip_A = flow_6_tuple[0]
    ip_B = flow_6_tuple[1]
    proto = int(flow_6_tuple[2])
    tp_src = flow_6_tuple[3]
    tp_dst = flow_6_tuple[4]
    timestamp = flow_6_tuple[5]
    
    # Assign arbitrary consistent direction:
    if ip_A > ip_B:
        direction = 1
    elif ip_B > ip_A:
        direction = 2
    elif tp_src > tp_dst:
        direction = 1
    elif tp_dst > tp_src:
        direction = 2
    else:
        direction = 1

    # Calculate hash based on direction:
    if direction == 1:
        flow_tuple = (ip_A, ip_B, proto, tp_src, tp_dst, timestamp)
    else:
        # Transpose IPs and port numbers for reverse packets:
        flow_tuple = (ip_B, ip_A, proto, tp_dst, tp_src, timestamp)
    return hash_tuple(flow_tuple)

def hash_b5(flow_5_tuple):
    """
    Generate a predictable bidirectional flow_hash for a TCP or UDP
    5-tuple. The hash is the same no matter which direction the
    traffic is travelling for all packets that are part of that flow.

    Pass this function a 5-tuple:
    (ip_src, ip_dst, ip_proto, tp_src, tp_dst)
    """
    ip_A = flow_5_tuple[0]
    ip_B = flow_5_tuple[1]
    proto = int(flow_5_tuple[2])
    tp_src = flow_5_tuple[3]
    tp_dst = flow_5_tuple[4]
    
    # Assign arbitrary consistent direction:
    if ip_A > ip_B:
        direction = 1
    elif ip_B > ip_A:
        direction = 2
    elif tp_src > tp_dst:
        direction = 1
    elif tp_dst > tp_src:
        direction = 2
    else:
        direction = 1

    # Calculate hash based on direction:
    if direction == 1:
        flow_tuple = (ip_A, ip_B, proto, tp_src, tp_dst)
    else:
        # Transpose IPs and port numbers for reverse packets:
        flow_tuple = (ip_B, ip_A, proto, tp_dst, tp_src)
    return hash_tuple(flow_tuple)

def hash_b4(flow_4_tuple):
    """
    Generate a predictable bidirectional flow_hash for a TCP or UDP
    4-tuple that includes timestamp for flow start. The hash is the
    same no matter which direction the traffic is travelling for all
    packets that are part of that flow.

    Pass this function a 4-tuple:
    (ip_src, ip_dst, ip_proto, timestamp)
    """
    ip_A = flow_4_tuple[0]
    ip_B = flow_4_tuple[1]
    proto = int(flow_4_tuple[2])
    timestamp = flow_4_tuple[3]
    
    # Assign arbitrary consistent direction:
    if ip_A > ip_B:
        direction = 1
    elif ip_B > ip_A:
        direction = 2
    else:
        direction = 1

    # Calculate hash based on direction:
    if direction == 1:
        flow_tuple = (ip_A, ip_B, proto, timestamp)
    else:
        # Transpose IPs for reverse packets:
        flow_tuple = (ip_B, ip_A, proto, timestamp)
    return hash_tuple(flow_tuple)

def hash_b3(flow_3_tuple):
    """
    Generate a predictable bidirectional flow_hash for a TCP or UDP
    3-tuple. The hash is the same no matter which direction the
    traffic is travelling for all packets that are part of that flow.

    Pass this function a 3-tuple:
    (ip_src, ip_dst, ip_proto)
    """
    ip_A = flow_3_tuple[0]
    ip_B = flow_3_tuple[1]
    proto = int(flow_3_tuple[2])
    
    # Assign arbitrary consistent direction:
    if ip_A > ip_B:
        direction = 1
    elif ip_B > ip_A:
        direction = 2
    else:
        direction = 1

    # Calculate hash based on direction:
    if direction == 1:
        flow_tuple = (ip_A, ip_B, proto)
    else:
        # Transpose IPs for reverse packets:
        flow_tuple = (ip_B, ip_A, proto)
    return hash_tuple(flow_tuple)

def hash_u6(flow_6_tuple):
    """
    Generate a unidirectional flow_hash for a TCP or UDP
    6-tuple.

    Pass this function a 6-tuple:
    (ip_src, ip_dst, ip_proto, tp_src, tp_dst, timestamp)
    """
    ip_A = flow_6_tuple[0]
    ip_B = flow_6_tuple[1]
    proto = int(flow_6_tuple[2])
    tp_src = flow_6_tuple[3]
    tp_dst = flow_6_tuple[4]
    timestamp = flow_6_tuple[5]
    flow_tuple = (ip_A, ip_B, proto, tp_src, tp_dst, timestamp)
    return hash_tuple(flow_tuple)

def hash_u5(flow_5_tuple):
    """
    Generate a unidirectional flow_hash for a TCP or UDP
    5-tuple.

    Pass this function a 5-tuple:
    (ip_src, ip_dst, ip_proto, tp_src, tp_dst)
    """
    ip_A = flow_5_tuple[0]
    ip_B = flow_5_tuple[1]
    proto = int(flow_5_tuple[2])
    tp_src = flow_5_tuple[3]
    tp_dst = flow_5_tuple[4]
    flow_tuple = (ip_A, ip_B, proto, tp_src, tp_dst)
    return hash_tuple(flow_tuple)

def hash_u4(flow_4_tuple):
    """
    Generate a unidirectional flow_hash for a TCP or UDP
    4-tuple.

    Pass this function a 4-tuple:
    (ip_src, ip_dst, ip_proto, timestamp)
    """
    ip_A = flow_4_tuple[0]
    ip_B = flow_4_tuple[1]
    proto = int(flow_4_tuple[2])
    timestamp = flow_4_tuple[3]
    flow_tuple = (ip_A, ip_B, proto, timestamp)
    return hash_tuple(flow_tuple)

def hash_u3(flow_3_tuple):
    """
    Generate a unidirectional flow_hash for a TCP or UDP
    3-tuple.

    Pass this function a 3-tuple:
    (ip_src, ip_dst, ip_proto)
    """
    ip_A = flow_3_tuple[0]
    ip_B = flow_3_tuple[1]
    proto = int(flow_3_tuple[2])
    flow_tuple = (ip_A, ip_B, proto)
    return hash_tuple(flow_tuple)

def hash_tuple(hash_tuple):
    """
    Simple function to hash a tuple with MD5.
    Returns a hash value for the tuple
    """
    hash_result = hashlib.md5()
    tuple_as_string = str(hash_tuple)
    hash_result.update(tuple_as_string.encode('utf-8'))
    return hash_result.hexdigest()
