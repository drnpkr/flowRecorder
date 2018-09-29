"""
flowRecorder system tests
"""

# Handle tests being in different directory branch to app code:
import sys
import struct

# For file handling:
import os
import csv

# For system calls to run commands:
import subprocess

# flowRecorder imports:
import config

# test packet imports:
import http1 as pkts

sys.path.insert(0, '../flowRecorder')

import logging

# Instantiate Config class:
config = config.Config()

logger = logging.getLogger(__name__)

FLOWRECORDER = "../flowRecorder/flowRecorder.py"
TEST_PCAP_HTTP1 = 'packet_captures/http1.pcap'
RESULT_FILE = 'temp/temp_test_output.csv'
UNIDIR = 'u'
BIDIR = 'b'

#======================== data.py Unit Tests ============================

def test_http1_unidir():
    """
    Test output for unidirectional processing of http1.pcap file
    """
    # System call to remove old result file if exists:
    if os.path.isfile(RESULT_FILE): 
        logger.info("deleting RESULT_FILE=%s", RESULT_FILE)
        os.remove(RESULT_FILE)

    # Run flowRecorder to generate output file:
    try:
        result = subprocess.check_output(["python", FLOWRECORDER,
                        "-f" , TEST_PCAP_HTTP1,
                        "-d", UNIDIR,
                        "-o", RESULT_FILE])
        logger.info("flowRecorder result is %s", result)
    except subprocess.CalledProcessError, e:
        logger.critical("Stdout output: %s", e.output)

    # Check results file exists:
    assert os.path.isfile(RESULT_FILE)

    # Read in results file:
    with open(RESULT_FILE) as csv_file:
        csv_reader = list(csv.DictReader(csv_file))
        assert len(csv_reader) == 2
        assert csv_reader[0]['src_ip'] == pkts.UNIDIR_SRC_IP[0]
        assert csv_reader[0]['src_port'] == pkts.UNIDIR_SRC_PORT[0]
        assert csv_reader[0]['dst_ip'] == pkts.UNIDIR_DST_IP[0]
        assert csv_reader[0]['dst_port'] == pkts.UNIDIR_DST_PORT[0]
        assert csv_reader[0]['proto'] == pkts.UNIDIR_PROTO[0]

#        line_count = 0
#        for row in csv_reader:
#            if line_count == 0:
#                headers = row
#                for item in row:
#                    print item, ","
#                line_count += 1
#            else:
#                for item in row:
#                    print item, ","
#                #logger.debug("row is", row)
#                line_count += 1

    # Validate contents of results file:
    # TBD
    assert 1 == 0


