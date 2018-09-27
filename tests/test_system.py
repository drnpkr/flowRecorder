"""
flowRecorder system tests
"""

# Handle tests being in different directory branch to app code:
import sys
import struct

# For file handling:
import os

# For system calls to run commands:
import subprocess

# flowRecorder imports:
import config

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
        print subprocess.check_output(["python", FLOWRECORDER,
                        "-f" , TEST_PCAP_HTTP1,
                        "-d", UNIDIR,
                        "-o", RESULT_FILE])
    except subprocess.CalledProcessError, e:
        print "Stdout output:\n", e.output

    # Check results file exists:
    assert os.path.isfile(RESULT_FILE)

    # Validate contents of results file:
    # TBD
    assert 1 == 0


