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
# MARGIN is used to allow for small differences in results due to 
# use of float type, rounding etc:
MARGIN = 0.0001

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

    # Call helper function to validate the results file values:
    validate_results_file_unidir(RESULT_FILE, pkts, 2)

    # Temp halt while working on code:
    assert 1 == 0

#================= HELPER FUNCTIONS ===========================================

def validate_results_file_unidir(filename, ground_truth, results_length):
    """
    Validate a unidirectional results file against ground truth values from
    a separate ground truth object
    """
    # Read in results file:
    with open(filename) as csv_file:
        csv_reader = list(csv.DictReader(csv_file))
        # Validate results file has correct number of rows (excl header):
        assert len(csv_reader) == results_length
        row_number = 0
        # Iterate through rows of result data, checking values:
        for row in csv_reader:
            assert row['src_ip'] == ground_truth.UNIDIR_SRC_IP[row_number]
            assert row['src_port'] == ground_truth.UNIDIR_SRC_PORT[row_number]
            assert row['dst_ip'] == ground_truth.UNIDIR_DST_IP[row_number]
            assert row['dst_port'] == ground_truth.UNIDIR_DST_PORT[row_number]
            assert row['proto'] == ground_truth.UNIDIR_PROTO[row_number]
            assert row['min_ps'] == ground_truth.UNIDIR_MIN_PS[row_number]
            assert row['max_ps'] == ground_truth.UNIDIR_MAX_PS[row_number]
            # Average needs leeway to cope with floats/division/rounding etc:
            assert float(row['avg_ps']) < float(ground_truth.UNIDIR_AVG_PS[row_number]) + MARGIN
            assert float(row['avg_ps']) > float(ground_truth.UNIDIR_AVG_PS[row_number]) - MARGIN
            # Std Dev needs leeway to cope with floats/division/rounding etc:
            assert float(row['std_dev_ps']) < float(ground_truth.UNIDIR_STD_DEV_PS[row_number]) + MARGIN
            assert float(row['std_dev_ps']) > float(ground_truth.UNIDIR_STD_DEV_PS[row_number]) - MARGIN
            assert row['flowStart'] == ground_truth.UNIDIR_FLOWSTART[row_number]
            assert row['flowEnd'] == ground_truth.UNIDIR_FLOWEND[row_number]
            # Flow Duration needs leeway to cope with floats/division/rounding etc:
            assert float(row['flowDuration']) < float(ground_truth.UNIDIR_FLOWDURATION[row_number]) + MARGIN
            assert float(row['flowDuration']) > float(ground_truth.UNIDIR_FLOWDURATION[row_number]) - MARGIN
            row_number += 1
