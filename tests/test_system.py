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
import http1 as groundtruth_http1
import groundtruth_PING1

sys.path.insert(0, '../flowRecorder')

import logging

# Instantiate Config class:
config = config.Config()

logger = logging.getLogger(__name__)

FLOWRECORDER = "../flowRecorder/flowRecorder.py"
TEST_PCAP_HTTP1 = 'packet_captures/http1.pcap'
TEST_PCAP_PING1 = 'packet_captures/PING1.pcap'
RESULT_FILE = 'temp/temp_test_output.csv'
UNIDIR = 'u'
BIDIR = 'b'
# MARGIN is used to allow for small differences in results due to 
# use of float type, rounding etc. Applies on both sides of result:
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
    except subprocess.CalledProcessError as e:
        logger.critical("Stdout output: %s", e.output)

    # Check results file exists:
    assert os.path.isfile(RESULT_FILE)

    # Call helper function to validate the results file values:
    validate_results_file_unidir(RESULT_FILE, groundtruth_http1, 2)

def test_http1_bidir():
    """
    Test output for bidirectional processing of http1.pcap file
    """
    # System call to remove old result file if exists:
    if os.path.isfile(RESULT_FILE): 
        logger.info("deleting RESULT_FILE=%s", RESULT_FILE)
        os.remove(RESULT_FILE)

    # Run flowRecorder to generate output file:
    try:
        result = subprocess.check_output(["python", FLOWRECORDER,
                        "-f" , TEST_PCAP_HTTP1,
                        "-d", BIDIR,
                        "-o", RESULT_FILE])
        logger.info("flowRecorder result is %s", result)
    except subprocess.CalledProcessError as e:
        logger.critical("Stdout output: %s", e.output)

    # Check results file exists:
    assert os.path.isfile(RESULT_FILE)

    # Call helper function to validate the results file values:
    validate_results_file_bidir(RESULT_FILE, groundtruth_http1, 1)

def test_PING1_unidir():
    """
    Test output for unidirectional processing of PING1.pcap file
    """
    # System call to remove old result file if exists:
    if os.path.isfile(RESULT_FILE): 
        logger.info("deleting RESULT_FILE=%s", RESULT_FILE)
        os.remove(RESULT_FILE)

    # Run flowRecorder to generate output file:
    try:
        result = subprocess.check_output(["python", FLOWRECORDER,
                        "-f" , TEST_PCAP_PING1,
                        "-d", UNIDIR,
                        "-o", RESULT_FILE])
        logger.info("flowRecorder result is %s", result)
    except subprocess.CalledProcessError as e:
        logger.critical("Stdout output: %s", e.output)

    # Check results file exists:
    assert os.path.isfile(RESULT_FILE)

    # Call helper function to validate the results file values:
    validate_results_file_unidir(RESULT_FILE, groundtruth_PING1, 2)

def test_PING1_bidir():
    """
    Test output for bidirectional processing of PING1.pcap file
    """
    # System call to remove old result file if exists:
    if os.path.isfile(RESULT_FILE): 
        logger.info("deleting RESULT_FILE=%s", RESULT_FILE)
        os.remove(RESULT_FILE)

    # Run flowRecorder to generate output file:
    try:
        result = subprocess.check_output(["python", FLOWRECORDER,
                        "-f" , TEST_PCAP_PING1,
                        "-d", BIDIR,
                        "-o", RESULT_FILE])
        logger.info("flowRecorder result is %s", result)
    except subprocess.CalledProcessError as e:
        logger.critical("Stdout output: %s", e.output)

    # Check results file exists:
    assert os.path.isfile(RESULT_FILE)

    # Call helper function to validate the results file values:
    validate_results_file_bidir(RESULT_FILE, groundtruth_PING1, 1)

#================= HELPER FUNCTIONS ===========================================

def validate_results_file_unidir(filename, ground_truth, results_length):
    """
    Validate a unidirectional results file against ground truth values from
    a separate ground truth object
    """
    logger.debug("Validating unidir results filename=%s against %s", filename, ground_truth.name)
    # Read in results file:
    with open(filename) as csv_file:
        csv_reader = list(csv.DictReader(csv_file))
        # Validate results file has correct number of rows (excl header):
        assert len(csv_reader) == results_length
        row_number = 0
        # Iterate through rows of result data, checking values:
        for row in csv_reader:
            logger.debug("Validating row=%s", row_number)
            assert row['src_ip'] == ground_truth.UNIDIR_SRC_IP[row_number]
            assert row['src_port'] == ground_truth.UNIDIR_SRC_PORT[row_number]
            assert row['dst_ip'] == ground_truth.UNIDIR_DST_IP[row_number]
            assert row['dst_port'] == ground_truth.UNIDIR_DST_PORT[row_number]
            assert row['proto'] == ground_truth.UNIDIR_PROTO[row_number]
            assert row['pktTotalCount'] == ground_truth.UNIDIR_PKTTOTALCOUNT[row_number]
            assert row['octetTotalCount'] == ground_truth.UNIDIR_OCTETTOTALCOUNT[row_number]
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
            # Inter-packet arrival times need leeway to cope with floats/division/rounding etc:
            assert float(row['min_piat']) < float(ground_truth.UNIDIR_MIN_PIAT[row_number]) + MARGIN
            assert float(row['min_piat']) > float(ground_truth.UNIDIR_MIN_PIAT[row_number]) - MARGIN
            assert float(row['max_piat']) < float(ground_truth.UNIDIR_MAX_PIAT[row_number]) + MARGIN
            assert float(row['max_piat']) > float(ground_truth.UNIDIR_MAX_PIAT[row_number]) - MARGIN
            assert float(row['avg_piat']) < float(ground_truth.UNIDIR_AVG_PIAT[row_number]) + MARGIN
            assert float(row['avg_piat']) > float(ground_truth.UNIDIR_AVG_PIAT[row_number]) - MARGIN
            assert float(row['std_dev_piat']) < float(ground_truth.UNIDIR_STD_DEV_PIAT[row_number]) + MARGIN
            assert float(row['std_dev_piat']) > float(ground_truth.UNIDIR_STD_DEV_PIAT[row_number]) - MARGIN
            row_number += 1

def validate_results_file_bidir(filename, ground_truth, results_length):
    """
    Validate a bidirectional results file against ground truth values from
    a separate ground truth object
    """
    logger.debug("Validating bidir results filename=%s against %s", filename, ground_truth.name)
    # Read in results file:
    with open(filename) as csv_file:
        csv_reader = list(csv.DictReader(csv_file))
        # Validate results file has correct number of rows (excl header):
        assert len(csv_reader) == results_length
        row_number = 0
        # Iterate through rows of result data, checking values:
        for row in csv_reader:
            logger.debug("Validating row=%s", row_number)
            # Combined values:
            assert row['src_ip'] == ground_truth.BIDIR_SRC_IP[row_number]
            assert row['src_port'] == ground_truth.BIDIR_SRC_PORT[row_number]
            assert row['dst_ip'] == ground_truth.BIDIR_DST_IP[row_number]
            assert row['dst_port'] == ground_truth.BIDIR_DST_PORT[row_number]
            assert row['proto'] == ground_truth.BIDIR_PROTO[row_number]
            assert row['min_ps'] == ground_truth.BIDIR_MIN_PS[row_number]
            assert row['max_ps'] == ground_truth.BIDIR_MAX_PS[row_number]
            # Average needs leeway to cope with floats/division/rounding etc:
            assert float(row['avg_ps']) < float(ground_truth.BIDIR_AVG_PS[row_number]) + MARGIN
            assert float(row['avg_ps']) > float(ground_truth.BIDIR_AVG_PS[row_number]) - MARGIN
            # Std Dev needs leeway to cope with floats/division/rounding etc:
            assert float(row['std_dev_ps']) < float(ground_truth.BIDIR_STD_DEV_PS[row_number]) + MARGIN
            assert float(row['std_dev_ps']) > float(ground_truth.BIDIR_STD_DEV_PS[row_number]) - MARGIN
            assert row['flowStart'] == ground_truth.BIDIR_FLOWSTART[row_number]
            assert row['flowEnd'] == ground_truth.BIDIR_FLOWEND[row_number]
            # Flow Duration needs leeway to cope with floats/division/rounding etc:
            assert float(row['flowDuration']) < float(ground_truth.BIDIR_FLOWDURATION[row_number]) + MARGIN
            assert float(row['flowDuration']) > float(ground_truth.BIDIR_FLOWDURATION[row_number]) - MARGIN
            # Inter-packet arrival times need leeway to cope with floats/division/rounding etc:
            assert float(row['min_piat']) < float(ground_truth.BIDIR_MIN_PIAT[row_number]) + MARGIN
            assert float(row['min_piat']) > float(ground_truth.BIDIR_MIN_PIAT[row_number]) - MARGIN
            assert float(row['max_piat']) < float(ground_truth.BIDIR_MAX_PIAT[row_number]) + MARGIN
            assert float(row['max_piat']) > float(ground_truth.BIDIR_MAX_PIAT[row_number]) - MARGIN
            assert float(row['avg_piat']) < float(ground_truth.BIDIR_AVG_PIAT[row_number]) + MARGIN
            assert float(row['avg_piat']) > float(ground_truth.BIDIR_AVG_PIAT[row_number]) - MARGIN
            assert float(row['std_dev_piat']) < float(ground_truth.BIDIR_STD_DEV_PIAT[row_number]) + MARGIN
            assert float(row['std_dev_piat']) > float(ground_truth.BIDIR_STD_DEV_PIAT[row_number]) - MARGIN
            # Forward values:
            assert row['f_pktTotalCount'] == ground_truth.BIDIR_F_PKTTOTALCOUNT[row_number]
            assert row['f_octetTotalCount'] == ground_truth.BIDIR_F_OCTETTOTALCOUNT[row_number]
            assert row['f_min_ps'] == ground_truth.BIDIR_F_MIN_PS[row_number]
            assert row['f_max_ps'] == ground_truth.BIDIR_F_MAX_PS[row_number]
            # Average needs leeway to cope with floats/division/rounding etc:
            assert float(row['f_avg_ps']) < float(ground_truth.BIDIR_F_AVG_PS[row_number]) + MARGIN
            assert float(row['f_avg_ps']) > float(ground_truth.BIDIR_F_AVG_PS[row_number]) - MARGIN
            # Std Dev needs leeway to cope with floats/division/rounding etc:
            assert float(row['f_std_dev_ps']) < float(ground_truth.BIDIR_F_STD_DEV_PS[row_number]) + MARGIN
            assert float(row['f_std_dev_ps']) > float(ground_truth.BIDIR_F_STD_DEV_PS[row_number]) - MARGIN
            assert row['f_flowStart'] == ground_truth.BIDIR_F_FLOWSTART[row_number]
            assert row['f_flowEnd'] == ground_truth.BIDIR_F_FLOWEND[row_number]
            # Flow Duration needs leeway to cope with floats/division/rounding etc:
            assert float(row['f_flowDuration']) < float(ground_truth.BIDIR_F_FLOWDURATION[row_number]) + MARGIN
            assert float(row['f_flowDuration']) > float(ground_truth.BIDIR_F_FLOWDURATION[row_number]) - MARGIN
            # Inter-packet arrival times need leeway to cope with floats/division/rounding etc:
            assert float(row['f_min_piat']) < float(ground_truth.BIDIR_F_MIN_PIAT[row_number]) + MARGIN
            assert float(row['f_min_piat']) > float(ground_truth.BIDIR_F_MIN_PIAT[row_number]) - MARGIN
            assert float(row['f_max_piat']) < float(ground_truth.BIDIR_F_MAX_PIAT[row_number]) + MARGIN
            assert float(row['f_max_piat']) > float(ground_truth.BIDIR_F_MAX_PIAT[row_number]) - MARGIN
            assert float(row['f_avg_piat']) < float(ground_truth.BIDIR_F_AVG_PIAT[row_number]) + MARGIN
            assert float(row['f_avg_piat']) > float(ground_truth.BIDIR_F_AVG_PIAT[row_number]) - MARGIN
            assert float(row['f_std_dev_piat']) < float(ground_truth.BIDIR_F_STD_DEV_PIAT[row_number]) + MARGIN
            assert float(row['f_std_dev_piat']) > float(ground_truth.BIDIR_F_STD_DEV_PIAT[row_number]) - MARGIN
            # Backward values:
            assert row['b_pktTotalCount'] == ground_truth.BIDIR_B_PKTTOTALCOUNT[row_number]
            assert row['b_octetTotalCount'] == ground_truth.BIDIR_B_OCTETTOTALCOUNT[row_number]
            assert row['b_min_ps'] == ground_truth.BIDIR_B_MIN_PS[row_number]
            assert row['b_max_ps'] == ground_truth.BIDIR_B_MAX_PS[row_number]
            # Average needs leeway to cope with floats/division/rounding etc:
            assert float(row['b_avg_ps']) < float(ground_truth.BIDIR_B_AVG_PS[row_number]) + MARGIN
            assert float(row['b_avg_ps']) > float(ground_truth.BIDIR_B_AVG_PS[row_number]) - MARGIN
            # Std Dev needs leeway to cope with floats/division/rounding etc:
            assert float(row['b_std_dev_ps']) < float(ground_truth.BIDIR_B_STD_DEV_PS[row_number]) + MARGIN
            assert float(row['b_std_dev_ps']) > float(ground_truth.BIDIR_B_STD_DEV_PS[row_number]) - MARGIN
            assert row['b_flowStart'] == ground_truth.BIDIR_B_FLOWSTART[row_number]
            assert row['b_flowEnd'] == ground_truth.BIDIR_B_FLOWEND[row_number]
            # Flow Duration needs leeway to cope with floats/division/rounding etc:
            assert float(row['b_flowDuration']) < float(ground_truth.BIDIR_B_FLOWDURATION[row_number]) + MARGIN
            assert float(row['b_flowDuration']) > float(ground_truth.BIDIR_B_FLOWDURATION[row_number]) - MARGIN
            # Inter-packet arrival times need leeway to cope with floats/division/rounding etc:
            assert float(row['b_min_piat']) < float(ground_truth.BIDIR_B_MIN_PIAT[row_number]) + MARGIN
            assert float(row['b_min_piat']) > float(ground_truth.BIDIR_B_MIN_PIAT[row_number]) - MARGIN
            assert float(row['b_max_piat']) < float(ground_truth.BIDIR_B_MAX_PIAT[row_number]) + MARGIN
            assert float(row['b_max_piat']) > float(ground_truth.BIDIR_B_MAX_PIAT[row_number]) - MARGIN
            assert float(row['b_avg_piat']) < float(ground_truth.BIDIR_B_AVG_PIAT[row_number]) + MARGIN
            assert float(row['b_avg_piat']) > float(ground_truth.BIDIR_B_AVG_PIAT[row_number]) - MARGIN
            assert float(row['b_std_dev_piat']) < float(ground_truth.BIDIR_B_STD_DEV_PIAT[row_number]) + MARGIN
            assert float(row['b_std_dev_piat']) > float(ground_truth.BIDIR_B_STD_DEV_PIAT[row_number]) - MARGIN
            row_number += 1

#f_pktTotalCount,f_octetTotalCount,f_min_ps,f_max_ps,f_avg_ps,f_std_dev_ps,
#f_flowStart,f_flowEnd,f_flowDuration,f_min_piat,f_max_piat,f_avg_piat,f_std_dev_piat,
#b_pktTotalCount,b_octetTotalCount,b_min_ps,b_max_ps,b_avg_ps,vstd_dev_ps,
#b_flowStart,b_flowEnd,b_flowDuration,b_min_piat,b_max_piat,b_avg_piat,b_std_dev_piat
