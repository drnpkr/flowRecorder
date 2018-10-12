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

"""
flowRecorder - a packet parser tool by Adrian Pekar

flowRecorder creates metadata about flows from packets,
either from live capture or from capture file
"""

import time

# Import sys and getopt for command line argument parsing:
import sys
import getopt

# Logging:
import logging

# Colorise the logs:
import coloredlogs

# For live packet capture:
import pcapy

# Import dpkt for packet parsing:
import dpkt

# flowRecorder project imports:
import config
import flows

# flowRecorder, for logging configuration:
from baseclass import BaseClass

VERSION = "0.2.0"

# Configure Logging:
logger = logging.getLogger(__name__)
coloredlogs.install(level='DEBUG', logger=logger,
                    fmt="%(asctime)s %(module)s[%(process)d] %(funcName)s " +
                    "%(levelname)s %(message)s",
                    datefmt='%H:%M:%S')

class FlowRecorder(BaseClass):
    """
    This class provides core methods for flowRecorder
    """
    def __init__(self, CLI_arguments):
        """
        Initialise the FlowRecorder class
        """
        # Instantiate config class which imports configuration file
        # config.yaml and provides access to keys/values:
        self.config = config.Config()

        # Now set config module to log properly:
        self.config.inherit_logging(self.config)

        # Set up Logging with inherited base class method:
        self.configure_logging(__name__, "flowRecorder_logging_level_s",
                                       "flowRecorder_logging_level_c")

        # Parse command line parameters:
        self.input_filename = ""
        self.interface = ""
        self.output_filename = ""
        # Direction parameter recorded in mode:
        self.mode = ""
        try:
            opts, args = getopt.getopt(CLI_arguments, "d:f:hi:o:v",
                                    ["direction=",
                                    "file=",
                                    "help",
                                    "interface=",
                                    "out=",
                                    "version"])
        except getopt.GetoptError as err:
            logger.critical('flowRecorder: Error with options: %s', err)
            print_help()
            sys.exit(2)
        for opt, arg in opts:
            if opt in ("-d", "--direction"):
                self.mode = arg
            elif opt in ("-f", "--file"):
                self.input_filename = arg
            elif opt in ("-h", "--help"):
                print_help()
                sys.exit()
            elif opt in ("-i", "--interface"):
                self.interface = arg
            elif opt in ("-o", "--out"):
                self.output_filename = arg
            elif opt in ("-v", "--version"):
                print("\n\n flowRecorder version", VERSION, "\n")
                sys.exit()
            else:
                print("ERROR: unhandled argument", opt)
                sys.exit()

        # Assume bidirectional if not specified:
        if not self.mode:
            logger.info("Direction not specified. Defaulting to bidirectional")
            self.mode = 'b'
        else:
            # Sanity check direction input:
            if self.mode != 'b' and  self.mode != 'u':
                logger.critical("Invalid direction %s", self.mode)
                sys.exit()

        # Must have a file OR interface specified:
        if self.input_filename and self.interface:
            logger.critical("file and interface specified. Choose only one")
            sys.exit()
        if not self.input_filename and not self.interface:
            logger.critical("An input file or interface must be specified")
            sys.exit()

        # Must have an output file specified:
        if not self.output_filename:
            logger.critical("Output filename not set")
            sys.exit()

        # Instantiate Flows Class:
        self.flows = flows.Flows(self.config, self.mode)

    def run(self):
        """
        Run flowRecorder
        """
        self.logger.info("Starting flowRecorder")
        time0 = time.time()
        if self.input_filename:
            # File Mode
            self._run_file(time0)
        else:
            # Live Packet Capture Mode
            self._run_live()
        # Write results to file:
        time3 = time.time()
        self.flows.write(self.output_filename)
        time4 = time.time()
        self.logger.info("Wrote results in %s seconds", time4 - time3)
        self.flows.stats()
        time5 = time.time()
        self.logger.info("Finished, total time %s seconds", time5 - time0)

    def _run_file(self, time0):
        """
        Read in packet capture file
        """
        # Check if incremental save is enabled
        incremental_save_enabled = self.config.get_value("incremental_save_enabled")
        #
        self.logger.info("Opening PCAP file=%s", self.input_filename)
        # Open the PCAP file:
        with open(self.input_filename, 'rb') as pcap_file:
            pcap_file_handle = dpkt.pcap.Reader(pcap_file)
            time1 = time.time()
            self.logger.info("Opened PCAP in %s seconds", time1 - time0)
            # If incremental save is disabled
            if incremental_save_enabled == False:
                try:
                    # Process PCAP packets into flows:
                    self.flows.ingest_pcap(pcap_file_handle)
                except (KeyboardInterrupt, SystemExit):
                    self.logger.info("SIGINT (Ctrl-c) detected.")
            # If incremental save is enabled
            else:
                try:
                    # Process PCAP packets into flows:
                    self.flows.ingest_pcap_inc_save(pcap_file_handle, self.output_filename)
                except (KeyboardInterrupt, SystemExit):
                    self.logger.info("SIGINT (Ctrl-c) detected.")
            time2 = time.time()
            self.logger.info("Processed in %s seconds", time2 - time1)

    def _run_live(self):
        """
        Run live packet capture
        """
        self.logger.info("Running live packet capture")
        # Retrieve parameters from config:
        maxlen = self.config.get_value("maxlen")
        promiscuous = self.config.get_value("promiscuous")
        read_timeout = self.config.get_value("read_timeout")
        # Instantiate sniffer:
        sniffer = pcapy.open_live(self.interface, maxlen, promiscuous, read_timeout)
        # Start sniffing:
        sniffing = True
        while sniffing:
            self.logger.info("Start sniffing on interface %s", self.interface)
            self.logger.info("Sniffing can be aborted via pressing Ctrl-c")
            try:
                sniffer.loop(0, self.flows.ingest_packet)
            except (KeyboardInterrupt, SystemExit):
                self.logger.info("SIGINT (Ctrl-c) detected.")
                sniffing = False

def print_help():
    """
    Print out the help instructions
    """
    print("""
flowRecorder
-------

flowRecorder parses packets and generates flow records. It has two modes:

1) Live packet capture from a NIC
     OR
2) Parsing packets from a PCAP file.

Example Usage:

To read in a PCAP file and process the packets into flows in one direction,
and save the results into a CSV file the following command can be used:

  python3 flowRecorder.py -d u -f p.pcap -o results.csv

To start caputring the packets from a NIC (en0) and organize them into flow
records in bidirection, the following command can be used:

  sudo python3 flowRecorder.py -d b -i en0 -o results.csv

Options:
 -d  --direction     Unidirectional (u) or Bidirectional (b) flows
                     (default is b)
 -f  --file          Input PCAP filename
 -h  --help          Display this help and exit
 -i  --interface     Name of interface (NIC) to capture from
 -o  --out           Output filename for flow results CSV export
 -v  --version       Show version information and exit
""")

if __name__ == "__main__":
    # Instantiate the FlowRecorder class:
    flowRecorder = FlowRecorder(sys.argv[1:])
    # Start flowRecorder with command line arguments from position 1:
    flowRecorder.run()
