flowRecorder
============

Use flowRecorder to turn packets into flow records.
The tool can work in two modes:

1. Live packet capture from a NIC
2. Parsing packets from a PCAP file.

The program can take a number of arguments:

-d, --direction <u,b>  sets whether the packets will be organised into flows in uni- or bidirection

-i, --interface interface_name  sets the networking interface card from which the packets will be sniffed

-f, --file file_name  sets the name of the PCAP file

-o, --out file_name  sets the name of the CSV file into which the results will be saved


**Examples:**

1. To read in a PCAP file and process the packets into flows
in one direction, and save the results into a CSV file the following
command can be used:

::

       python ~/flowRecorder/flowRecorder/flowRecorder.py -d u -f p.pcap -o results.csv

2. To start capturing the packets from a NIC (en0) and organize them 
into flow records in bidirection, the following command can be used:

::

       sudo python ~/flowRecorder/flowRecorder/flowRecorder.py -d b -i en0 -o results.csv

Notes
=====
* Only creates flows for IP packets
* Uses 5-tuple of ip_src, ip_dst, proto, src_port, dst_port flow keys as
  common properties to identify TCP/UDP flows
* Uses 3-tuple of ip_src, ip_dst, proto flow keys as
  common properties to identify non-TCP/UDP flows
* Packet lengths are calculated on sizes of IP packets (i.e. ignores
  Ethernet framing size)
* Flows are considered to have expired if more than a threshold of time
  has passed since previous packet and when this occurs further packets
  will be considered as a new flow and the previous packets moved to the
  flow archive. Threshold for flow expiration is in the config file.

Dependencies
============

flowRecorder depends on the following libraries:

-  dpkt
-  pcapy
-  hashlib
-  numpy

These can be installed with (Python 2.x):

::

   sudo apt-get update
   sudo apt-get install libpcap-dev

   sudo apt install python-pip python-pytest python-yaml

   pip install dpkt pcapy numpy

These can be installed with (Python 3.x):

::

   sudo apt-get update
   sudo apt-get install libpcap-dev

   sudo apt install python3-pip python-pytest3 python-yaml

   pip3 install dpkt pcapy numpy


Testing
=======

Run python 2.x self tests with:

::

    cd ~/flowRecorder/tests/; py.test

Run python 3.x self tests with:

::

    cd ~/flowRecorder/tests/; py.test-3

Known issues
============

The program is not optimized for processing large PCAP files. For
example, processsing 500K packets takes approximately 40 minutes. The
processing time mainly depends on the selected directionality and the
computing resources.

**The tool is under testing. Please report any issues/bugs to the
developers.**
