flowRecorder
============

A packet parser tool. It parses the packets and organize them into flow
records. The tool can work in two modes:

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

       python3 flowRecorder.py -d u -f p.pcap -o results.csv

2. To start caputring the packets from a NIC (en0) and organize them 
into flow records in bidirection, the following command can be used:

::

       sudo python3 flowRecorder.py -d b -i en0 -o results.csv

Dependencies
============

flowRecorder depends on the following libraries:

-  dpkt
-  pcapy
-  hashlib
-  pandas
-  numpy

These can be installed with:

::

   sudo apt-get update
   sudo apt-get install libpcap-dev

   sudo apt install python3-pip

   pip3 install dpkt pcapy pandas numpy click

Known issues
============

The program is not optimized for processing large PCAP files. For
example, processsing 500K packets takes approximately 40 minutes. The
processing time mainly depends on the selected directionality and the
computing resources.

**The tool is under testing. Please report any issues/bugs to the
developer.**
