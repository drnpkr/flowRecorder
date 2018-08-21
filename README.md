# flowRecorder

A packet parser tool. It parses the packets and organize them into flow records. The tool can work in two modes:

  1. Live packet capture from a NIC
  2. Parsing packets from a PCAP file.

The program can take a number of arguments:
    **-d, --dricetion** sets whether the packets will be organised into flows in uni- or bidirection
    **-i, --interface** sets the networking interface card from which the packets will be sniffed
    **-f, --file** sets the name of the PCAP file
    **-o, --out** sets the name of the CSV file into which the results will be saved

Examples:
  1) To read in a PCAP file and process the packets into flows in one direction, and save the results into a CSV file the following command can be used:
```
    python3 flowRecorder.py -d u -f p.pcap -o results.csv
```
  
  2) To start caputring the packets from a NIC and organize them into flow records in bidirection, the following command can be used:
```
    python3 flowRecorder.py -d b -i en0 -o results.csv
```

# Dependencies

flowRecorder depends on the following libraries:

dpkt
pcapy
hashlib
pandas
numpy

# Known issues

The program is not optimized for processing large PCAP files. For example, processsing 500K packets takes approximately 40 minutes. However, the processing time also depends on the directionality and the computing resources.
