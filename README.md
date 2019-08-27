# lte_s1ap_parser
This script parses the pcap s1ap messages

Env:
Ubuntu 18.04

Packages:
virtualenv
tshark

run: apt install -y virutalenv pyshark

Clone the repository and run,

virtualenv lte_s1ap_parser
cd lte_s1ap_latest
run ./install.sh --> this installs all required packages

run program,
python live_parser.py <interface_name>


NOTE: pyshark requires python >=3.5 
