#!/usr/bin/env python
 
import sys
import signal
from scapy.all import *
 
def signal_handler(signal, frame):
	print('=================')
	print('Execution aborted')
	print('=================')
	os.system("kill -9 " + str(os.getpid()))
	sys.exit(1)

def usage():
	if len(sys.argv) != 3:
		print "\n\tUsage: python arp-mon.py -i <Interface>\n"
		sys.exit(1)

def monitor (packet):
	try:
		print packet[0].summary()
	except:
		print "Missing scapy library"

def check_root():
    if not os.geteuid() == 0:
        print "Run as root."
        exit(1)

if __name__ == "__main__":
	signal.signal(signal.SIGINT, signal_handler)
	usage()
	check_root()
	parameters ={sys.argv[1]:sys.argv[2]}
	try:
		sniff(iface=parameters["-i"], filter="arp", prn=monitor)
	except:
		print "Unknown parameters"
		sys.exit(1)
