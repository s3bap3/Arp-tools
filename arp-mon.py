#!/usr/bin/env python
 
#!/usr/bin/env python

def missing_library(string):
	print "\nMissing %s Library\n" %(string)
	sys.exit(1)
 
try:
	import sys
except: 
	missing_library("sys")
try:
	import signal
except: 
	missing_library("signal")
try:
	from scapy.all import *
except: 
	missing_library("scapy")
try:
	import netaddr
except: 
	missing_library("netaddr")	
 
def signal_handler(signal, frame):
	print('=================')
	print('Execution aborted')
	print('=================')
	os.system("kill -9 " + str(os.getpid()))
	sys.exit(1)

def usage():
	if len(sys.argv) != 3:
		print "\nUsage: "
		print "\tpython arp-mon.py -i <Interface>\n"
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
		print "\n[*] Sniffing for ARP Requests and Responses"
		print "\nPacket details"
		sniff(iface=parameters["-i"], filter="arp", prn=monitor)
	except:
		print "Unknown parameters"
		sys.exit(1)
