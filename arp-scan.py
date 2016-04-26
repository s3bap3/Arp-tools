#!/usr/bin/env python
 
try:
	import sys
	import signal
	from scapy.all import *
	import netaddr
except:
	print "\nMissing Libraries"
	print "Check that the following libraries are available"
	print "\tsys\n\tsignal\n\tscapy\n\tnetaddr"
	sys.exit(1)
 
def signal_handler(signal, frame):
	print('=================')
	print('Execution aborted')
	print('=================')
	os.system("kill -9 " + str(os.getpid()))
	sys.exit(1)

def usage():
	if len(sys.argv) < 3:
		print "\n\tUsage:  python arp-scan.py -i <IP>"
		print "\t\tpython arp-scan.py -n <IP network/netmask>"
		print "\t\tpython arp-scan.py -l <Ips list>"
		print "\t\tpython arp-scan.py -f <File>\n"
		sys.exit(1)
 
def decode_netmask (network):
	try:
		for ip in netaddr.IPNetwork(network):
			scan(str(ip))
	except:
		print "Missing netaddr library"

def decode_file (filename):
	ipsfile = open (filename,"r")
	for line in ipsfile:
		scan(line)

def decode_enumeration (iplist):
	for line in iplist:
		scan(line)

def scan (ip):
	try:
		ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip,hwdst="ff:ff:ff:ff:ff:ff"), timeout=2, verbose=0)
		for pair in ans:
			print pair[1].psrc + "\t\t" + pair[1].hwsrc
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
	if sys.argv[1] == "-n":
		decode_netmask(parameters["-n"])
	elif sys.argv[1] == "-i":
		scan(parameters["-i"])
	elif sys.argv[1] == "-f":
		decode_file(parameters["-f"])
	elif sys.argv[1] == "-l":
		decode_enumeration(sys.argv[2:])
	else:
		print "Unknown parameters"
		sys.exit(1)
