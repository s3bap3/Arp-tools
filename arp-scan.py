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
	print('\n=================')
	print('Execution aborted')
	print('=================')
	os.system("kill -9 " + str(os.getpid()))
	sys.exit(1)

def signal_exit(signal, frame):
	sys.exit(1)

def usage():
	if len(sys.argv) < 3:
		print "\nUsage:"
		print "\tpython arp-scan.py -l <IPs>"
		print "\t<ips> is a single ip, range , or list of IPs (separated by \",\")\n"
		sys.exit(1)
 
def decode_netmask (network):
	for ip in netaddr.IPNetwork(network):
		scan_devices(str(ip))

def decode_file (filename):
	ipsfile = open (filename,"r")
	for line in ipsfile:
		scan_devices(line)

def decode_enumeration (iplist):
	for line in iplist:
		scan_devices(line)

def scan_devices(ip):
	ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip,hwdst="ff:ff:ff:ff:ff:ff"), timeout=2, verbose=0)
	for pair in ans:
		print "%-20s%s" %(pair[1].psrc, pair[1].hwsrc)

def check_root():
    if not os.geteuid() == 0:
        print "Run as root."
        exit(1)

if __name__ == "__main__":
	signal.signal(signal.SIGINT, signal_handler)
	usage()
	check_root()
	parameters ={sys.argv[1]:sys.argv[2]}
	print "\n[*] Scanning for active IPs"
	if "/" in parameters["-l"]:
		print "[*] Scanning subnet %s" %(parameters["-l"])
		print "\n%-20s%s" %("IP", "MAC")
		decode_netmask(parameters["-l"])
	elif "," in parameters["-l"]:
		print "[*] Scanning list of IPs %s" %(parameters["-l"])
		print "\n%-20s%s" %("IP", "MAC")
		decode_enumeration(parameters["-l"])
	else:
		print "[*] Scanning Single IP %s" %(parameters["-l"])
		print "\n%-20s%s" %("IP", "MAC")
		scan_devices(parameters["-l"])
	print ""
