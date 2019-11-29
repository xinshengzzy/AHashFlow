from mytools import *
from nfdump_reader import nfcapdReader
import csv
from scapy.all import *

path = "/home/zongyi/traces/"
tsinghua = path + "Tsinghua.20140204"
hgc = path + "HGC.20080415000.pcap"
chinatelecom = path + "ChinaTelecom.nfcapd.201512312300"
caida = path + "CAIDA.equinix-nyc.dirA.20180315-125910.UTC.anon.pcap"
limit = 5000000
res = "./results.txt"
with open(res, "w") as f:
	f.write("#trace\tn_flowID\tn_digest\n")

# processing the CAIDA trace file
s1 = set()
s2 = set()
count = 0
def func(pkt):
	global s1, s2, count, limit
	srcip, dstip, proto, sport, dport = None, None, None, None, None
	if pkt.haslayer(IP):
		srcip = pkt[IP].src
		dstip = pkt[IP].dst
		proto = pkt[IP].proto
		if pkt.haslayer(TCP):
			sport = pkt[TCP].sport
			dport = pkt[TCP].dport
		elif pkt.haslayer(UDP):
			sport = pkt[UDP].sport
			dport = pkt[UDP].dport
	if srcip and dstip and proto and sport and dport:
		flowID = "\t".join([srcip, dstip, str(proto), str(sport), str(dport)])
		digest = hash1(flowID)
		s1.add(flowID)
		s2.add(digest)
		count = count + 1
	if count >= limit:
		return True
	else:
		return False
sniff(offline=caida, stop_filter=func, store=False)
with open(res, "a") as f:
	f.write("\t".join(["CAIDA", str(len(s1)), str(len(s2))]) + "\n")

# processing the HGC trace file
s1 = set()
s2 = set()
count = 0
sniff(offline=hgc, stop_filter=func, store=False)
with open(res, "a") as f:
	f.write("\t".join(["HGC", str(len(s1)), str(len(s2))]) + "\n")

# processing the ChinaTelecom trace file
reader = nfcapdReader(chinatelecom)
count = 0
s1 = set()
s2 = set()
for row in reader.reader:
	if False == row[11].isdigit():
		continue
	flowID = "\t".join([row[3], row[4], row[5], row[6], row[7]])
	digest = hash1(flowID)
	s1.add(flowID)
	s2.add(digest)
	pktCnt = int(row[11])
	count = count + pktCnt
	if count >= limit:
		break
with open(res, "a") as f:
	f.write("\t".join(["ChinaTelecom", str(len(s1)), str(len(s2))]) + "\n")

# processing the Tsinghua trace file
count = 0
s1 = set()
s2 = set()
with open(tsinghua, "r") as f:
	while True:
		l = f.readline()
		if "#" == l[0]:
			continue
		l = l.replace(",", "")
		items = l.split(" ")
		flowID = "\t".join([items[1], items[2], items[4], items[5], items[6]])
		digest = hash1(flowID)
		pktCnt = int(items[17])
		count = count + pktCnt
		s1.add(flowID)
		s2.add(digest)
		if count >= limit:
			break
with open(res, "a") as f:
	f.write("\t".join(["Tsinghua", str(len(s1)), str(len(s2))]) + "\n")


