from scapy.all import *

flows = dict()
n = 2500000
count = 0
# this function is used to calculate the maximum/average size of CAIDA and HGC flows.
def func(pkt):
	global flows, n, count
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
		key = "\t".join([srcip, dstip, str(proto), str(sport), str(dport)])
		if key in flows:
			flows[key] = flows[key] + 1
		else:
			flows[key] = 1
	count = count + 1
	print count
	if count >= n:
		return True
	else:
		return False



if __name__ == "__main__":
	caida_file="/home/zongyi/Trace/CAIDA/equinix-nyc.dirA.20180315-130200.UTC.anon.pcap"
	hgc_file="/home/zongyi/Trace/HGC/20080415001.pcap"
	n = 2500000
	with open("./res.txt", "a") as f:
		# parse the CAIDA trace file
		flows.clear()
		count = 0
		sniff(offline=caida_file, stop_filter=func, store=False)
		total = 0
		_max = 0
		for key, value in flows.items():
			total = total + value
			if value > _max:
				_max = value
		f.write("Algorithm\tn_flows\tmax_size\taverage_size\n")
		line = "\t".join(["CAIDA", str(len(flows)), str(_max), str(float(total)/len(flows))])
		f.write(line + "\n")

		# parse the HGC trace file
		flows.clear()
		count = 0
		sniff(offline=hgc_file, stop_filter=func, store=False)
		total = 0
		_max = 0
		for key, value in flows.items():
			total = total + value
			if value > _max:
				_max = value
		line = "\t".join(["HGC", str(len(flows)), str(_max), str(float(total)/len(flows))])
		f.write(line + "\n")
