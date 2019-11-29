import mytools
from simulators.CHashFlow import CHashFlow
from simulators.AHashFlow import AHashFlow
import json

memory = 1.0*1024*1024
caida = "/home/zongyi/traces/CAIDA.equinix-nyc.dirA.20180315-125910.UTC.anon.json"
hgc = "/home/zongyi/traces/HGC.20080415000.json"
resFile = "./fsc.txt"

caida_chf = CHashFlow(memory)
hgc_chf = CHashFlow(memory)
caida_ahf = AHashFlow(memory)
hgc_ahf = AHashFlow(memory)
count = 0
caida_flows = dict()
hgc_flows = dict()

with open(caida, "r") as f:
	caida_pkts = json.load(f)

with open(hgc, "r") as f:
	hgc_pkts = json.load(f)

def func(n_pkts, resFile):
	global caida_chf, hgc_chf, caida_ahf, hgc_ahf, count
	global caida_flows, hgc_flows, caida_pkts, hgc_pkts
	for i in range(n_pkts):
		p = caida_pkts[count]
		if p in caida_flows:
			caida_flows[p] = caida_flows[p] + 1
		else:
			caida_flows[p] = 1
		caida_ahf.receive_pkt(p)
		caida_chf.receive_pkt(p)

		p = hgc_pkts[count]
		if p in hgc_flows:
			hgc_flows[p] = hgc_flows[p] + 1
		else:
			hgc_flows[p] = 1
		hgc_ahf.receive_pkt(p)
		hgc_chf.receive_pkt(p)
		count = count + 1
	
	l = "\t".join([str(count), str(caida_ahf.fsc(caida_flows)), str(hgc_ahf.fsc(hgc_flows)), str(caida_chf.fsc(caida_flows)), str(hgc_chf.fsc(hgc_flows))])
	with open(resFile, "a") as f:
		f.write(l + "\n")

with open(resFile, "w") as f:
	f.write("n_pkts\tCAIDA-AHashFlow\tHGC-AHashFlow\tCAIDA-CHashFlow\tHGC-CHashFlow\n")

for i in range(10):
	func(500000, resFile)

