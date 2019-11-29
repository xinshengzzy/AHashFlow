import json
import mytools
from simulators.CHashFlow import CHashFlow
from simulators.AHashFlow import AHashFlow
memory = 1.0*1024*1024

hgc1 = "/home/zongyi/traces/HGC.20080415000.json"
hgc2 = "/home/zongyi/traces/HGC.20080415001.json"
caida1 = "/home/zongyi/traces/CAIDA.equinix-nyc.dirA.20180315-125910.UTC.anon.json"
caida2 = "/home/zongyi/traces/CAIDA.equinix-nyc.dirA.20180315-130000.UTC.anon.json"
n_pkts = 5000000

def collectFlows(pkts, n_pkts):
	'''Collect the flows appearing in the first n_pkts packets, and record
	the index of the last packet of each flow in the whole trace'''
	flows = dict()
	for i in range(n_pkts):
		p = pkts[i]
		flowID = p[1]
		if flowID not in flows:
			flows[flowID] = {"count": 0, "idx": 0}
		flows[flowID]["count"] = flows[flowID]["count"] + 1
		flows[flowID]["idx"] = i
	for i in range(n_pkts, len(pkts)):
		p = pkts[i]
		flowID = p[1]
		if flowID in flows:
			flows[flowID]["count"] = flows[flowID]["count"] + 1
			flows[flowID]["idx"] = i
	mappedFlows = dict()
	for key, value in flows.items():
		digest = mytools.hash5(key)%(2**32)
		mappedFlows[digest] = value
	return mappedFlows

def process(trace, n_pkts):
	with open(trace, "r") as f:
		pkts = json.load(f)
	flows = collectFlows(pkts, n_pkts)
	switch = AHashFlow(memory)
	for i in range(n_pkts):
		p = pkts[i][1]
		switch.receive_pkt(p)
	
	idx = []
	for item in switch.M:
		p = item[0]
		if p in flows and flows[p]["idx"] < n_pkts:
			idx.append(flows[p]["idx"])
	idx.sort()
	for item in idx:
		print item

process(hgc1, n_pkts)
#process(hgc2, n_pkts)
#process(caida1, n_pkts)
#process(caida2, n_pkts)
