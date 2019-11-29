import json
from simulators.CHashFlow import CHashFlow
from simulators.AHashFlow import AHashFlow

src1 = "/home/zongyi/traces/CAIDA.equinix-nyc.dirA.20180315-125910.UTC.anon.json"
src2 = "/home/zongyi/traces/HGC.20080415000.json"
dst1 = "./resForCAIDA.txt"
dst2 = "./resForHGC.txt"
#n_pkts = 2500000
#n_pkts = 5000000
thresh = 10
#memory = int(0.1*1024*1024)
CHF = 0
AHF = 1

def func(alg, memory, src, n_pkts, thresh):
	assert(alg == AHF or alg == CHF)
	if alg == AHF:
		switch = AHashFlow(memory)
	elif alg == CHF:
		switch = CHashFlow(memory)
	print switch
	print "n_pkts:", n_pkts
	print "memory:", memory/(1024.0*1024), "MB"

	with open(src, "r") as f:
		pkts = json.load(f)

	flows = dict()
	for i in range(n_pkts):
		p = pkts[i][1]
		if p not in flows:
			flows[p] = 0
		flows[p] = flows[p] + 1
		switch.receive_pkt(p)

	print "hh_are:", switch.hh_are(flows, thresh)	
	print "hh_f1score:", switch.hh_f1score(flows, thresh)

def HHCollect(src, n_pkts, thresh):
	with open(src, "r") as f:
		pkts = json.load(f)

	flows = dict()
	for i in range(n_pkts):
		p = pkts[i][1]
		if p not in flows:
			flows[p] = 0
		flows[p] = flows[p] + 1
	
	hhs = []
	for key, value in flows.items():
		if value >= thresh:
			hhs.append(value)
	hhs.sort()
	for item in hhs:
		print item

if __name__ == "__main__":
	memory = 0.25*1024*1024
	thresh = 5
	ahf = AHashFlow(memory)
	chf = CHashFlow(memory)
	with open(src1, "r") as f:
		pkts = json.load(f)

	with open(dst1, "w") as f:
		f.write("#n_pkts\tahf.hh_are\tchf.hh_are\tahf.hh_f1score\tchf.hh_f1score\n")
	flows = dict()
	count = 0
	for k in range(40):
		for i in range(500000):
			p = pkts[count][1]
			count = count + 1
			if p not in flows:
				flows[p] = 0
			flows[p] = flows[p] + 1
			ahf.receive_pkt(p)
			chf.receive_pkt(p)
		l = [str(count)]
		l.append(str(ahf.hh_are(flows, thresh)))
		l.append(str(chf.hh_are(flows, thresh)))
		l.append(str(ahf.hh_f1score(flows, thresh)))
		l.append(str(chf.hh_f1score(flows, thresh)))
		line = "\t".join(l) + "\n"
		with open(dst1, "a") as f:
			f.write(line)

