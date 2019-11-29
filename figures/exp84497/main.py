import json
from simulators.CHashFlow import CHashFlow
from simulators.AHashFlow import AHashFlow

src1 = "/home/zongyi/traces/HGC.20080415000.json"
src21 = "/home/zongyi/traces/CAIDA.equinix-nyc.dirA.20180315-125910.UTC.anon.json"
dst1 = "./resForHGC.txt"
dst2 = "./resForCAIDA.txt"
n_pkts = 5000000
#n_pkts = 50000
memory = 1.0*1024*1024

def func(memory, src, dst):
	chf = CHashFlow(memory)
	ahf = AHashFlow(memory)

	with open(src, "r") as f:
		pkts = json.load(f)

	flows = dict()
	for i in range(n_pkts):
		p = pkts[i][1]
		if p not in flows:
			flows[p] = 0
		flows[p] = flows[p] + 1
#		chf.receive_pkt(p)
		ahf.receive_pkt(p)
	
	with open(dst, "w") as f:
		f.write("#threshold\tAHashFlow.HH.ARE\tCHashFlow.HH.ARE\tAHashFlow.HH.F1Score\tCHashFlow.HH.F1Score\n")
		for thresh in range(5, 51, 5):
			l = [str(thresh)]
			l.append(str(ahf.hh_are(flows, thresh)))
#			l.append(str(chf.hh_are(flows, thresh)))
			l.append(str(ahf.hh_f1score(flows, thresh)))
#			l.append(str(chf.hh_f1score(flows, thresh)))
			line = "\t".join(l) + "\n"
			f.write(line)

if __name__ == "__main__":
	func(memory, src1, dst2)
