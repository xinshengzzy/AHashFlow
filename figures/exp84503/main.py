import json
from simulators.CHashFlow import CHashFlow
from simulators.AHashFlow import AHashFlow
from simulators.TurboFlow import TurboFlow

AHF = 0
CHF = 1
TF = 2

src1 = "/home/zongyi/traces/CAIDA.equinix-nyc.dirA.20180315-125910.UTC.anon.json"
src2 = "/home/zongyi/traces/HGC.20080415000.json"
ahf1 = "./ahf1.txt"
ahf2 = "./ahf2.txt"
ahf3 = "./ahf3.txt"
ahf4 = "./ahf4.txt"
ahf5 = "./ahf5.txt"
ahf6 = "./ahf6.txt"
ahf7 = "./ahf7.txt"
ahf8 = "./ahf8.txt"
ahf9 = "./ahf9.txt"
ahf10 = "./ahf10.txt"
chf1 = "./chf1.txt"
chf2 = "./chf2.txt"
chf3 = "./chf3.txt"
chf4 = "./chf4.txt"
chf5 = "./chf5.txt"
chf6 = "./chf6.txt"
chf7 = "./chf7.txt"
chf8 = "./chf8.txt"
chf9 = "./chf9.txt"
chf10 = "./chf10.txt"
tf1 = "./tf1.txt"
tf2 = "./tf2.txt"
tf3 = "./tf3.txt"
tf4 = "./tf4.txt"
tf5 = "./tf5.txt"
tf6 = "./tf6.txt"
tf7 = "./tf7.txt"
tf8 = "./tf8.txt"
tf9 = "./tf9.txt"
tf10 = "./tf10.txt"
memory = 0.25*1024*1024
n_pkts = 10000000

def func(alg, memory, n_pkts, src, dst):
	assert(alg in [AHF, CHF, TF])
	if alg == AHF:
		switch = AHashFlow(memory)
	elif alg == CHF:
		switch = CHashFlow(memory)
	elif alg == TF:
		switch = TurboFlow(memory)
	with open(src, "r") as f:
		pkts = json.load(f)

	with open(dst, "w") as f:
		f.write("#threshold\thh_are\thh_f1score\tn_exports\n")
	flows = dict()
	for i in range(n_pkts):
		p = pkts[i][1]
		if p not in flows:
			flows[p] = 0
		flows[p] = flows[p] + 1
		switch.receive_pkt(p)
	for thresh in range(5, 51, 5):
		l = [str(thresh)]
		l.append(str(switch.hh_are(flows, thresh)))
		l.append(str(switch.hh_f1score(flows, thresh)))
		l.append(str(switch.get_n_exports()))
		line = "\t".join(l) + "\n"
		with open(dst, "a") as f:
			f.write(line)

if __name__ == "__main__":
	func(TF, memory, n_pkts, src1, tf2)
	func(CHF, memory, n_pkts, src1, chf2)
	func(AHF, memory, n_pkts, src1, ahf2)
