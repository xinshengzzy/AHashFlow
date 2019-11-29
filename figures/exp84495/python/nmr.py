import mytools
from simulators.HashFlow import HashFlow
from simulators.CHashFlow import CHashFlow
from simulators.DHashFlow import DHashFlow
import json

memory = 1.0*1024*1024
trace = "/home/zongyi/traces/CAIDA.equinix-nyc.dirA.20180315-125910.UTC.anon.json"
resFile = "./nmr.txt"

hf = HashFlow(memory)
chf = CHashFlow(memory)
dhf = DHashFlow(memory)
count = 0

def func(pkts, n_pkts, resFile):
	global hf, chf, dhf, count
	for i in range(n_pkts):
		p = pkts[count]
		count = count + 1
		hf.receive_pkt(p)
		dhf.receive_pkt(p)
		chf.receive_pkt(p)
	
	l = "\t".join([str(count), str(hf.nmr()), str(dhf.nmr()), str(chf.nmr())])
	with open(resFile, "a") as f:
		f.write(l + "\n")
	
	

with open(resFile, "w") as f:
	f.write("n_pkts\tHashFlow\tDHashFlow\tCHashFlow\n")

with open(trace, "r") as f:
	pkts = json.load(f)
	func(pkts, 500000, resFile)
	for i in range(10):
		func(pkts, 200000, resFile)

