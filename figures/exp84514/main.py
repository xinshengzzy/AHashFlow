from simulators.ZipfTrafficGenerator import Zipf流量生成器
import simulators.AHashFlow as AHashFlow
from my_constants import *
from network.flow_tools import *
import simulators.AHashFlow as AHashFlow
import simulators.EHashFlow as EHashFlow
from simulators.FlowClassifier import FlowClassifier
import my_constants as mc
import json


src = "/root/traces/CAIDA.equinix-nyc.dirA.20180315-130000.UTC.anon.json"

def func(hf, flows):
	res = dict()
	res["n_promotions"] = len(hf.records)
	res["ae"] = dict()
	res["are"] = dict()
	res["f1score"] = dict()
	print("n_promotions:", len(hf.records))

	for thresh in range(10, 101, 10):
		ae = banded_ae_calc(hf.flows, flows, thresh, -1)
		are = banded_are_calc(hf.flows, flows, thresh, -1)
		f1score =  banded_f1score_calc(hf.flows, flows, thresh, -1)
		res["ae"][str(thresh)] = ae
		res["are"][str(thresh)] = are
		res["f1score"][str(thresh)] = f1score
		print("thresh:%d, ae:%.3f, are:%.3f, f1score:%.3f" % (thresh, ae, are, f1score))
	return res

def calc(n, gamma, flows, n_pkts):
	EHashFlow.set_n(n)
	EHashFlow.set_gamma(gamma)
	ehf = EHashFlow.EHashFlow(src, TYPE_JSON, n_pkts)
	res = func(ehf, flows)
	filename = ".".join(["ehf", "n", str(n), "gamma", str(gamma), "npkts", str(n_pkts), "caida.130000.json"])
	with open(filename, "w") as f:
		json.dump(res, f)

if "__main__" == __name__:
	n = 1
	for n_pkts in range(5, 26, 5):
		n_pkts = n_pkts * (10**6)
		cls = FlowClassifier(src, TYPE_JSON, n_pkts)
		for gamma in range(4, 13, 2):
			print("n_pkts=%d, gamma=%d" % (n_pkts, gamma))
			calc(n, gamma, cls.flows, n_pkts)