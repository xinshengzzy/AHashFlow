from my_constants import *
from network.flow_tools import *
import simulators.HashFlow as HashFlow
import simulators.GHashFlow as GHashFlow
from simulators.FlowClassifier import FlowClassifier
import my_constants as mc
import json


src = "/root/traces/CAIDA.equinix-nyc.dirA.20180315-130000.UTC.anon.json"
n_pkts = 5*(10**6)

def func(hf, flows):
	res = dict()
	res["n_promotions"] = hf.n_promotions
	res["ae"] = dict()
	res["are"] = dict()
	res["f1score"] = dict()
	print("n_promotions:%d" % hf.n_promotions)

	for thresh in range(10, 101, 10):
		ae = banded_ae_calc(hf.flows, flows, thresh, -1)
		are = banded_are_calc(hf.flows, flows, thresh, -1)
		f1score =  banded_f1score_calc(hf.flows, flows, thresh, -1)
		res["ae"][str(thresh)] = ae
		res["are"][str(thresh)] = are
		res["f1score"][str(thresh)] = f1score
		print("thresh:%d, ae:%.3f, are:%.3f, f1score:%.3f" % (thresh, ae, are, f1score))
	return res

def calc(n_pkts):
	print("n_pkts:%d" % n_pkts)
	ghf = GHashFlow.GHashFlow(src, TYPE_JSON, n_pkts)
	cls = FlowClassifier(src, TYPE_JSON, n_pkts)
	hf = HashFlow.HashFlow(src, TYPE_JSON, n_pkts)
#	for 流标识符, 计数器 in ghf.M:
#		print(流标识符, 计数器)
	print("HashFlow:")
	filename = ".".join(["hf", "npkts", str(n_pkts), "caida.130000.json"])
	with open(filename, "w") as f:
		res = func(hf, cls.flows)
		json.dump(res, f)
	print("GHashFlow:")
	filename = ".".join(["ghf", "npkts", str(n_pkts), "caida.130000.json"])
	with open(filename, "w") as f:
		res = func(ghf, cls.flows)
		json.dump(res, f)

if "__main__" == __name__:
	for n_pkts in range(1, 11):
		n_pkts = n_pkts * (10**6)
		calc(n_pkts)
#	calc(n_pkts)
