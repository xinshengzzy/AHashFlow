from simulators.ZipfTrafficGenerator import ZipfTrafficGenerator
import simulators.AHashFlow as AHashFlow
from my_constants import *
from network.flow_tools import *
import simulators.AHashFlow as AHashFlow
import simulators.EHashFlow as EHashFlow
from simulators.FlowClassifier import FlowClassifier
import my_constants as mc
import json


src = "/root/traces/CAIDA.equinix-nyc.dirA.20180315-130000.UTC.anon.json"
n_pkts = -1

def func(hf, flows):
	res = dict()
	res["n_promotions"] = len(hf.records)
	res["ae"] = dict()
	res["are"] = dict()
	res["f1score"] = dict()
	print "n_promotions:", len(hf.records)

	for thresh in range(10, 101, 10):
		ae = banded_ae_calc(hf.flows, flows, thresh, -1)
		are = banded_are_calc(hf.flows, flows, thresh, -1)
		f1score =  banded_f1score_calc(hf.flows, flows, thresh, -1)
		res["ae"][str(thresh)] = ae
		res["are"][str(thresh)] = are
		res["f1score"][str(thresh)] = f1score
		print "thresh:%d, ae:%.3f, are:%.3f, f1score:%.3f" % (thresh, ae, are, f1score)
	return res

def calc(n, gamma, flows):
	print "AHashFlow:"
	AHashFlow.set_n(n)
	AHashFlow.set_gamma(gamma)
	ahf = AHashFlow.AHashFlow(src, TYPE_JSON, n_pkts)
	res = func(ahf, flows)
	filename = ".".join(["ahf", "n", str(n), "gamma", str(gamma), "caida.130000.json"])
	with open(filename, "w") as f:
		json.dump(res, f)

	print "EHashFlow:"
	EHashFlow.set_n(n)
	EHashFlow.set_gamma(gamma)
	ehf = EHashFlow.EHashFlow(src, TYPE_JSON, n_pkts)
	res = func(ehf, flows)
	filename = ".".join(["ehf", "n", str(n), "gamma", str(gamma), "caida.130000.json"])
	with open(filename, "w") as f:
		json.dump(res, f)

if "__main__" == __name__:
	cls = FlowClassifier(src, TYPE_JSON, n_pkts)
	for n in [1, 2, 4]:
		for gamma in range(4, 11):
			print "gamma:", gamma, ", n:", n
			calc(n, gamma, cls.flows)
