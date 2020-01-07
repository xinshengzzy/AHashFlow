import json
import sys
import math
from my_constants import *
import simulators.AHashFlow as AHashFlow
import simulators.FlowClassifier as FlowClassifier
from flow_tools import *

n_pkts = 1000

def func(src, gamma, flows, n_pkts):
	AHashFlow.set_gamma(gamma)
	ahf = AHashFlow.AHashFlow(src, TYPE_JSON, n_pkts)
	results = dict()
	for thresh in [10, 20, 30, 40, 50, 60]:
		are = hh_are_calc(flows, ahf.flows, thresh)
		f1score = hh_f1score_calc(flow, ahf.flows, thresh)
		results[thresh] = {"are": are, "f1score": f1score}
	return results

def calc(src, dst):
	cls = FlowClassifier.FlowClassifier(src, TYPE_JSON, n_pkts)
	results = dict()
	for gamma in range(2, 11):
		temp = func(src, gamma, cls.flows, n_pkts)
		results[gamma] = temp
	with open(dst, "w") as f:
		json.dump(results, f)
	

if "__main__" == __name__:
	src = "/root/traces/CAIDA.equinix-nyc.dirA.20180315-130000.UTC.anon.json"
	print AHashFlow.M_TABLE_1_SIZE
	exit()
	ahf = AHashFlow.AHashFlow(src, TYPE_JSON, n_pkts)

