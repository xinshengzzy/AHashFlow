import json
import sys
import math
from my_constants import *
import simulators.AHashFlow as AHashFlow
import simulators.FlowClassifier as FlowClassifier
from flow_tools import *

n_pkts = -1

def func(src, gamma, flows, n_pkts):
	AHashFlow.set_gamma(gamma)
	ahf = AHashFlow.AHashFlow(src, TYPE_JSON, n_pkts)
	results = dict()
	results["n_promotions"] = len(ahf.records)
	results["n_exports"] = len(ahf.ids)
	results["are"] = dict()
	results["f1score"] = dict()
	for thresh in [10, 20, 30, 40, 50, 60]:
		are = hh_are_calc(flows, ahf.flows, thresh)
		f1score = hh_f1score_calc(flows, ahf.flows, thresh)
		results["are"][thresh] = are
		results["f1score"][thresh] = f1score
#		results[thresh] = {"are": are, "f1score": f1score}
		print "thresh:", thresh, ", are:", are, ", f1score:", f1score
	return results

def calc(src, dst):
	cls = FlowClassifier.FlowClassifier(src, TYPE_JSON, n_pkts)
	print "real n_flows:", len(cls.flows)
	results = dict()
	for gamma in range(0, 11):
#	for gamma in range(2, 4):
		print "gamma:", gamma
		temp = func(src, gamma, cls.flows, n_pkts)
		results[gamma] = temp
	with open(dst, "w") as f:
		json.dump(results, f)
	

if "__main__" == __name__:
	assert(3 == len(sys.argv))
	src = sys.argv[1]
	dst = sys.argv[2]
	calc(src, dst)
