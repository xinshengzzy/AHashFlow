import json
import sys
import math
from my_constants import *
import simulators.AHashFlow as AHashFlow
import simulators.FlowClassifier as FlowClassifier
import simulators.Perfect as Perfect
from network.flow_tools import *

n_pkts = -1

def func(src, dst, scheme):
	cls = FlowClassifier.FlowClassifier(src, TYPE_JSON, n_pkts)
	print "scheme:", scheme
	AHashFlow.set_scheme(scheme)
	ahf = AHashFlow.AHashFlow(src, TYPE_JSON, n_pkts)
	result = dict()
	result["scheme"] = str(scheme)
	result["are"] = dict()
	result["f1score"] = dict()
	for thresh in [10, 20, 30, 40, 50, 60, 70, 80, 90, 100]:
		are = hh_are_calc(cls.flows, ahf.flows, thresh)
		f1score = hh_f1score_calc(cls.flows, ahf.flows, thresh)
		result["are"][str(thresh)] = are
		result["f1score"][str(thresh)] = f1score
		print "thresh:", thresh, ", are:", are, ", f1score:", f1score
	with open(dst, "w") as f:
		json.dump(result, f)

if "__main__" == __name__:
	assert(4 == len(sys.argv))
	src = sys.argv[1]
	dst = sys.argv[2]
	scheme = int(sys.argv[3])
	func(src, dst, scheme)
