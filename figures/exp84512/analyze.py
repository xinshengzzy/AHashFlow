# coding: utf8
import json
import sys
import math
from my_constants import *
import simulators.AHashFlow as AHashFlow
import simulators.DHashFlow as DHashFlow
import simulators.FlowClassifier as FlowClassifier
from network.flow_tools import *

n_pkts = -1
#n_pkts = 1000

src = "/root/traces/CAIDA.equinix-nyc.dirA.20180315-130000.UTC.anon.json"
dst = "./res.caida.13000.json"

def func(n, gamma, flows):
	AHashFlow.set_n(n)
	AHashFlow.set_gamma(gamma)
	ahf = AHashFlow.AHashFlow(src, TYPE_JSON, n_pkts)
	results = dict()
	results["n_promotions"] = len(ahf.records)
	results["n_exports"] = len(ahf.ids)
	ae = banded_ae_calc(ahf.flows, flows, 33, -1)
	results["ae"] = ae
#	f1score1 = banded_f1score_calc(ahf.flows, flows, param + 1, -1)
	f1score = banded_f1score_calc(ahf.flows, flows, 33, -1)
#	results["f1score1"] = f1score1
	results["f1score"] = f1score
	return results

def calc():
	'''对数据包进行流归类'''
	cls = FlowClassifier.FlowClassifier(src, TYPE_JSON, n_pkts)
	res = dict()
	'''
	n = 2, gamma = 6, n_promotions = 208332
	n = 4, gamma = 8, n_promotions = 181305
	n = 8
	n = 16
	n = 32, gamma = 32, n_promotions = 185980 
	'''
	n = 4
	for gamma in range(n, 21):
		temp = func(n, gamma, cls.flows)
		print "gamma:", gamma, ", n_promotions:", temp["n_promotions"]
	exit()
	for param in [2, 4, 8, 16, 32]:
		print "param:", param
		temp = func(param, cls.flows)
		res[param] = temp
	with open(dst, "w") as f:
   		json.dump(res, f)	   

if "__main__" == __name__:
	calc()
