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
	ae1 = banded_ae_calc(flows, ahf.flows, gamma + 1, -1)
	ae2 = banded_ae_calc(flows, ahf.flows, gamma + 1, 255)
	results["ae1"] = ae1
	results["ae2"] = ae2
	return results

def calc():
	'''对数据包进行流归类'''
	cls = FlowClassifier.FlowClassifier(src, TYPE_JSON, n_pkts)
	res = dict()
	gamma = 5
	for n in [8, 16, 32, 64, 128, 256]:
		print "n:", n
		temp = func(n, gamma, cls.flows)
		res[n] = temp
	with open(dst, "w") as f:
   		json.dump(res, f)	   

if "__main__" == __name__:
	calc()
