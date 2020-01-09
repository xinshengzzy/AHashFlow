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
dst1 = "./caida.hh.ae.13000.dhf.json"
dst2 = "./caida.hh.ae.13000.ahf.n.2.json"
dst3 = "./caida.hh.ae.13000.ahf.n.4.json"
dst4 = "./caida.hh.ae.13000.ahf.n.8.json"
dst5 = "./caida.hh.ae.13000.ahf.n.16.json"

def func(cls, hf, dst):
	results = dict()
	results["n_promotions"] = len(hf.records)
	results["n_exports"] = len(hf.ids)
	results["hh_ae"] = dict()
	for thresh in range(10, 101, 10):
		ae = hh_ae_calc(cls.flows, hf.flows, thresh)
		results["hh_ae"][thresh] = ae
	with open(dst, "w") as f:
		json.dump(results, f)
		
def calc():
#	'''对数据包进行流归类'''
	cls = FlowClassifier.FlowClassifier(src, TYPE_JSON, n_pkts)

	gamma = 6
	DHashFlow.set_gamma(gamma)
	'''生成DHashFlow的结果'''
	print "DHashFlow"
	dhf = DHashFlow.DHashFlow(src, TYPE_JSON, n_pkts)
	func(cls, dhf, dst1)

	AHashFlow.set_gamma(gamma)
	'''生成AHashFlow(N=2)的结果'''
	print "AHashFlow (N=2)"
	AHashFlow.set_n(2)
	ahf = AHashFlow.AHashFlow(src, TYPE_JSON, n_pkts)
	func(cls, ahf, dst2)

	'''生成AHashFlow(N=4)的结果'''
	print "AHashFlow (N=4)"
	AHashFlow.set_n(4)
	ahf = AHashFlow.AHashFlow(src, TYPE_JSON, n_pkts)
	func(cls, ahf, dst3)
	
	'''生成AHashFlow(N=8)的结果'''
	print "AHashFlow (N=8)"
	AHashFlow.set_n(8)
	ahf = AHashFlow.AHashFlow(src, TYPE_JSON, n_pkts)
	func(cls, ahf, dst4)

	'''生成AHashFlow(N=16)的结果'''
	print "AHashFlow (N=16)"
	AHashFlow.set_n(16)
	ahf = AHashFlow.AHashFlow(src, TYPE_JSON, n_pkts)
	func(cls, ahf, dst5)

if "__main__" == __name__:
	calc()
