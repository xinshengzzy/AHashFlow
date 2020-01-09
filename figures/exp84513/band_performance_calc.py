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
dst1 = "./caida.13000.band.dhf.json"
dst2 = "./caida.13000.band.ahf.n.2.json"
dst3 = "./caida.13000.band.ahf.n.4.json"
dst4 = "./caida.13000.band.ahf.n.8.json"
dst5 = "./caida.13000.band.ahf.n.16.json"

def func(cls, hf):
	results = dict()
	results["n_promotions"] = len(hf.records)
	results["n_exports"] = len(hf.ids)
	results["are"] = dict()
	results["f1score"] = dict()
	bands = [[10, 20], [20, 30], [30, 40], [40, 50], [50, 60], [60, 70], 
		[70, 80], [80, 90], [90, 100], [100, -1]]
	for band in bands:
		are = band_are_calc(cls.flows, hf.flows, band[0], band[1])
		f1score = band_f1score_calc(cls.flows, hf.flows, band[0], band[1])
		key = str(band[0]) + str(band[1])
		results["are"][key] = are
		results["f1score"][key] = f1score
	return results

def calc():
#	'''对数据包进行流归类'''
	cls = FlowClassifier.FlowClassifier(src, TYPE_JSON, n_pkts)
	'''生成DHashFlow的结果'''
	print "DHashFlow"
	results = dict()
	for gamma in range(1, 21):
		print "gamma:", gamma
		DHashFlow.set_gamma(gamma)
		dhf = DHashFlow.DHashFlow(src, TYPE_JSON, n_pkts)
		temp = func(cls, dhf)
		results[str(gamma)] = temp
	with open(dst1, "w") as f:
		json.dump(results, f)

	'''生成AHashFlow(N=2)的结果'''
	print "AHashFlow(N=2)"
	AHashFlow.set_n(2)
	results = dict()
	for gamma in range(2, 21):
		print "gamma:", gamma
		AHashFlow.set_gamma(gamma)
		ahf = AHashFlow.AHashFlow(src, TYPE_JSON, n_pkts)
		temp = func(cls, ahf)
		results[str(gamma)] = temp
	with open(dst2, "w") as f:
		json.dump(results, f)

	'''生成AHashFlow(N=4)的结果'''
	print "AHashFlow(N=4)"
	AHashFlow.set_n(4)
	results = dict()
	for gamma in range(4, 21):
		print "gamma:", gamma
		AHashFlow.set_gamma(gamma)
		ahf = AHashFlow.AHashFlow(src, TYPE_JSON, n_pkts)
		temp = func(cls, ahf)
		results[str(gamma)] = temp
	with open(dst3, "w") as f:
		json.dump(results, f)

	'''生成AHashFlow(N=8)的结果'''
	print "AHashFlow(N=8)"
	AHashFlow.set_n(8)
	results = dict()
	for gamma in range(8, 21):
		print "gamma:", gamma
		AHashFlow.set_gamma(gamma)
		ahf = AHashFlow.AHashFlow(src, TYPE_JSON, n_pkts)
		temp = func(cls, ahf)
		results[str(gamma)] = temp
	with open(dst4, "w") as f:
		json.dump(results, f)

	'''生成AHashFlow(N=16)的结果'''
	print "AHashFlow(N=16)"
	AHashFlow.set_n(16)
	results = dict()
	for gamma in range(16, 21):
		print "gamma:", gamma
		AHashFlow.set_gamma(gamma)
		ahf = AHashFlow.AHashFlow(src, TYPE_JSON, n_pkts)
		temp = func(cls, ahf)
		results[str(gamma)] = temp
	with open(dst5, "w") as f:
		json.dump(results, f)

if "__main__" == __name__:
	calc()
