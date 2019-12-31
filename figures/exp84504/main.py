from simulators.FlowClassifier import FlowClassifier
from simulators.AHashFlow import AHashFlow
from flow_tools import *
import json
filename = "/root/traces/CAIDA.equinix-nyc.dirA.20180315-125910.UTC.anon.clean.pcap"
n_pkts = 1000000
thresh = 5
def main(filename, n_pkts, thresh):
	cls = FlowClassifier(filename, n_pkts)
	ahf = AHashFlow(filename, n_pkts)
	hh_are = hh_are_calc(cls.flows, ahf.flows, thresh)
	hh_f1score = hh_f1score_calc(cls.flows, ahf.flows, thresh)
	res = dict()
	res["filename"] = filename
	res["n_pkts"] = n_pkts
	res["threshold"] = thresh
	res["hh_are"] = hh_are
	res["hh_f1score"] = hh_f1score
	print "hh_are:", hh_are
	print "hh_f1score:", hh_f1score
	return res

if "__main__" == __name__:
	n_pkts = 1000000
	main(filename, n_pkts, thresh)
