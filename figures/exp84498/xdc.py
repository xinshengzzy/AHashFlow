import json

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

hgc1 = "/home/zongyi/traces/HGC.20080415000.json"
hgc2 = "/home/zongyi/traces/HGC.20080415001.json"
caida1 = "/home/zongyi/traces/CAIDA.equinix-nyc.dirA.20180315-125910.UTC.anon.json"
caida2 = "/home/zongyi/traces/CAIDA.equinix-nyc.dirA.20180315-130000.UTC.anon.json"
n_pkts = 5000000
resHGC1 = "./resForHGC1.txt"
resHGC2 = "./resForHGC2.txt"
resCAIDA1 = "./resForCAIDA1.txt"
resCAIDA2 = "./resForCAIDA2.txt"
x = 0.95

def collectCompFlows(pkts, n_pkts, x = 0.9):
        flows = dict()
        for i in range(n_pkts):
                p = pkts[i]
                flowType = p[0]
                flowID = p[1]
                flags = p[2]
                if flowID not in flows:
						flows[flowID] = {"type": flowType, "count": 0, "SYN": 0, "RST": 0, "FIN": 0}
                flows[flowID]["count"] = flows[flowID]["count"] + 1
                if 'TCP' == flowType:
                        if flags & SYN:
                                flows[flowID]["SYN"] = 1
                        if flags & RST:
                                flows[flowID]["RST"] = 1
                        if flags & FIN:
                                flows[flowID]["FIN"] = 1

        for i in range(n_pkts, len(pkts)):
                p = pkts[i]
                flowType = p[0]
                flowID = p[1]
                flags = p[2]
                if 'TCP' == flowType and flowID in flows:
                        flows[flowID]["count"] = flows[flowID]["count"] + 1
                        if flags & SYN:
                                flows[flowID]["SYN"] = 1
                        if flags & RST:
                                flows[flowID]["RST"] = 1
                        if flags & FIN:
                                flows[flowID]["FIN"] = 1
                elif "UDP" == flowType and flowID in flows:
                        flows[flowID]["count"] = flows[flowID]["count"] + 1

	completeFlows = dict()
	for key, value in flows.items():	
			if "TCP" == value["type"] and 1 == value["SYN"] \
					and (1 == value["FIN"] or 1 == value["RST"]) and value["count"] >= 3:
					cnt = value["count"]
					point = int(cnt*x)
					completeFlows[key] = {"point3": cnt, "point2": point, "cnt": 0, "a": 0, "b": 0, "c": 0}
	return completeFlows

def calcXDC(flows, pkts, resFile):
	count = 0
	for p in pkts:
		count = count + 1
		flowID = p[1]
		if flowID in flows:
			flows[flowID]["cnt"] = flows[flowID]["cnt"] + 1
		   	if 1 == flows[flowID]["cnt"]:
		 		flows[flowID]["a"] = count
		 	if flows[flowID]["cnt"] == flows[flowID]["point2"]:
		 		flows[flowID]["b"] = count
		 	if flows[flowID]["cnt"] == flows[flowID]["point3"]:
		 		flows[flowID]["c"] = count

	with open(resFile, "w") as f:
		res = []
		for key, value in flows.items():
			xdc = float(value["b"] - value["a"])/(value["c"] - value["a"])
			res.append((value["point3"], xdc))
		json.dump(res, f)


def process(trace, n_pkts, resFile, x):
	with open(trace, "r") as f:
		pkts = json.load(f)
	flows = collectCompFlows(pkts, n_pkts, x)
	calcXDC(flows, pkts, resFile)

process(hgc1, n_pkts, resHGC1, x)
process(hgc2, n_pkts, resHGC2, x)
process(caida1, n_pkts, resCAIDA1, x)
process(caida2, n_pkts, resCAIDA2, x)
