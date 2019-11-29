import json

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

hgc = "/home/zongyi/traces/HGC.20080415000.json"
caida = "/home/zongyi/traces/CAIDA.equinix-nyc.dirA.20180315-125910.UTC.anon.json"
n_pkts = 5000000
resFile = "./numOfFlows.txt"

def processFile(trace, n_pkts, resFile):
        with open(resFile, "a") as f:
                line = "trace:" + trace + "\n"
                f.write(line)
                line = "n_pkts:" + str(n_pkts) + "\n"
                f.write(line)

        flows = dict()
        with open(trace, "r") as f:
                pkts = json.load(f)

        for i in range(n_pkts):
                p = pkts[i]
                flowType = p[0]
                flowID = p[1]
                flags = p[2]
                if flowID not in flows:
                        flows[flowID] = {"type": flowType, "count": 0, "SYN": 0, "RST": 0, "FIN": 0}
                if 'TCP' == flowType:
                        flows[flowID]["count"] = flows[flowID]["count"] + 1
                        if flags & SYN:
                                flows[flowID]["SYN"] = 1
                        if flags & RST:
                                flows[flowID]["RST"] = 1
                        if flags & FIN:
                                flows[flowID]["FIN"] = 1
                elif "UDP" == flowType:
                        flows[flowID]["count"] = flows[flowID]["count"] + 1

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

        with open(resFile, "a") as f:
                f.write("len(flows):" + str(len(flows)) + "\n")
                f.write("cnt1: the number of UDP flows" + "\n")
                f.write("cnt2: the number of TCP flows which don't have a FIN or RST flag" + "\n")
                f.write("cnt3: the number of TCP flows which have a FIN or RST flag " + "\n")
        cnt1 = cnt2 = cnt3 = 0
        for key, value in flows.items():
                if "UDP" == value["type"]:
                        cnt1 = cnt1 + 1
                elif "TCP" == value["type"]:
                        if 0 == value["FIN"] and 0 == value["RST"]:
                                cnt2 = cnt2 + 1
                        else:
                                cnt3 = cnt3 + 1
        with open(resFile, "a") as f:
                f.write("cnt1:" + str(cnt1) + "\n")
                f.write("cnt2:" + str(cnt2) + "\n")
                f.write("cnt3:" + str(cnt3) + "\n")


with open(resFile, "w") as f:
        pass
processFile(caida, n_pkts, resFile)
processFile(hgc, n_pkts, resFile)
