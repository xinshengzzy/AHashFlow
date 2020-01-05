import json
import sys
import math

T = 10.0

def func(src, dst):
	with open(src, "r") as f:
		pkts = json.load(f)
	periods = []
	flows = dict()
	begin = -1
	end = 0
	for p in pkts:
		flowid = "\t".join([p["srcip"], p["dstip"], p["proto"], p["srcport"], p["dstport"]])
		timestamp = float(p["timestamp"])
		if -1 == begin:
			begin = timestamp
		if timestamp > end:
			end = timestamp
		if flowid not in flows:
			flows[flowid] = {"begin": timestamp, "end": timestamp, "size": 1}
		else:
			interval = timestamp - flows[flowid]["end"]
			if interval <= T:
				flows[flowid]["end"] = timestamp
				flows[flowid]["size"] = flows[flowid]["size"] + 1
			else:
				periods.append([flows[flowid]["begin"], flows[flowid]["end"]])
				flows[flowid] = {"begin": timestamp, "end": timestamp, "size": 1}
	for key, value in flows.items():
		periods.append([value["begin"], value["end"]])
	length = int(math.floor(end - begin + 0.5) + 1)
	n_flows = [0]*length
	for item in periods:
		pt1 = int(math.floor(item[0] - begin + 0.5))
		pt2 = int(math.floor(item[1] - begin + 0.5))
		for i in range(pt1, pt2 + 1):
			n_flows[i] = n_flows[i] + 1
	with open(dst, "w") as f:
		json.dump(n_flows, f)


if "__main__" == __name__:
	assert(3 == len(sys.argv))
	src = sys.argv[1]
	dst = sys.argv[2]
	func(src, dst)
