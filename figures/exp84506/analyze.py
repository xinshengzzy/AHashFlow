import json
import sys
import math

T = 10.0

def func(src, dst):
	with open(src, "r") as f:
		pkts = json.load(f)
	sizes = []
	flows = dict()
	for p in pkts:
		flowid = "\t".join([p["srcip"], p["dstip"], p["proto"], p["srcport"], p["dstport"]])
		timestamp = float(p["timestamp"])
		if flowid not in flows:
			flows[flowid] = {"latest": timestamp, "size": 1}
		else:
			interval = timestamp - flows[flowid]["latest"]
			if interval <= T:
				flows[flowid]["latest"] = timestamp
				flows[flowid]["size"] = flows[flowid]["size"] + 1
			else:
				sizes.append(flows[flowid]["size"])
				flows[flowid] = {"latest": timestamp, "size": 1}
	for key, value in flows.items():
		sizes.append(value["size"])
	length = max(sizes)
	cdf = [0]*(length + 1)
	for item in sizes:
		cdf[item] = cdf[item] + 1
	for i in range(1, length + 1):
		cdf[i] = cdf[i] + cdf[i - 1]
	total = float(cdf[-1])
	for i in range(len(cdf)):
		cdf[i] = cdf[i]/total
	with open(dst, "w") as f:
		json.dump(cdf, f)


if "__main__" == __name__:
	assert(3 == len(sys.argv))
	src = sys.argv[1]
	dst = sys.argv[2]
	func(src, dst)
