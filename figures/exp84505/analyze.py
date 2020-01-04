import json
import sys
import math

def func(src, dst):
	with open(src, "r") as f:
		pkts = json.load(f)
	intervals = []
	flows = dict()
	for p in pkts:
		flowid = "\t".join([p["srcip"], p["dstip"], p["proto"], p["srcport"], p["dstport"]])
		timestamp = float(p["timestamp"])
		if flowid not in flows:
			flows[flowid] = {"latest": timestamp}
		else:
			tmp = timestamp - flows[flowid]["latest"]
			flows[flowid]["latest"] = timestamp
			intervals.append(tmp)
	intervals.sort()
	length = int(math.ceil(intervals[-1]))
	cdf = [0]*(length + 1)
	for item in intervals:
		tmp = int(math.ceil(item))
		cdf[tmp] = cdf[tmp] + 1
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
