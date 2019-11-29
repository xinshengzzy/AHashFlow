import json
src1 = "/home/zongyi/traces/CAIDA.equinix-nyc.dirA.20180315-125910.UTC.anon.json"
src2 = "/home/zongyi/traces/CAIDA.equinix-nyc.dirA.20180315-130000.UTC.anon.json"
src3 = "/home/zongyi/traces/HGC.20080415000.json"
src4 = "/home/zongyi/traces/HGC.20080415001.json"
dst1 = "./CAIDA1.json"
dst2 = "./CAIDA2.json"
dst3 = "./HGC1.json"
dst4 = "./HGC2.json"
n_pkts = 5000000

def func(src, n_pkts, dst):
	with open(src, "r") as f:
		pkts = json.load(f)
	flows = dict()
	for i in range(n_pkts):
		p = pkts[i][1]
		if p not in flows:
			flows[p] = {"begin": i, "end": 0, "cnt": 0}
		flows[p]["end"] = i
		flows[p]["cnt"] = flows[p]["cnt"] + 1
	span_max = 0
	for key, value in flows.items():
		temp = value["end"] - value["begin"] + 1
		if temp > span_max:
			span_max = temp
	spans = dict()	
	for key, value in flows.items():
		temp = value["end"] - value["begin"] + 1
		if temp not in spans:
			spans[temp] = 0
		spans[temp] = spans[temp] + 1
	idx = []
	cdf = []
	pre = 0
	for i in range(1, span_max + 1):
		if i in spans:
			idx.append(i)
			temp = pre + spans[i]
			pre = temp
			cdf.append(temp)
	for i in range(len(cdf)):
		cdf[i] = cdf[i]/float(pre)
	with open(dst, "w") as f:
		json.dump([idx, cdf], f)
	return [idx, cdf]

if __name__ == "__main__":
	res1 = func(src1, n_pkts, dst1)
	res2 = func(src2, n_pkts, dst2)
	res3 = func(src3, n_pkts, dst3)
	res4 = func(src4, n_pkts, dst4)

	with open("./temp.json", "w") as f:
		json.dump([res1, res2, res3, res4], f)
