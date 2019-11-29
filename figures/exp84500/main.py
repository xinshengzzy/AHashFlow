import json
src1 = "/home/zongyi/traces/CAIDA.equinix-nyc.dirA.20180315-125910.UTC.anon.json"
src2 = "/home/zongyi/traces/CAIDA.equinix-nyc.dirA.20180315-130000.UTC.anon.json"
src3 = "/home/zongyi/traces/HGC.20080415000.json"
src4 = "/home/zongyi/traces/HGC.20080415001.json"
dst = "./res.txt"
n_pkts = 5000000
max_cnt = 20

def func(src, dst, n_pkts, max_cnt):
	with open(src, "r") as f:
		pkts = json.load(f)
	flows = dict()
	for i in range(n_pkts):
		p = pkts[i][1]
		if p not in flows:
			flows[p] = 0
		flows[p] = flows[p] + 1

	stats = [0]*max_cnt
	for key, value in flows.items():
		if value <= max_cnt:
			stats[value - 1] = stats[value - 1] + 1
	n_flows = len(flows)
	res = []
	for i in range(max_cnt):
		temp = (n_flows - stats[i])/float(n_flows)
		res.append(str(temp))
		n_flows = n_flows - stats[i]
	with open(dst, "a") as f:
		l = "\t".join(res) + "\n"
		f.write(l)

if __name__ == "__main__":
	with open(dst, "w") as f:
		pass
	func(src1, dst, n_pkts, max_cnt)
	func(src2, dst, n_pkts, max_cnt)
	func(src3, dst, n_pkts, max_cnt)
	func(src4, dst, n_pkts, max_cnt)
