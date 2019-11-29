import json
src1 = "/home/zongyi/traces/CAIDA.equinix-nyc.dirA.20180315-125910.UTC.anon.json"
src2 = "/home/zongyi/traces/HGC.20080415000.json"
n_pkts = 5000000
thresh = 10

with open(src1, "r") as f:
	pkts = json.load(f)

flows = dict()
for i in range(n_pkts):
	p = pkts[i][1]
	if p not in flows:
		flows[p] = 0
	flows[p] = flows[p] + 1

print "n_flows:", len(flows)
n_hhs = 0
for key, value in flows.items():
	if value >= thresh:
		n_hhs = n_hhs + 1
print "n_hhs:", n_hhs
exit()

max_cnt = 10000
stats = [0]*max_cnt
for key, value in flows.items():
	if value < max_cnt:
		stats[value - 1] = stats[value - 1] + 1

for i in range(max_cnt):
	print i + 1, ":", stats[i]

exit()

for i in range(n_pkts):
	p = pkts[i][1]
	if p not in flows:
		flows[p] = {"begin": i, "end": 0, "cnt": 0}
	flows[p]["end"] = i
	flows[p]["cnt"] = flows[p]["cnt"] + 1

stats = dict()
for i in range(0, n_pkts + 1, 1000):
	stats[i] = []
for key, value in flows.items():
	begin = value["begin"]
	begin = begin + 1000 - begin%1000
	if value["cnt"] >= thresh:
		for idx in range(begin, value["end"] + 1, 1000):
			stats[idx].append(value["cnt"])

with open("./test.txt", "w") as f:
	for i in range(0, n_pkts + 1, 1000):
		f.write(str(len(stats[i])) + "\n")
