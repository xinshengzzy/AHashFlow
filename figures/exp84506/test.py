import json
filename1 = "./cdf.caida.20180315-125910.json"
filename2 = "./cdf.caida.20180315-130000.json"
filename3 = "./cdf.hgc.20080415000.json"
filename4 = "./cdf.hgc.20080415001.json"
with open(filename4, "r") as f:
	l = json.load(f)

length = len(l)
for i in range(1, length):
	print (1.0 - l[i])/(1.0 - l[i - 1])

