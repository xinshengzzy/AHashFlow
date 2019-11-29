import json
import matplotlib.pyplot as plt
import matplotlib
import matplotlib
#import np
from matplotlib.patches import Ellipse

font = {'size':18}
matplotlib.rc('font', **font)


caida1 = "./resForCAIDA1.txt"
caida2 = "./resForCAIDA2.txt"
hgc1 = "./resForHGC1.txt"
hgc2 = "./resForHGC2.txt"

def func(dataFile):
	with open(dataFile, "r") as f:
		l = json.load(f)
#	max_size = 0
#	for item in l:
#		if item[0] > max_size:
#			max_size = item[0]
	xdc = [0]*101
	flow_size = []
#	flow_size = [0]*(max_size + 1)
	for item in l:
		flow_size.append(item[0])
		for i in range(100, -1, -1):
			if item[1] <= i*0.01:
				xdc[i] = xdc[i] + 1
			else:
				break
	flow_size.sort()
	cdf = range(1, len(flow_size) + 1)
	for i in range(len(flow_size)):
		cdf[i] = float(cdf[i])/len(flow_size)
#		for i in range(max_size, -1, -1):
#			if item[0] <= i:
#				flow_size[i] = flow_size[i] + 1
#			else:
#				break
	for i in range(101):
		xdc[i] = float(xdc[i])/len(l)
#	for i in range(max_size + 1):
#		flow_size[i] = float(flow_size[i])/len(l)
	return xdc, [flow_size, cdf]

if __name__ == "__main__":
	xdc1, flow_size1	= func(caida1)
	xdc2, flow_size2 = func(caida2)
	xdc3, flow_size3 = func(hgc1)
	xdc4, flow_size4 = func(hgc2)
	plt.figure(1)
	plt.title("x=0.95")
	plt.xticks(range(0, 101, 10), ("0", "0.1", "0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9", "1.0"))
	plt.plot(range(101), xdc1, label = "CAIDA1", marker = "x")
	plt.plot(range(101), xdc2, label = "CAIDA2", marker = "o")
	plt.plot(range(101), xdc3, label = "HGC1", marker = "^")
	plt.plot(range(101), xdc4, label = "HGC2", marker = "s")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 2)
	plt.xlabel("x-Dist Coefficient")
	plt.ylabel("CDF")
	plt.savefig("xdc4.pdf", bbox_inches = "tight")
	plt.savefig("xdc4.png", bbox_inches = "tight")
	
#	flows = flow_size1[0]
#	thresh = 5
#	cnt = 0
#	for item in flows:
#		if item <= thresh:
#	cnt = cnt + 1
#	print "ratio:", float(cnt)/len(flows)
#	flows.sort()
#	for item in flows:
#		print item
#	plt.figure(2)
#	plt.plot(flow_size1[0], flow_size1[1], label = "CAIDA1", marker = "x")
#	plt.plot(flow_size2[0], flow_size2[1], label = "CAIDA2", marker = "x")
#	plt.plot(flow_size3[0], flow_size3[1], label = "HGC1", marker = "^")
#	plt.plot(flow_size4[0], flow_size4[1], label = "HGC2", marker = "^")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
#	plt.xlabel("x-Dist Coefficient")
#	plt.ylabel("CDF")
#	plt.savefig("flow_size.pdf", bbox_inches = "tight")
#	plt.savefig("flow_size.png", bbox_inches = "tight")
