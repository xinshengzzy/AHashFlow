import json
import matplotlib.pyplot as plt
import matplotlib
#import np
from matplotlib.patches import Ellipse

font = {'size':18}
matplotlib.rc('font', **font)

src1 = "./nflows.caida.20180315-125910.json"
src2 = "./nflows.caida.20180315-130000.json"
src3 = "./nflows.hgc.20080415000.json"
src4 = "./nflows.hgc.20080415001.json"

def devide(nflows, c):
	for i in range(len(nflows)):
		nflows[i] = nflows[i]/c
	return nflows

if __name__ == "__main__":
	c = 10000.0
	with open(src1, "r") as f:
		nflows1 = json.load(f)
		nflows1 = devide(nflows1, c)
	with open(src2, "r") as f:
		nflows2 = json.load(f)
		nflows2 = devide(nflows2, c)
	with open(src3, "r") as f:
		nflows3 = json.load(f)
		nflows3 = devide(nflows3, c)
	with open(src4, "r") as f:
		nflows4 = json.load(f)
		nflows4 = devide(nflows4, c)

	plt.figure(1)
#	plt.title("Heavy Hitters ARE")
#	plt.xticks(range(5), ("1M", "5M", "10M", "15M", "20M"))
#	plt.ylim(0, 1.05)
	plt.plot(nflows1, label = "CAIDA1", marker = "x", mfc="none")
	plt.plot(nflows2, label = "CAIDA2", marker = "s", mfc="none")
	plt.plot(nflows3, label = "ISP1", marker = "o", mfc="none")
	plt.plot(nflows4, label = "ISP2", marker = "1", mfc="none")
#	plt.plot(range(5), are_hw, label = "Hardware", marker = "o")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 4)
	plt.ylabel("Nun. of Active Flows (X10000)")
	plt.xlabel("Time/Sec")
	plt.savefig("nflows.pdf", bbox_inches = "tight")
	plt.savefig("nflows.png", bbox_inches = "tight")
