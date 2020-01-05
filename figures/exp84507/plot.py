import json
import matplotlib.pyplot as plt
import matplotlib
#import np
from matplotlib.patches import Ellipse

font = {'size':18}
matplotlib.rc('font', **font)

src1 = "./cdf.caida.20180315-125910.json"
src2 = "./cdf.caida.20180315-130000.json"
src3 = "./cdf.hgc.20080415000.json"
src4 = "./cdf.hgc.20080415001.json"
src5 = "./zipf_dist_1.json"
src6 = "./zipf_dist_2.json"

if __name__ == "__main__":
	with open(src1, "r") as f:
		[idx1, cdf1] = json.load(f)
	with open(src2, "r") as f:
		[idx2, cdf2] = json.load(f)
	with open(src3, "r") as f:
		[idx3, cdf3] = json.load(f)
	with open(src4, "r") as f:
		[idx4, cdf4] = json.load(f)
	with open(src5, "r") as f:
		[idx5, cdf5] = json.load(f)
	with open(src6, "r") as f:
		[idx6, cdf6] = json.load(f)

	plt.figure(1)
#	plt.title("Heavy Hitters ARE")
#	plt.xticks(range(5), ("1M", "5M", "10M", "15M", "20M"))
	plt.ylim(0, 1.05)
	plt.plot(idx1, cdf1, label = "CAIDA1", marker = "x", mfc="none")
	plt.plot(idx2, cdf2, label = "CAIDA2", marker = "s", mfc="none")
	plt.plot(idx3, cdf3, label = "ISP1", marker = "o", mfc="none")
	plt.plot(idx4, cdf4, label = "ISP2", marker = "1", mfc="none")
	plt.plot(idx5, cdf5, label = "zipf1", marker = "p", mfc="none")
	plt.plot(idx6, cdf6, label = "zipf2", marker = "d", mfc="none")
#	plt.plot(range(5), are_hw, label = "Hardware", marker = "o")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 4)
	plt.xlabel("Proportion of Flows")
	plt.ylabel("Proportion of Packets")
	plt.savefig("cdf.pdf", bbox_inches = "tight")
	plt.savefig("cdf.png", bbox_inches = "tight")
