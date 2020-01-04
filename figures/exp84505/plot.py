import json
import matplotlib.pyplot as plt
import matplotlib
#import np
from matplotlib.patches import Ellipse

font = {'size':18}
matplotlib.rc('font', **font)

sw = "res_for_sw_impl.json"
hw = "res_for_hw_impl.json"

src1 = "./cdf.caida.20180315-125910.json"
src2 = "./cdf.caida.20180315-130000.json"
src3 = "./cdf.hgc.20080415000.json"
src4 = "./cdf.hgc.20080415001.json"

if __name__ == "__main__":
	with open(src1, "r") as f:
		cdf1 = json.load(f)
	with open(src2, "r") as f:
		cdf2 = json.load(f)
	with open(src3, "r") as f:
		cdf3 = json.load(f)
	with open(src4, "r") as f:
		cdf4 = json.load(f)
	are_sw = []
	are_hw = []
	f1score_sw = []
	f1score_hw = []
	n_pkts = ["1000000", "5000000", "10000000", "15000000", "20000000"]
	for key in n_pkts:
		are_sw.append(res_sw[key]["hh_are"])
		f1score_sw.append(res_sw[key]["hh_f1score"])
		are_hw.append(res_hw[key]["hh_are"])
		f1score_hw.append(res_hw[key]["hh_f1score"])

	plt.figure(1)
#	plt.title("Heavy Hitters ARE")
	plt.xticks(range(5), ("1M", "5M", "10M", "15M", "20M"))
	plt.plot(range(5), are_sw, label = "Software", marker = "x")
	plt.plot(range(5), are_hw, label = "Hardware", marker = "o")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 1)
	plt.xlabel("Num. of Replayed Packets")
	plt.ylabel("ARE")
	plt.savefig("hh_are.pdf", bbox_inches = "tight")
	plt.savefig("hh_are.png", bbox_inches = "tight")

	plt.figure(2)
#	plt.title("Heavy Hitters ARE")
	plt.xticks(range(5), ("1M", "5M", "10M", "15M", "20M"))
	plt.plot(range(5), f1score_sw, label = "Software", marker = "x")
	plt.plot(range(5), f1score_hw, label = "Hardware", marker = "o")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 1)
	plt.xlabel("Num. of Replayed Packets")
	plt.ylabel("ARE")
	plt.savefig("hh_are.pdf", bbox_inches = "tight")
	plt.savefig("hh_are.png", bbox_inches = "tight")
