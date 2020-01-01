import json
import matplotlib.pyplot as plt
import matplotlib
#import np
from matplotlib.patches import Ellipse

font = {'size':18}
matplotlib.rc('font', **font)

sw = "res_for_sw_impl.json"
hw = "res_for_hw_impl.json"

def func(src):
	thresholds = []
	hh_are = []
	hh_f1score = []
	n_exports = []
	with open(src, "r") as f:
		for line in f:
			if "#" == line[0]:
				continue
			items = line.split("\t")
			thresholds.append(int(items[0]))	
			hh_are.append(float(items[1]))
			hh_f1score.append(float(items[2]))
			n_exports.append(float(items[3]))
	return [thresholds, hh_are, hh_f1score, n_exports]

if __name__ == "__main__":
	with open(hw, "r") as f:
		res_hw = json.load(f)
	with open(sw, "r") as f:
		res_sw = json.load(f)
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
