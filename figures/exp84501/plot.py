import json
import matplotlib.pyplot as plt
import matplotlib
import matplotlib
#import np
from matplotlib.patches import Ellipse

font = {'size':18}
matplotlib.rc('font', **font)

src_ahf = "./ahf3.txt"
src_chf = "./chf3.txt"
src_tf = "./tf3.txt"

def func(src):
	npkts = []
	hh_are = []
	hh_f1score = []
	n_exports = []
	with open(src, "r") as f:
		for line in f:
			if "#" == line[0]:
				continue
			items = line.split("\t")
			npkts.append(int(items[0]))	
			hh_are.append(float(items[1]))
			hh_f1score.append(float(items[2]))
			n_exports.append(float(items[3])/int(items[0]))
	return [npkts, hh_are, hh_f1score, n_exports]

if __name__ == "__main__":
	res_ahf = func(src_ahf)
	res_chf = func(src_chf)
	res_tf = func(src_tf)
	plt.figure(1)
#	plt.title("x=0.95")
#	plt.xticks(range(0, 101, 10), ("0", "0.1", "0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9", "1.0"))
	plt.plot(range(1, 41), res_ahf[1], label = "AHashFlow", marker = "x")
	plt.plot(range(1, 41), res_chf[1], label = "CHashFlow", marker = "o")
	plt.plot(range(1, 41), res_tf[1], label = "TurboFlow", marker = "s")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 1)
	plt.ylim(0.0, 1.0)
	plt.xlabel("X500000 pkts")
	plt.ylabel("ARE")
	plt.savefig("hh_are_3.pdf", bbox_inches = "tight")
	plt.savefig("hh_are_3.png", bbox_inches = "tight")

	plt.figure(2)
#	plt.title("x=0.95")
#	plt.xticks(range(0, 101, 10), ("0", "0.1", "0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9", "1.0"))
	plt.plot(range(1, 41), res_ahf[2], label = "AHashFlow", marker = "x")
	plt.plot(range(1, 41), res_chf[2], label = "CHashFlow", marker = "o")
	plt.plot(range(1, 41), res_tf[2], label = "TurboFlow", marker = "s")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.ylim(0.5, 1.0)
	plt.legend(loc = 3)
	plt.xlabel("X500000 pkts")
	plt.ylabel("F1 Score")
	plt.savefig("hh_f1score_3.pdf", bbox_inches = "tight")
	plt.savefig("hh_f1score_3.png", bbox_inches = "tight")

	plt.figure(3)
#	plt.title("x=0.95")
#	plt.xticks(range(0, 101, 10), ("0", "0.1", "0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9", "1.0"))
	plt.plot(range(1, 41), res_ahf[3], label = "AHashFlow", marker = "x")
	plt.plot(range(1, 41), res_chf[3], label = "CHashFlow", marker = "o")
	plt.plot(range(1, 41), res_tf[3], label = "TurboFlow", marker = "s")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.ylim(0.0, 0.5)
	plt.legend(loc = 1)
	plt.xlabel("X500000 pkts")
	plt.ylabel("PLR")
	plt.savefig("plr_3.pdf", bbox_inches = "tight")
	plt.savefig("plr_3.png", bbox_inches = "tight")

