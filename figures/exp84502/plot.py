import json
import matplotlib.pyplot as plt
import matplotlib
import matplotlib
#import np
from matplotlib.patches import Ellipse

font = {'size':18}
matplotlib.rc('font', **font)

src1 = "./CAIDA1.json"
src2 = "./CAIDA2.json"
src3 = "./HGC1.json"
src4 = "./HGC2.json"

def func(src):
	with open(src, "r") as f:
		idx, cdf = json.load(f)
	delta = len(idx)/50
	idx2 = []
	cdf2 = []
	for i in range(0, len(idx), delta):
		idx2.append(idx[i])
		cdf2.append(cdf[i])
	return idx2, cdf2

if __name__ == "__main__":
	idx1, cdf1 = func(src1)
	idx2, cdf2 = func(src2)
	idx3, cdf3 = func(src3)
	idx4, cdf4 = func(src4)
	plt.figure(1)
#	plt.title("x=0.95")
#	plt.xticks(range(0, 101, 10), ("0", "0.1", "0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9", "1.0"))
	plt.plot(idx1, cdf1, label = "CAIDA1", marker = "x")
	plt.plot(idx2, cdf2, label = "CAIDA2", marker = "o")
	plt.plot(idx3, cdf3, label = "HGC1", marker = "s")
	plt.plot(idx4, cdf4, label = "HGC2", marker = "*")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 4)
	plt.ylim(0, 1.0)
	plt.xlim(-100000, 5000000)
	plt.xlabel("Span")
	plt.ylabel("CDF")
	plt.savefig("cdf.pdf", bbox_inches = "tight")
	plt.savefig("cdf.png", bbox_inches = "tight")

	exit()
	plt.figure(2)
#	plt.title("x=0.95")
#	plt.xticks(range(0, 101, 10), ("0", "0.1", "0.2", "0.3", "0.4", "0.5", "0.6", "0.7", "0.8", "0.9", "1.0"))
	plt.plot(range(5, 51, 5), res_ahf[2], label = "AHashFlow", marker = "x")
	plt.plot(range(5, 51, 5), res_chf[2], label = "CHashFlow", marker = "o")
	plt.plot(range(5, 51, 5), res_tf[2], label = "Turboflow", marker = "s")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 4)
	plt.xlabel("Threshold")
	plt.ylabel("F1 Score")
	plt.savefig("hh_f1score.pdf", bbox_inches = "tight")
	plt.savefig("hh_f1score.png", bbox_inches = "tight")
	
