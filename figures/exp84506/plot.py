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

len_max = 30

if __name__ == "__main__":
	with open(src1, "r") as f:
		cdf1 = json.load(f)
		len1 = len(cdf1)
		print "len1:", len1
		if len1 > len_max:
			len1 = len_max
	with open(src2, "r") as f:
		cdf2 = json.load(f)
		len2 = len(cdf2)
		print "len1:", len1
		if len2 > len_max:
			len2 = len_max
	with open(src3, "r") as f:
		cdf3 = json.load(f)
		len3 = len(cdf3)
		print "len1:", len1
		if len3 > len_max:
			len3 = len_max
	with open(src4, "r") as f:
		cdf4 = json.load(f)
		len4 = len(cdf4)
		print "len1:", len1
		if len4 > len_max:
			len4 = len_max


	plt.figure(1)
#	plt.title("Heavy Hitters ARE")
#	plt.xticks(range(5), ("1M", "5M", "10M", "15M", "20M"))
	plt.ylim(0, 1.05)
	plt.plot(range(len1), cdf1[0: len1], label = "CAIDA1", marker = "x", mfc="none")
	plt.plot(range(len2), cdf2[0: len2], label = "CAIDA2", marker = "s", mfc="none")
	plt.plot(range(len3), cdf3[0: len3], label = "ISP1", marker = "o", mfc="none")
	plt.plot(range(len4), cdf4[0: len4], label = "ISP2", marker = "1", mfc="none")
#	plt.plot(range(5), are_hw, label = "Hardware", marker = "o")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 4)
	plt.xlabel("Flow Size/pkts")
	plt.ylabel("CDF")
	plt.savefig("cdf.pdf", bbox_inches = "tight")
	plt.savefig("cdf.png", bbox_inches = "tight")
