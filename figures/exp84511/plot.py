import json
import matplotlib.pyplot as plt
import matplotlib
from matplotlib.patches import Ellipse
import numpy as np

font = {'size':18}
matplotlib.rc('font', **font)

src1 = "./dhf.results.caida.20180315-130000.json"
src2 = "./ahf.results.caida.20180315-130000.json"

def func(res, gamma):
	thresh = ["10", "20", "30", "40", "50", "60"]
	are = []
	f1score = []
	n_promotions = res[gamma]["n_promotions"]
	for item in thresh:
		tmp1 = res[gamma]["are"][item]
		tmp2 = res[gamma]["f1score"][item]
		are.append(tmp1)
		f1score.append(tmp2)
	return are, f1score, n_promotions

if __name__ == "__main__":
	with open(src1, "r") as f:
		res1 = json.load(f)
	with open(src2, "r") as f:
		res2 = json.load(f)
	
	are0, f1score0, n0 = func(res2, "4")
	are1, f1score1, n1 = func(res2, "5")
	are2, f1score2, n2 = func(res1, "2")
	are3, f1score3, n3 = func(res1, "3")
	are4, f1score4, n4 = func(res1, "4")
	are5, f1score5, n5 = func(res1, "5")

	thresh = [10, 20, 30, 40, 50, 60]
	plt.figure(1)
#	plt.title("Heavy Hitters ARE")
#	plt.xticks(range(5), ("1M", "5M", "10M", "15M", "20M"))
	plt.ylim(0, 1.05)
	plt.plot(thresh, are0, label = "AHF-4", marker = "x", mfc="none")
	plt.plot(thresh, are1, label = "AHF-5", marker = "s", mfc="none")
	plt.plot(thresh, are2, label = "DHF-2", marker = "o", mfc="none")
	plt.plot(thresh, are3, label = "DHF-3", marker = "1", mfc="none")
	plt.plot(thresh, are4, label = "DHF-4", marker = "p", mfc="none")
	plt.plot(thresh, are5, label = "DHF-5", marker = "d", mfc="none")
#	plt.plot(range(5), are_hw, label = "Hardware", marker = "o")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 1)
	plt.xlabel("Threshold")
	plt.ylabel("ARE")
	plt.savefig("are.pdf", bbox_inches = "tight")
	plt.savefig("are.png", bbox_inches = "tight")
	

	plt.figure(2)
#	plt.title("Heavy Hitters ARE")
#	plt.xticks(range(5), ("1M", "5M", "10M", "15M", "20M"))
	plt.ylim(0, 1.05)
	plt.plot(thresh, f1score0, label = "AHF-4", marker = "x", mfc="none")
	plt.plot(thresh, f1score1, label = "AHF-5", marker = "s", mfc="none")
	plt.plot(thresh, f1score2, label = "DHF-2", marker = "o", mfc="none")
	plt.plot(thresh, f1score3, label = "DHF-3", marker = "1", mfc="none")
	plt.plot(thresh, f1score4, label = "DHF-4", marker = "p", mfc="none")
	plt.plot(thresh, f1score5, label = "DHF-5", marker = "d", mfc="none")
#	plt.plot(range(5), are_hw, label = "Hardware", marker = "o")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 3)
	plt.xlabel("Threshold")
	plt.ylabel("F1 Score")
	plt.savefig("f1score.pdf", bbox_inches = "tight")
	plt.savefig("f1score.png", bbox_inches = "tight")

	fig = plt.figure(3)
	n_promotions = [n0, n1, n2, n3, n4, n5]
	for i in range(len(n_promotions)):
		n_promotions[i] = n_promotions[i]/100000.0
	ax = fig.add_axes([0,0,1,1])
	ax.set_xlim([0,7])
	ax.set_ylim([0,10])
	plt.bar(np.arange(1, 7) - 0.25, n_promotions, color = 'r', width = 0.5)
	plt.xlabel("Settings")
	plt.ylabel(r"Num. of Promotions($\times 10^{5}$)")
	plt.xticks(range(1, 7), ("AHF-4", "AHF-5", "DHF-2", "DHF-3", "DHF-4", "DHF-5"))
	rects = ax.patches
	labels = [str(item) for item in n_promotions]
	for rect, label in zip(rects, labels):
		height = rect.get_height()
		ax.text(rect.get_x() + rect.get_width() / 2, height + 0.1, label,
				ha='center', va='bottom')
	plt.savefig("npromotions.pdf", bbox_inches = "tight")
	plt.savefig("npromotions.png", bbox_inches = "tight")

