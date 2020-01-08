import json
import matplotlib.pyplot as plt
import matplotlib
from matplotlib.patches import Ellipse
import numpy as np

font = {'size':18}
matplotlib.rc('font', **font)

src1 = "./caida.13000.dhf.json"
src2 = "./caida.13000.ahf.n.2.json"
src3 = "./caida.13000.ahf.n.4.json"
src4 = "./caida.13000.ahf.n.8.json"

def func(res, gamma):
	thresh = [str(item) for item in range(10, 101, 10)]
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
	with open(src3, "r") as f:
		res3 = json.load(f)
	with open(src4, "r") as f:
		res4 = json.load(f)

	idx = 9
	thresh = range(10, 101, 10)
	print "thresh=", thresh[idx]
	print "DHashFlow:"
	for gamma in range(1, 11):
		are, f1score, n = func(res1, str(gamma))
		print "gamma:", gamma, ", n_promotions:", n, ", are:", are[idx], ", f1score:", f1score[idx]

	print "AHashFlow (N=2):"
	for gamma in range(2, 11):
		are, f1score, n = func(res2, str(gamma))
		print "gamma:", gamma, ", n_promotions:", n, ", are:", are[idx], ", f1score:", f1score[idx]

	print "AHashFlow (N=4):"
	for gamma in range(4, 11):
		are, f1score, n = func(res3, str(gamma))
		print "gamma:", gamma, ", n_promotions:", n, ", are:", are[idx], ", f1score:", f1score[idx]

	print "AHashFlow (N=8):"
	for gamma in range(8, 11):
		are, f1score, n = func(res4, str(gamma))
		print "gamma:", gamma, ", n_promotions:", n, ", are:", are[idx], ", f1score:", f1score[idx]
	are0, f1score0, n0 = func(res1, "3")
	are1, f1score1, n1 = func(res1, "4")
	are2, f1score2, n2 = func(res1, "5")
	are3, f1score3, n3 = func(res3, "5")
	are4, f1score4, n4 = func(res3, "6")
	are5, f1score5, n5 = func(res3, "7")

#	print "are0:", are0, ", f1score0:", f1score0
#	print "are3:", are3, ", f1score3:", f1score3
	are_dhf = are2
	f1score_dhf = f1score2
	are_ahf = are5
	f1score_ahf = f1score5
	for i in range(10):
		print "thresh:", (i+1)*10, ", are:", are_dhf[i] - are_ahf[i], ", f1score:", f1score_ahf[i] - f1score_dhf[i]
	print "are:", are_dhf[9], are_ahf[9]
	print "f1score:", f1score_dhf[9], f1score_ahf[9]

	thresh = range(10, 101, 10)
	plt.figure(1)
#	plt.title("Heavy Hitters ARE")
#	plt.xticks(range(5), ("1M", "5M", "10M", "15M", "20M"))
	plt.xlim(8, 102)
	plt.ylim(0, 0.65)
	plt.plot(thresh, are0, label = r"DHF.$\gamma$.3", marker = "x", mfc="none")
	plt.plot(thresh, are1, label = r"DHF.$\gamma$.4", marker = "s", mfc="none")
	plt.plot(thresh, are2, label = r"DHF.$\gamma$.5", marker = "o", mfc="none")
	plt.plot(thresh, are3, label = r"AHF.$\gamma$.5", marker = "1", mfc="none")
	plt.plot(thresh, are4, label = r"AHF.$\gamma$.6", marker = "p", mfc="none")
	plt.plot(thresh, are5, label = r"AHF.$\gamma$.7", marker = "d", mfc="none")
#	plt.plot(range(5), are_hw, label = "Hardware", marker = "o")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 1, ncol=2)
	plt.xlabel("Threshold")
	plt.ylabel("ARE")
	plt.savefig("are.pdf", bbox_inches = "tight")
	plt.savefig("are.png", bbox_inches = "tight")
	

	plt.figure(2)
#	plt.title("Heavy Hitters ARE")
#	plt.xticks(range(5), ("1M", "5M", "10M", "15M", "20M"))
	plt.xlim(8, 102)
	plt.ylim(0.6, 1)
	plt.plot(thresh, f1score0, label = r"DHF.$\gamma$.3", marker = "x", mfc="none")
	plt.plot(thresh, f1score1, label = r"DHF.$\gamma$.4", marker = "s", mfc="none")
	plt.plot(thresh, f1score2, label = r"DHF.$\gamma$.5", marker = "o", mfc="none")
	plt.plot(thresh, f1score3, label = r"AHF.$\gamma$.5", marker = "1", mfc="none")
	plt.plot(thresh, f1score4, label = r"AHF.$\gamma$.6", marker = "p", mfc="none")
	plt.plot(thresh, f1score5, label = r"AHF.$\gamma$.7", marker = "d", mfc="none")
#	plt.plot(range(5), are_hw, label = "Hardware", marker = "o")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 4)
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
	ax.set_ylim([0,8])
	plt.bar(np.arange(1, 7) - 0.25, n_promotions, color = 'r', width = 0.5)
	plt.xlabel("Settings")
	plt.ylabel(r"Num. of Recirculationss($\times 10^{5}$)")
	plt.xticks(range(1, 7), (r"DHF.$\gamma$.3", r"DHF.$\gamma$.4", r"DHF.$\gamma$.5", r"AHF.$\gamma$.5", r"AHF.$\gamma$.6", r"AHF.$\gamma$.7"))
	rects = ax.patches
	labels = [str(item) for item in n_promotions]
	algs = ["DHF", "DHF", "DHF", "AHF", "AHF", "AHF"]
	for rect, label in zip(rects, labels):
		height = rect.get_height()
		ax.text(rect.get_x() + rect.get_width() / 2, height + 0.1, label,
				ha='center', va='bottom')
#	for rect, label in zip(rects, algs):
#		height = rect.get_height()
#		ax.text(rect.get_x() + rect.get_width() / 2, height + 0.5, label,
#				ha='center', va='bottom')
	plt.savefig("npromotions.pdf", bbox_inches = "tight")
	plt.savefig("npromotions.png", bbox_inches = "tight")

