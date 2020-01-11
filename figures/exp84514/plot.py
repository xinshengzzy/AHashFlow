import json
import matplotlib.pyplot as plt
import matplotlib
from matplotlib.patches import Ellipse
import numpy as np

font = {'size':18}
matplotlib.rc('font', **font)

src = "./res.caida.13000.json"
thresh = 20

def func(alg, n):
	ae = []
	are = []
	f1score = []
	n_promotions = []
	for gamma in range(4, 11):
		filename = ".".join([alg, "n", str(n), "gamma", "caida.130000.json"])
		with open(filename, "r") as f:
			res = json.load(f)
			n_promotions.append(res["n_promotions"])
			ae.append(res["ae"][str(thresh)])
			are.append(res["are"][str(thresh)])
			f1score.append(res["f1score"][str(thresh)])
	return are, f1score


if __name__ == "__main__":
	are_ahf_n1, f1score_ahf_n1 = func("ahf", 1)
	print "are:", are_ahf_n1
	print "f1score:", f1score_ahf_n1
	exit()

	with open(src, "r") as f:
		res = json.load(f)
	Ns = ["8", "16", "32", "64", "128", "256"]
	n_promotions = []
	AE1 = []
	AE2 = []
	for key in Ns:
		n_promotions.append(res[key]["n_promotions"])
		AE1.append(res[key]["ae1"])
		AE2.append(res[key]["ae2"])
		print "n:", key, ", npromotions:", res[key]["n_promotions"], ", ae1:", res[key]["ae1"], ", ae2:", res[key]["ae2"]

	fig = plt.figure(1)
	ax = fig.add_axes([0,0,1,1])
	ax.set_xlim([0,7])
#	ax.set_ylim([0,8])
	plt.bar(np.arange(1, 7) - 0.25, AE2, color = 'r', width = 0.5)
	plt.xlabel("N")
	plt.ylabel("AE")
	plt.xticks(range(1, 7), Ns)
	rects = ax.patches
	labels = [str(int(item*100)/100.0) for item in AE2]
	algs = ["DHF", "DHF", "DHF", "AHF", "AHF", "AHF"]
	for rect, label in zip(rects, labels):
		height = rect.get_height()
		ax.text(rect.get_x() + rect.get_width() / 2, height + 0.1, label,
				ha='center', va='bottom')
#	for rect, label in zip(rects, algs):
#		height = rect.get_height()
#		ax.text(rect.get_x() + rect.get_width() / 2, height + 0.5, label,
#				ha='center', va='bottom')
	plt.savefig("AE.pdf", bbox_inches = "tight")
	plt.savefig("AE.png", bbox_inches = "tight")

