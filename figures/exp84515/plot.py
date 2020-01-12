import json
import matplotlib.pyplot as plt
import matplotlib
from matplotlib.patches import Ellipse
import numpy as np

font = {'size':18}
matplotlib.rc('font', **font)

are_30 = []
are_40 = []
are_50 = []
are_60 = []
are_70 = []
are_80 = []
f1score_30 = []
f1score_40 = []
f1score_50 = []
f1score_60 = []
f1score_70 = []
f1score_80 = []
n_promotions = []

def 提取(文件名):
	with open(文件名, "r") as f:
		数据 = json.load(f)
	n_promotions.append(数据["n_promotions"])
	are_30.append(数据["are"]["30"])
	are_40.append(数据["are"]["40"])
	are_50.append(数据["are"]["50"])
	are_60.append(数据["are"]["60"])
	are_70.append(数据["are"]["70"])
	are_80.append(数据["are"]["80"])
	f1score_30.append(数据["f1score"]["30"])
	f1score_40.append(数据["f1score"]["40"])
	f1score_50.append(数据["f1score"]["50"])
	f1score_60.append(数据["f1score"]["60"])
	f1score_70.append(数据["f1score"]["70"])
	f1score_80.append(数据["f1score"]["80"])

if __name__ == "__main__":
	for gamma in range(4, 21):
		文件名= "ehf.n.1.gamma.%d.caida.130000.json" % gamma
		提取(文件名)

	print("are_30:")
	print(are_30)

	gamma = range(4, 21)
	plt.figure(1)
	plt.ylim(0, 0.6)
	plt.plot(gamma, are_30, label="thresh=30", marker = "x", mfc="none")
	plt.plot(gamma, are_40, label="thresh=40", marker = "s", mfc="none")
	plt.plot(gamma, are_50, label="thresh=50", marker = "o", mfc="none")
	plt.plot(gamma, are_60, label="thresh=60", marker = "1", mfc="none")
	plt.plot(gamma, are_70, label="thresh=70", marker = "p", mfc="none")
	plt.plot(gamma, are_80, label="thresh=80", marker = "d", mfc="none")
	plt.legend(loc = 1, ncol=2)
	plt.xlabel(r"$\gamma$")
	plt.ylabel("ARE")
	plt.savefig("are.pdf", bbox_inches="tight")
	plt.savefig("are.png", bbox_inches="tight")

	plt.figure(2)
	plt.ylim(0.5, 1.0)
	plt.plot(gamma, f1score_30, label="thresh=30", marker = "x", mfc="none")
	plt.plot(gamma, f1score_40, label="thresh=40", marker = "s", mfc="none")
	plt.plot(gamma, f1score_50, label="thresh=50", marker = "o", mfc="none")
	plt.plot(gamma, f1score_60, label="thresh=60", marker = "1", mfc="none")
	plt.plot(gamma, f1score_70, label="thresh=70", marker = "p", mfc="none")
	plt.plot(gamma, f1score_80, label="thresh=80", marker = "d", mfc="none")
	plt.legend(loc = 4, ncol=2)
	plt.xlabel(r"$\gamma$")
	plt.ylabel("F1 Score")
	plt.savefig("f1score.pdf", bbox_inches="tight")
	plt.savefig("f1score.png", bbox_inches="tight")

	n_promotions = [item/100000.0 for item in n_promotions]
	fig = plt.figure(3)
	ax = fig.add_axes([0,0,1,1])
	ax.set_xlim([3,20.5])
	plt.bar(np.arange(4, 21), n_promotions, color = 'r', width = 0.5)
	plt.xlabel(r"$\gamma$")
	plt.ylabel(r"Num. of Packets($\times 10^{5}$)")
	plt.xticks(range(4, 21, 2), [str(item) for item in range(4, 21, 2)])
	rects = ax.patches
	labels = ["%.2f" % item for item in n_promotions]
	for rect, label in zip(rects, labels):
		height = rect.get_height()
	plt.savefig("npromotions.pdf", bbox_inches = "tight")
	plt.savefig("npromotions.png", bbox_inches = "tight")

