import json
import matplotlib.pyplot as plt
import matplotlib
from matplotlib.patches import Ellipse
import numpy as np

font = {'size':18}
matplotlib.rc('font', **font)

are_4 = []
are_6 = []
are_8 = []
are_10 = []
are_12 = []
are_14 = []
f1score_4 = []
f1score_6 = []
f1score_8 = []
f1score_10 = []
f1score_12 = []
f1score_14 = []

阈值 = "60"

def 提取(gamma, 数据包数, 平均相对误差, f1score):
	文件名 = ".".join(["ehf", "gamma", str(gamma), "npkts", str(数据包数), "caida.130000.json"])
	with open(文件名, "r") as f:
		数据 = json.load(f)
	平均相对误差.append(数据["are"][阈值])
	f1score.append(数据["f1score"][阈值])
	return 平均相对误差, f1score

if __name__ == "__main__":
	for 数据包数 in range(5, 26, 5):
		数据包数 = 数据包数*(10**6)
		are_4, f1score_4 = 提取(4, 数据包数, are_4, f1score_4)
		are_6, f1score_6 = 提取(6, 数据包数, are_6, f1score_6)
		are_8, f1score_8 = 提取(8, 数据包数, are_8, f1score_8)
		are_10, f1score_10 = 提取(10, 数据包数, are_10, f1score_10)
		are_12, f1score_12 = 提取(12, 数据包数, are_12, f1score_12)
#		are_14, f1score_14 = 提取(14, 数据包数, are_14, f1score_14)

	print("are_4:")
	for 项 in are_4:
		print("%.3f" % 项)
	print("f1score_4:")
	for 项 in f1score_4:
		print("%.3f" % 项)
	exit()

	print("thresh=30")
	for gamma in range(4, 21):
		索引 = gamma - 4
		print("gamma=%d, are=%.3f, f1score=%.3f, n_promotions=%d" % (gamma, are_30[索引], f1score_30[索引], n_promotions[索引]))
	print("thresh=70")
	for gamma in range(4, 21):
		索引 = gamma - 4
		print("gamma=%d, are=%.3f, f1score=%.3f" % (gamma, are_70[索引], f1score_70[索引]))
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

