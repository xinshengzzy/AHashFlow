import json
import matplotlib.pyplot as plt
import matplotlib
from matplotlib.patches import Ellipse
import numpy as np

font = {'size':18}
matplotlib.rc('font', **font)

n_pkts = 8*(10**6)

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
	are = []
	f1score = []
	for 阈值 in range(10, 101, 10):
		are.append(数据["are"][str(阈值)])
		f1score.append(数据["f1score"][str(阈值)])
	return are, f1score

if __name__ == "__main__":
	filename1 = ".".join(["hf", "npkts", str(n_pkts), "caida.130000.json"])
	filename2 = ".".join(["ghf", "npkts", str(n_pkts), "caida.130000.json"])
	hf_are, hf_f1score = 提取(filename1)
	ghf_are, ghf_f1score = 提取(filename2)
	thresh = range(10, 101, 10)
	print("HashFlow:")
	for 索引 in range(10):
		print("阈值=%d, are=%.3f, f1score=%.3f" % (thresh[索引], hf_are[索引], hf_f1score[索引]))
	print("GHashFlow:")
	for 索引 in range(10):
		print("阈值=%d, are=%.3f, f1score=%.3f" % (thresh[索引], ghf_are[索引], ghf_f1score[索引]))

	plt.figure(1)
	plt.ylim(0, 0.6)
	plt.plot(thresh, hf_are, label="HashFlow", marker = "x", mfc="none")
	plt.plot(thresh, ghf_are, label="GHashFlow", marker = "s", mfc="none")
#	plt.plot(gamma, are_50, label="thresh=50", marker = "o", mfc="none")
#	plt.plot(gamma, are_60, label="thresh=60", marker = "1", mfc="none")
#	plt.plot(gamma, are_70, label="thresh=70", marker = "p", mfc="none")
#	plt.plot(gamma, are_80, label="thresh=80", marker = "d", mfc="none")
	plt.legend(loc = 1, ncol=2)
	plt.xlabel("Threshold")
	plt.ylabel("ARE")
	plt.savefig("are.pdf", bbox_inches="tight")
	plt.savefig("are.png", bbox_inches="tight")

	plt.figure(2)
	plt.ylim(0.5, 1.0)
	plt.plot(thresh, hf_f1score, label="HashFlow", marker = "x", mfc="none")
	plt.plot(thresh, ghf_f1score, label="GHashFlow", marker = "s", mfc="none")
#	plt.plot(gamma, f1score_50, label="thresh=50", marker = "o", mfc="none")
#	plt.plot(gamma, f1score_60, label="thresh=60", marker = "1", mfc="none")
#	plt.plot(gamma, f1score_70, label="thresh=70", marker = "p", mfc="none")
#	plt.plot(gamma, f1score_80, label="thresh=80", marker = "d", mfc="none")
	plt.legend(loc = 4, ncol=2)
	plt.xlabel("Threshold")
	plt.ylabel("F1 Score")
	plt.savefig("f1score.pdf", bbox_inches="tight")
	plt.savefig("f1score.png", bbox_inches="tight")
	exit()
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

