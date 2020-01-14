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

阈值 = "70"

def 提取(gamma, 数据包数, 平均相对误差, f1score):
	文件名 = ".".join(["ehf", "gamma", str(gamma), "npkts", str(数据包数), "caida.130000.json"])
	with open(文件名, "r") as f:
		数据 = json.load(f)
	平均相对误差.append(数据["are"][阈值])
	f1score.append(数据["f1score"][阈值])
	return 平均相对误差, f1score

if __name__ == "__main__":
	for 数据包数 in range(5, 26, 2):
		数据包数 = 数据包数*(10**6)
		are_4, f1score_4 = 提取(4, 数据包数, are_4, f1score_4)
		are_6, f1score_6 = 提取(6, 数据包数, are_6, f1score_6)
		are_8, f1score_8 = 提取(8, 数据包数, are_8, f1score_8)
		are_10, f1score_10 = 提取(10, 数据包数, are_10, f1score_10)
		are_12, f1score_12 = 提取(12, 数据包数, are_12, f1score_12)
		are_14, f1score_14 = 提取(14, 数据包数, are_14, f1score_14)

	数据包数 = range(5, 26, 2)
	plt.figure(1)
	plt.ylim(0, 0.5)
	plt.plot(数据包数, are_4, label=r"$\gamma=4$", marker = "x", mfc="none")
	plt.plot(数据包数, are_6, label=r"$\gamma=6$", marker = "s", mfc="none")
	plt.plot(数据包数, are_8, label=r"$\gamma=8$", marker = "o", mfc="none")
	plt.plot(数据包数, are_10, label=r"$\gamma=10$", marker = "1", mfc="none")
	plt.plot(数据包数, are_12, label=r"$\gamma=12$", marker = "p", mfc="none")
	plt.plot(数据包数, are_14, label=r"$\gamma=14$", marker = "d", mfc="none")
	plt.legend(loc = 1, ncol=2)
	plt.xlabel(r"Num. of Packets($\times 10^6$)")
	plt.ylabel("ARE")
	plt.savefig("are.pdf", bbox_inches="tight")
	plt.savefig("are.png", bbox_inches="tight")

	plt.figure(2)
	plt.ylim(0.5, 1.0)
	plt.plot(数据包数, f1score_4, label=r"$\gamma=4$", marker = "x", mfc="none")
	plt.plot(数据包数, f1score_6, label=r"$\gamma=6$", marker = "s", mfc="none")
	plt.plot(数据包数, f1score_8, label=r"$\gamma=8$", marker = "o", mfc="none")
	plt.plot(数据包数, f1score_10, label=r"$\gamma=10$", marker = "1", mfc="none")
	plt.plot(数据包数, f1score_12, label=r"$\gamma=12$", marker = "p", mfc="none")
	plt.plot(数据包数, f1score_14, label=r"$\gamma=14$", marker = "d", mfc="none")
	plt.legend(loc = 4, ncol=2)
	plt.xlabel(r"Num. of Packets($\times 10^6$)")
	plt.ylabel("F1 Score")
	plt.savefig("f1score.pdf", bbox_inches="tight")
	plt.savefig("f1score.png", bbox_inches="tight")

