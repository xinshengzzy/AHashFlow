import json
import matplotlib.pyplot as plt
import matplotlib
#import np
from matplotlib.patches import Ellipse

font = {'size':18}
matplotlib.rc('font', **font)

a1 = "./result.scheme.1.caida.20180315-130000.json"
a2 = "./result.scheme.2.caida.20180315-130000.json"
a3 = "./result.scheme.3.caida.20180315-130000.json"
a4 = "./result.scheme.4.caida.20180315-130000.json"
a5 = "./result.scheme.5.caida.20180315-130000.json"


m1 = "./result.scheme.12.caida.20180315-130000.json"
m2 = "./result.scheme.13.caida.20180315-130000.json"
m3 = "./result.scheme.3.caida.20180315-130000.json"
m4 = "./result.scheme.14.caida.20180315-130000.json"
m5 = "./result.scheme.15.caida.20180315-130000.json"

def func(filename):
	with open(filename, "r") as f:
		res = json.load(f)
	are = []
	f1score = []
	for key in range(10, 101, 10):
		key = str(key)
		are.append(res["are"][key])
		f1score.append(res["f1score"][key])
	return [are, f1score]

if __name__ == "__main__":
	thresh = range(10, 101, 10)

	are1, f1score1 = func(a1)
	are2, f1score2 = func(a2)
	are3, f1score3 = func(a3)
	are4, f1score4 = func(a4)
	are5, f1score5 = func(a5)

	plt.figure(1)
#	plt.title("Heavy Hitters ARE")
#	plt.xticks(range(5), ("1M", "5M", "10M", "15M", "20M"))
	plt.ylim(0, 1)
	plt.plot(thresh, are1, label = "scheme 1", marker = "x", mfc="none")
	plt.plot(thresh, are2, label = "scheme 2", marker = "s", mfc="none")
	plt.plot(thresh, are3, label = "scheme 3", marker = "o", mfc="none")
	plt.plot(thresh, are4, label = "scheme 4", marker = "1", mfc="none")
	plt.plot(thresh, are5, label = "scheme 5", marker = "p", mfc="none")
#	plt.plot(range(5), are_hw, label = "Hardware", marker = "o")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 1)
	plt.xlabel(r"Threshold")
	plt.ylabel("ARE")
	plt.savefig("a_table_are.pdf", bbox_inches = "tight")
	plt.savefig("a_table_are.png", bbox_inches = "tight")

	plt.figure(2)
#	plt.title("Heavy Hitters ARE")
#	plt.xticks(range(5), ("1M", "5M", "10M", "15M", "20M"))
	plt.ylim(0, 1)
	plt.plot(thresh, f1score1, label = "scheme 1", marker = "x", mfc="none")
	plt.plot(thresh, f1score2, label = "scheme 2", marker = "s", mfc="none")
	plt.plot(thresh, f1score3, label = "scheme 3", marker = "o", mfc="none")
	plt.plot(thresh, f1score4, label = "scheme 4", marker = "1", mfc="none")
	plt.plot(thresh, f1score5, label = "scheme 5", marker = "p", mfc="none")
#	plt.plot(range(5), are_hw, label = "Hardware", marker = "o")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 4)
	plt.xlabel("Threshold")
	plt.ylabel("F1 Score")
	plt.savefig("a_table_f1score.pdf", bbox_inches = "tight")
	plt.savefig("a_table_f1score.png", bbox_inches = "tight")

	are1, f1score1 = func(m1)
	are2, f1score2 = func(m2)
	are3, f1score3 = func(m3)
	are4, f1score4 = func(m4)
	are5, f1score5 = func(m5)

	plt.figure(3)
#	plt.title("Heavy Hitters ARE")
#	plt.xticks(range(5), ("1M", "5M", "10M", "15M", "20M"))
	plt.ylim(0, 1)
	plt.plot(thresh, are1, label = "scheme 12", marker = "x", mfc="none")
	plt.plot(thresh, are2, label = "scheme 13", marker = "s", mfc="none")
	plt.plot(thresh, are3, label = "scheme 3", marker = "o", mfc="none")
	plt.plot(thresh, are4, label = "scheme 14", marker = "1", mfc="none")
	plt.plot(thresh, are5, label = "scheme 15", marker = "p", mfc="none")
#	plt.plot(range(5), are_hw, label = "Hardware", marker = "o")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 1)
	plt.xlabel(r"Threshold")
	plt.ylabel("ARE")
	plt.savefig("m_table_are.pdf", bbox_inches = "tight")
	plt.savefig("m_table_are.png", bbox_inches = "tight")

	plt.figure(4)
#	plt.title("Heavy Hitters ARE")
#	plt.xticks(range(5), ("1M", "5M", "10M", "15M", "20M"))
	plt.ylim(0, 1)
	plt.plot(thresh, f1score1, label = "scheme 12", marker = "x", mfc="none")
	plt.plot(thresh, f1score2, label = "scheme 13", marker = "s", mfc="none")
	plt.plot(thresh, f1score3, label = "scheme 3", marker = "o", mfc="none")
	plt.plot(thresh, f1score4, label = "scheme 14", marker = "1", mfc="none")
	plt.plot(thresh, f1score5, label = "scheme 15", marker = "p", mfc="none")
#	plt.plot(range(5), are_hw, label = "Hardware", marker = "o")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 4)
	plt.xlabel("Threshold")
	plt.ylabel("F1 Score")
	plt.savefig("m_table_f1score.pdf", bbox_inches = "tight")
	plt.savefig("m_table_f1score.png", bbox_inches = "tight")
