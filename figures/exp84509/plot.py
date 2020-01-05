import json
import matplotlib.pyplot as plt
import matplotlib
#import np
from matplotlib.patches import Ellipse

font = {'size':18}
matplotlib.rc('font', **font)

src = "./results.caida.20180315-130000.json"

def func(are_lst, f1score_lst, item):
	are_lst.append(item["are"])
	f1score_lst.append(item["f1score"])
	return [are_lst, f1score_lst]

if __name__ == "__main__":
	with open(src, "r") as f:
		results = json.load(f)

	gammas = range(1, 11)
	n_promotions = []
	are_10 = []
	are_20 = []
	are_30 = []
	are_40 = []
	are_50 = []
	are_60 = []
	f1score_10 = []
	f1score_20 = []
	f1score_30 = []
	f1score_40 = []
	f1score_50 = []
	f1score_60 = []
	for gamma in gammas:
		npromotions.appdn(results[str(gamma)]["n_promotions"])
	for gamma in gammas:
		records = results[str(gamma)]
		n_promotions.append(records["n_promotions"])
		are_10.append(records["are"][10])
		f1score_10.append(records["f1score"]["10"])
		are_20.append(records["are"]["20"])
		f1score_20.append(records["f1score"]["20"])
		are_30.append(records["are"]["30"])
		f1score_30.append(records["f1score"]["30"])
		are_40.append(records["are"][40])
		f1score_40.append(records["f1score"]["40"])
		are_50.append(records["are"]["50"])
		f1score_50.append(records["f1score"]["50"])
		are_60.append(records["are"]["60"])
		f1score_60.append(records["f1score"]["60"])

	plt.figure(1)
#	plt.title("Heavy Hitters ARE")
#	plt.xticks(range(5), ("1M", "5M", "10M", "15M", "20M"))
#	plt.ylim(0, 1.05)
	plt.plot(gammas, are_10, label = "thresh=10", marker = "x", mfc="none")
	plt.plot(gammas, are_20, label = "thresh=20", marker = "s", mfc="none")
	plt.plot(gammas, are_30, label = "thresh=30", marker = "o", mfc="none")
	plt.plot(gammas, are_40, label = "thresh=40", marker = "1", mfc="none")
	plt.plot(gammas, are_50, label = "thresh=50", marker = "p", mfc="none")
	plt.plot(gammas, are_60, label = "thresh=60", marker = "d", mfc="none")
#	plt.plot(range(5), are_hw, label = "Hardware", marker = "o")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 2)
	plt.xlabel(r"$\gamma$")
	plt.ylabel("ARE")
	plt.savefig("are.pdf", bbox_inches = "tight")
	plt.savefig("are.png", bbox_inches = "tight")

	plt.figure(2)
#	plt.title("Heavy Hitters ARE")
#	plt.xticks(range(5), ("1M", "5M", "10M", "15M", "20M"))
#	plt.ylim(0, 1.05)
	plt.plot(gammas, f1score_10, label = "thresh=10", marker = "x", mfc="none")
	plt.plot(gammas, f1score_20, label = "thresh=20", marker = "s", mfc="none")
	plt.plot(gammas, f1score_30, label = "thresh=30", marker = "o", mfc="none")
	plt.plot(gammas, f1score_40, label = "thresh=40", marker = "1", mfc="none")
	plt.plot(gammas, f1score_50, label = "thresh=50", marker = "p", mfc="none")
	plt.plot(gammas, f1score_60, label = "thresh=60", marker = "d", mfc="none")
#	plt.plot(range(5), are_hw, label = "Hardware", marker = "o")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 3)
	plt.xlabel(r"$\gamma$")
	plt.ylabel("F1 Score")
	plt.savefig("f1score.pdf", bbox_inches = "tight")
	plt.savefig("f1score.png", bbox_inches = "tight")

	plt.figure(3)
#	plt.title("Heavy Hitters ARE")
#	plt.xticks(range(5), ("1M", "5M", "10M", "15M", "20M"))
#	plt.ylim(0, 1.05)
	plt.plot(gammas, n_promotions, label = "thresh=10", marker = "x", mfc="none")
#	plt.plot(range(5), are_hw, label = "Hardware", marker = "o")
#	plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
	plt.legend(loc = 3)
	plt.xlabel(r"$\gamma$")
	plt.ylabel("Num. of Promotions")
	plt.savefig("npromotions.pdf", bbox_inches = "tight")
	plt.savefig("npromotions.png", bbox_inches = "tight")
