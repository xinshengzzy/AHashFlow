import json
import matplotlib.pyplot as plt
import matplotlib
from matplotlib.patches import Ellipse
import numpy as np

font = {'size':18}
matplotlib.rc('font', **font)

src = "./res.caida.13000.json"
thresh = 30

def func(alg, n):
	ae = []
	are = []
	f1score = []
	n_promotions = []
	for gamma in range(5, 11):
		filename = ".".join([alg, "n", str(n), "gamma", str(gamma), "caida.130000.json"])
		with open(filename, "r") as f:
			res = json.load(f)
			n_promotions.append(res["n_promotions"]/100000.0)
			ae.append(res["ae"][str(thresh)])
			are.append(res["are"][str(thresh)])
			f1score.append(res["f1score"][str(thresh)])
	return are, f1score, n_promotions


if __name__ == "__main__":
	are_ahf_n1, f1score_ahf_n1, npromotions_ahf_n1 = func("ahf", 1)
	are_ahf_n2, f1score_ahf_n2, npromotions_ahf_n2 = func("ahf", 2)
	are_ahf_n4, f1score_ahf_n4, npromotions_ahf_n4 = func("ahf", 4)
	
	are_ehf_n1, f1score_ehf_n1, npromotions_ehf_n1 = func("ehf", 1)
	are_ehf_n2, f1score_ehf_n2, npromotions_ehf_n2 = func("ehf", 2)
	are_ehf_n4, f1score_ehf_n4, npromotions_ehf_n4 = func("ehf", 4)

	print("npromotions_ahf_n1:")
	print(npromotions_ahf_n1)
	print("npromotions_ahf_n2:")
	print(npromotions_ahf_n2)
	print("npromotions_ahf_n4:")
	print(npromotions_ahf_n4)
	print("npromotions_ehf_n1:")
	print(npromotions_ehf_n1)

	gamma = range(5, 11)
	plt.figure(1)
	plt.ylim(0, 0.6)
	plt.plot(gamma, are_ahf_n1, label="AHF(N=1)", marker = "x", mfc="none")
	plt.plot(gamma, are_ahf_n2, label="AHF(N=2)", marker = "s", mfc="none")
	plt.plot(gamma, are_ahf_n4, label="AHF(N=4)", marker = "o", mfc="none")
	plt.plot(gamma, are_ehf_n1, label="EHF(N=1)", marker = "1", mfc="none")
#	plt.plot(gamma, are_ehf_n2, label="EHF(N=2)", marker = "p", mfc="none")
#	plt.plot(gamma, are_ehf_n4, label="EHF(N=4)", marker = "d", mfc="none")
	plt.legend(loc = 1, ncol=2)
	plt.xlabel(r"$\gamma$")
	plt.ylabel("ARE")
	plt.savefig("are.pdf", bbox_inches="tight")
	plt.savefig("are.png", bbox_inches="tight")

	plt.figure(2)
	plt.ylim(0.5, 1.0)
	plt.plot(gamma, f1score_ahf_n1, label="AHF(N=1)", marker = "x", mfc="none")
	plt.plot(gamma, f1score_ahf_n2, label="AHF(N=2)", marker = "s", mfc="none")
	plt.plot(gamma, f1score_ahf_n4, label="AHF(N=4)", marker = "o", mfc="none")
	plt.plot(gamma, f1score_ehf_n1, label="EHF(N=1)", marker = "1", mfc="none")
#	plt.plot(gamma, f1score_ehf_n2, label="EHF(N=2)", marker = "p", mfc="none")
#	plt.plot(gamma, f1score_ehf_n4, label="EHF(N=4)", marker = "d", mfc="none")
	plt.legend(loc = 4, ncol=2)
	plt.xlabel(r"$\gamma$")
	plt.ylabel("F1 Score")
	plt.savefig("f1score.pdf", bbox_inches="tight")
	plt.savefig("f1score.png", bbox_inches="tight")

	plt.figure(3)
	plt.ylim(0, 10)
	plt.plot(gamma, npromotions_ahf_n1, label="AHF(N=1)", marker = "x", mfc="none")
	plt.plot(gamma, npromotions_ahf_n2, label="AHF(N=2)", marker = "s", mfc="none")
	plt.plot(gamma, npromotions_ahf_n4, label="AHF(N=4)", marker = "o", mfc="none")
	plt.plot(gamma, npromotions_ehf_n1, label="EHF(N=1)", marker = "1", mfc="none")
#	plt.plot(gamma, npromotions_ehf_n2, label="EHF(N=2)", marker = "p", mfc="none")
#	plt.plot(gamma, npromotions_ehf_n4, label="EHF(N=4)", marker = "d", mfc="none")
	plt.legend(loc = 1, ncol=2)
	plt.xlabel(r"$\gamma$")
	plt.ylabel(r"Num. of Promotions($\times 10^5$)")
	plt.savefig("npromotions.pdf", bbox_inches="tight")
	plt.savefig("npromotions.png", bbox_inches="tight")
