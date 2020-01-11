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
		filename = ".".join([alg, "n", str(n), "gamma", str(gamma), "caida.130000.json"])
		with open(filename, "r") as f:
			res = json.load(f)
			n_promotions.append(res["n_promotions"])
			ae.append(res["ae"][str(thresh)])
			are.append(res["are"][str(thresh)])
			f1score.append(res["f1score"][str(thresh)])
	return are, f1score


if __name__ == "__main__":
	are_ahf_n1, f1score_ahf_n1 = func("ahf", 1)
	are_ahf_n2, f1score_ahf_n2 = func("ahf", 2)
#	are_ahf_n4, f1score_ahf_n4 = func("ahf", 4)
	
	are_ehf_n1, f1score_ehf_n1 = func("ehf", 1)
	are_ehf_n2, f1score_ehf_n2 = func("ehf", 2)
#	are_ehf_n4, f1score_ehf_n4 = func("ehf", 4)

	gamma = range(4, 11)
	plt.figure(1)
	plt.ylim(0, 1.0)
	plt.plot(gamma, are_ahf_n1, label="AHF(N=1)", marker = "x", mfc="none")
	plt.plot(gamma, are_ahf_n2, label="AHF(N=2)", marker = "s", mfc="none")
#	plt.plot(gamma, are_ahf_n3, label="AHF(N=3)", marker = "o", mfc="none")
	plt.plot(gamma, are_ehf_n1, label="EHF(N=1)", marker = "1", mfc="none")
	plt.plot(gamma, are_ehf_n2, label="EHF(N=2)", marker = "p", mfc="none")
#	plt.plot(gamma, are_ehf_n3, label="EHF(N=3)", marker = "d", mfc="none")
	plt.legend(loc = 1)
	plt.xlabel(r"$\gamma$")
	plt.ylabel("ARE")
	plt.savefig("are.pdf", bbox_inches="tight")
	plt.savefig("are.png", bbox_inches="tight")
