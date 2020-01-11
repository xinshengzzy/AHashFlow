import json
import matplotlib.pyplot as plt
import matplotlib
from matplotlib.patches import Ellipse
import numpy as np

font = {'size':18}
matplotlib.rc('font', **font)

src = "./res.caida.13000.json"

if __name__ == "__main__":
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

