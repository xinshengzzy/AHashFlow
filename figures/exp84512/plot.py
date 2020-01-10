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
	fig = plt.figure(1)
	params = ["2", "4", "8", "16", "32"]
	n_promotions = []
	aes = []
	f1score1 = []
	f1score2 = []
	for key in params:
		n_promotions.append(res[key]["n_promotions"])
		aes.append(res[key]["ae"])
		f1score1.append(res[key]["f1score1"])
		f1score2.append(res[key]["f1score2"])
	for i in range(5):
		print "param:", params[i], ", n_promotions:", n_promotions[i], ", ae:", aes[i], "f1score1:", f1score1[i], ", f1score2:", f1score2[i]
	exit()
	ax = fig.add_axes([0,0,1,1])
#	ax.set_xlim([0,7])
#	ax.set_ylim([0,8])
	plt.bar(np.arange(1, 6) - 0.25, n_promotions, color = 'r', width = 0.25)
	plt.bar(np.arange(1, 6), aes, color = 'b', width = 0.25)
	plt.xlabel("Parameter")
#	plt.ylabel(r"Num. of Recirculationss($\times 10^{5}$)")
	plt.xticks(range(1, 6), ("2", "4", "8", "16", "32"))
	rects = ax.patches
	labels = [str(item) for item in n_promotions]
	for rect, label in zip(rects, labels):
		height = rect.get_height()
		ax.text(rect.get_x() + rect.get_width() / 2, height + 0.1, label,
				ha='center', va='bottom')
#	for rect, label in zip(rects, algs):
#		height = rect.get_height()
#		ax.text(rect.get_x() + rect.get_width() / 2, height + 0.5, label,
#				ha='center', va='bottom')
	plt.savefig("npromotions.pdf", bbox_inches = "tight")
	plt.savefig("npromotions.png", bbox_inches = "tight")

