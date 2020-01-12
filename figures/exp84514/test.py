import json

def func(src):
	with open(src, "r") as f:
		res = json.load(f)

	print("n_promotions:", res["n_promotions"])
	for thresh in range(10, 101, 10):
		ae = res["ae"][str(thresh)]
		are = res["are"][str(thresh)]
		f1score = res["f1score"][str(thresh)]
		print("thresh:%d, ae:%.3f, are:%.3f, f1score:%.3f" % (thresh, ae, are, f1score))

n = 2
gamma = 4
print("AHashFlow: n=%d, gamma=%d" % (n, gamma))
filename = "./ahf.n.%d.gamma.%d.caida.130000.json" % (n, gamma)
func(filename)

gamma = 9
print("EHashFlow: gamma=%d" % gamma)
filename = "./ehf.n.1.gamma.%d.caida.130000.json" % gamma
func(filename)
