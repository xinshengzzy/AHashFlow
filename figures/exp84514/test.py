import json

src = "./ahf.n.2.gamma.5.caida.130000.json"
with open(src, "r") as f:
	res = json.load(f)

print "n_promotions:", res["n_promotions"]
for thresh in range(10, 101, 10):
	ae = res["ae"][str(thresh)]
	are = res["are"][str(thresh)]
	f1score = res["f1score"][str(thresh)]
	print "thresh:%d, ae:%.3f, are:%.3f, f1score:%.3f" % (thresh, ae, are, f1score)
