import json

src1 = "./caida.hh.ae.13000.dhf.json"
src2 = "./caida.hh.ae.13000.ahf.n.2.json"
src3 = "./caida.hh.ae.13000.ahf.n.4.json"
src4 = "./caida.hh.ae.13000.ahf.n.8.json"
src5 = "./caida.hh.ae.13000.ahf.n.16.json"

def func(src):
	with open(src, "r") as f:
		res = json.load(f)
	return res["n_promotions"], res["hh_ae"]

if "__main__" == __name__:
	n1, ae1 = func(src1)
	n2, ae2 = func(src2)
	n3, ae3 = func(src3)
	n4, ae4 = func(src4)
	n5, ae5 = func(src5)

	def myfunc(thresh):
		print "thresh:", thresh
		print "DHF:", "n_promotions:", n1, ", ae:", ae1[str(thresh)]
		print "AH F(n=2):", "n_promotions:", n2, ", ae:", ae2[str(thresh)]
		print "AH F(n=4):", "n_promotions:", n3, ", ae:", ae3[str(thresh)]
		print "AH F(n=8):", "n_promotions:", n4, ", ae:", ae4[str(thresh)]
		print "AH F(n=16):", "n_promotions:", n5, ", ae:", ae5[str(thresh)]

	for thresh in range(10, 101, 10):
		myfunc(thresh)

