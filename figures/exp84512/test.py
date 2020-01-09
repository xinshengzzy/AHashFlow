import json

src10 = "./caida.13000.ahf.n.2.json"
src11 = "./caida.13000.ahf.n.2.json.1"
dst1 = "./caida.13000.ahf.n.2.json.2"

def func(src1, src2, dst):
	with open(src1, "r") as f:
		res1 = json.load(f)
	with open(src2, "r") as f:
		res2 = json.load(f)
	res = dict()
	for key, value in res1.items():
		res[key] = value
	for key, value in res2.items():
		res[key] = value
	with open(dst, "w") as f:
		json.dump(res, f)
	

if "__main__" == __name__:
	func(src10, src11, dst1)
