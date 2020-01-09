import json

src10 = "./caida.13000.ahf.n.2.json"
src11 = "./caida.13000.ahf.n.2.json.1"
dst1 = "./caida.13000.ahf.n.2.json.2"
src20 = "./caida.13000.ahf.n.4.json"
src21 = "./caida.13000.ahf.n.4.json.1"
dst2 = "./caida.13000.ahf.n.4.json.2"
src30 = "./caida.13000.ahf.n.8.json"
src31 = "./caida.13000.ahf.n.8.json.1"
dst3 = "./caida.13000.ahf.n.8.json.2"
src40 = "./caida.13000.dhf.json"
src41 = "./caida.13000.dhf.json.1"
dst4 = "./caida.13000.dhf.json.2"
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
	func(src20, src21, dst2)
	func(src30, src31, dst3)
	func(src40, src41, dst4)
