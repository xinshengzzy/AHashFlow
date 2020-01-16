from simulators.ZipfTrafficGenerator import Zipf流量生成器

流量生成器 = Zipf流量生成器(80000, 20, 1.2, 100000)
print("包序列长度：%d" % len(流量生成器.包序列))
