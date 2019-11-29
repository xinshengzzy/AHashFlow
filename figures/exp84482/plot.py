import matplotlib.pyplot as plt
import numpy as np
import matplotlib

font = {'size':18}
matplotlib.rc('font', **font)


n_hashes = []
utilization = []
with open("result_84482.txt", "r") as f:
    for line in f:
        items = line.split(" ")
        n_hashes.append(int(items[0]))
        utilization.append(float(items[1]))

plt.figure(1)
plt.plot(n_hashes, utilization, marker = "x", markersize=10, color = "blue")
plt.xticks(range(1000,10001, 1000), ("1K", "2K", "3K", "4K", "5K", "6K", "7K", "8K", "9K", "10K"))
#plt.plot(range(10), basic, label = "Basic", marker = "x", markersize=10)
#plt.plot(range(10), alpha3, label = r"$\alpha$=0.3", marker = "*", markersize=10)
#plt.plot(range(10), alpha4, label = r"$\alpha$=0.4", marker = "o", markersize=10)
#plt.plot(range(10), alpha5, label = r"$\alpha$=0.5", marker = "<", markersize=10)
#plt.plot(range(10), alpha6, label = r"$\alpha$=0.6", marker = ">", markersize=10)
#plt.plot(range(10), alpha7, label = r"$\alpha$=0.7", marker = "v", markersize=10)
#plt.plot(range(10), alpha8, label = r"$\alpha$=0.8", marker = "^", markersize=10)
#plt.plot(range(10), alpha9, label = r"$\alpha$=0.9", marker = "h", markersize=10)
#plt.plot(range(10), alpha10, label = r"$\alpha$=1.0", marker = "s", markersize=10)
#plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 3, mode = "expand", borderaxespad = 0.0)
plt.xlabel("Num. of Flows")
plt.ylabel("ARE")
plt.savefig("count_min_sketch_are.pdf", bbox_inches = "tight")
plt.savefig("count_min_sketch_are.png", bbox_inches = "tight")
#plt.show()

