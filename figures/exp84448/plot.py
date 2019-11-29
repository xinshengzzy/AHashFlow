import matplotlib.pyplot as plt
import numpy as np
import matplotlib

font = {'size':18}
matplotlib.rc('font', **font)


def mean(l):
    return float(sum(l))/max(len(l), 1)

def convert(l):
    items = l.split(" ")
    lst = []
    for item in items:
        lst.append(float(item))
    return lst
n_flows = []
basic = []
alpha6 = []
alpha7 = []
alpha8 = []

with open("data.txt", "r") as f:
    for line in f:
        if "#" == line[0]:
            continue
        items = line.split(" ")
        n_flows.append(int(items[0]))
        basic.append(float(items[1]))
        alpha6.append(float(items[2]))
        alpha7.append(float(items[3]))
        alpha8.append(float(items[4]))
            
plt.figure(1)
plt.xticks(range(20000, 220001, 40000), ("20K", "60K", "100K", "140K", "180K", "220K"))
plt.plot(n_flows, basic, label = "Basic", marker = "x", markersize=10)
plt.plot(n_flows, alpha6, label = r"$\alpha$=0.6", marker = ">", markersize=10)
plt.plot(n_flows, alpha7, label = r"$\alpha$=0.7", marker = "v", markersize=10)
plt.plot(n_flows, alpha8, label = r"$\alpha$=0.8", marker = "^", markersize=10)
plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
plt.xlabel("Num. of Concurrent Flows")
plt.ylabel("Cache Hit Ratio")
plt.savefig("hash_table_comparison.pdf", bbox_inches = "tight")
plt.savefig("hash_table_comparison.png", bbox_inches = "tight")
#plt.show()

