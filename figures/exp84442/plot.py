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

with open("data.txt", "r") as f:
    f.readline() # drop the first line
    basic = convert(f.readline())[1:]
    alpha1 = convert(f.readline())[1:]
    alpha2 = convert(f.readline())[1:]
    alpha3 = convert(f.readline())[1:]
    alpha4 = convert(f.readline())[1:]
    alpha5 = convert(f.readline())[1:]
    alpha6 = convert(f.readline())[1:]
    alpha7 = convert(f.readline())[1:]
    alpha8 = convert(f.readline())[1:]
    alpha9 = convert(f.readline())[1:]
    alpha10 = convert(f.readline())[1:]
plt.figure(1)
plt.xticks(range(10), ("#1", "#2", "#3", "#3", "#5", "#6", "#7", "#8", "#9", "#10"))
plt.plot(range(10), basic, label = "Basic", marker = "x", markersize=10)
plt.plot(range(10), alpha3, label = r"$\alpha$=0.3", marker = "*", markersize=10)
plt.plot(range(10), alpha4, label = r"$\alpha$=0.4", marker = "o", markersize=10)
plt.plot(range(10), alpha5, label = r"$\alpha$=0.5", marker = "<", markersize=10)
plt.plot(range(10), alpha6, label = r"$\alpha$=0.6", marker = ">", markersize=10)
plt.plot(range(10), alpha7, label = r"$\alpha$=0.7", marker = "v", markersize=10)
plt.plot(range(10), alpha8, label = r"$\alpha$=0.8", marker = "^", markersize=10)
plt.plot(range(10), alpha9, label = r"$\alpha$=0.9", marker = "h", markersize=10)
plt.plot(range(10), alpha10, label = r"$\alpha$=1.0", marker = "s", markersize=10)
plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 3, mode = "expand", borderaxespad = 0.0)
plt.xlabel("Trace File")
plt.ylabel("Cache Hit Ratio")
plt.savefig("hash_table_comparison.pdf", bbox_inches = "tight")
plt.savefig("hash_table_comparison.png", bbox_inches = "tight")
#plt.show()

