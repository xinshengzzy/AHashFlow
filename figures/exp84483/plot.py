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

alpha = []
hierarchical_utilization = []
normal_utilization = []
with open("result_hierarchical_84483.txt", "r") as f:
    for line in f:
        items = line.split(" ")
        alpha.append(float(items[0]))
        hierarchical_utilization.append(float(items[1]))
with open("result_normal_84483.txt", "r") as f:
    line = f.readline()
    temp = float(line)
    for i in range(10):
        normal_utilization.append(temp)

plt.figure(1)
#plt.xticks(range(10), ("#1", "#2", "#3", "#3", "#5", "#6", "#7", "#8", "#9", "#10"))
plt.xticks([0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0])
plt.plot(alpha, hierarchical_utilization, label = "Hierarchical", marker = "x", markersize=10, color = "blue")
plt.plot(alpha, normal_utilization, label = "Normal", markersize=10, color = "red")
#plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
plt.legend(loc = 3)
plt.xlabel(r"$\alpha$")
plt.ylabel("Utilization")
plt.ylim(0,1)
plt.savefig("hash_table_utilization.pdf", bbox_inches = "tight")
plt.savefig("hash_table_utilization.png", bbox_inches = "tight")
#plt.show()

