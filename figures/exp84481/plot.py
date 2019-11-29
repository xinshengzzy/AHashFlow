import matplotlib.pyplot as plt
import numpy as np
import matplotlib

font = {'size':26}
matplotlib.rc('font', **font)

def parse_file(filename):
    n_hashes = []
    utilization = []
    with open(filename, "r") as f:
        for line in f:
            items = line.split(" ")
            n_hashes.append(int(items[0]))
            utilization.append(float(items[1]))
    return n_hashes, utilization

markersize = 18

n_hashes_1, util_1 = parse_file("./utilization_coe_1.txt")
n_hashes_2, util_2 = parse_file("./utilization_coe_2.txt")
n_hashes_3, util_3 = parse_file("./utilization_coe_3.txt")
n_hashes_4, util_4 = parse_file("./utilization_coe_4.txt")

sim_n_hashes_1, sim_util_1 = parse_file("./sim_utilization_coe_1.txt")
sim_n_hashes_2, sim_util_2 = parse_file("./sim_utilization_coe_2.txt")
sim_n_hashes_3, sim_util_3 = parse_file("./sim_utilization_coe_3.txt")
sim_n_hashes_4, sim_util_4 = parse_file("./sim_utilization_coe_4.txt")



plt.figure(1)
#plt.plot(n_hashes, utilization, marker = "o", markersize=10)
print(util_1)
print(sim_util_1)
print(util_2)
print(sim_util_2)
print(util_3)
print(sim_util_3)
print(util_4)
print(sim_util_4)
plt.xticks(range(1,11), ("1", "2", "3", "4", "5", "6", "7", "8", "9", "10"))
line_1, = plt.plot(n_hashes_1, util_1, label = "theo", marker = "H", markerfacecolor = "none", markersize=markersize, color = "blue")
line_2, = plt.plot(n_hashes_2, util_2, label = "theo", marker = "s", markerfacecolor = "none", markersize=markersize, color = "blue")
line_3, = plt.plot(n_hashes_3, util_3, label = "theo", marker = "D", markerfacecolor = "none", markersize=markersize, color = "blue")
line_4, = plt.plot(n_hashes_4, util_4, label = "theo", marker = "o", markerfacecolor = "none", markersize=markersize, color = "blue")

sim_line_1, = plt.plot(sim_n_hashes_1, sim_util_1, label = "sim m/n=1", marker = "x", markerfacecolor = "none", markersize=markersize, color = "red")
sim_line_2, = plt.plot(sim_n_hashes_2, sim_util_2, label = "sim m/n=2", marker = "+", markerfacecolor = "none", markersize=markersize, color = "red")
sim_line_3, = plt.plot(sim_n_hashes_3, sim_util_3, label = "sim m/n=3", marker = "*", markerfacecolor = "none", markersize=markersize, color = "red")
sim_line_4, = plt.plot(sim_n_hashes_4, sim_util_4, label = "sim m/n=4", marker = "|", markerfacecolor = "none", markersize=markersize, color = "red")

#plt.plot(range(10), alpha4, label = r"$\alpha$=0.4", marker = "o", markersize=10)
#plt.plot(range(10), alpha5, label = r"$\alpha$=0.5", marker = "<", markersize=10)
#plt.plot(range(10), alpha6, label = r"$\alpha$=0.6", marker = ">", markersize=10)
#plt.plot(range(10), alpha7, label = r"$\alpha$=0.7", marker = "v", markersize=10)
#plt.plot(range(10), alpha8, label = r"$\alpha$=0.8", marker = "^", markersize=10)
#plt.plot(range(10), alpha9, label = r"$\alpha$=0.9", marker = "h", markersize=10)
#plt.plot(range(10), alpha10, label = r"$\alpha$=1.0", marker = "s", markersize=10)
plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
#plt.legend(handles = [line_1, line_2, line_3, line_4], loc = 1)
#plt.legend(handles = [sim_line_1, sim_line_2, sim_line_3, sim_line_4], loc = 4)
#plt.legend(loc = 3, ncol = 2, mode = "expand")
plt.xlabel("Num. of Hashes")
plt.ylabel("Utilization")
plt.ylim(0.5, 1.05)
plt.savefig("hash_table_utilization.pdf", bbox_inches = "tight")
plt.savefig("hash_table_utilization.png", bbox_inches = "tight")
plt.savefig("hash_table_utilization.eps", bbox_inches = "tight")
#plt.show()

