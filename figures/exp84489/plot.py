import matplotlib.pyplot as plt
import numpy as np
import matplotlib

font = {'size':26}
matplotlib.rc('font', **font)
markersize=18

def parse_file(filename):
    depth = []
    util_5 = []
    util_6 = []
    util_7 = []
    util_8 = []
    util_9 = []
    util_10 = []
    with open(filename, "r") as f:
        for line in f:
            if "#" == line[0]:
                continue
            items = line.split(" ")
            depth.append(int(items[0]))
            util_5.append(float(items[1]))
            util_6.append(float(items[2]))
            util_7.append(float(items[3]))
            util_8.append(float(items[4]))
            util_9.append(float(items[5]))
            util_10.append(float(items[6]))
    return depth, util_5, util_6, util_7, util_8, util_9, util_10


if "__main__" == __name__:
    ########## m/n=1.0 ##########
    theo_depth, theo_util_5, theo_util_6, theo_util_7, theo_util_8, theo_util_9, theo_util_10 = parse_file("./utilization_theory_ratio_10.txt")
    sim_depth, sim_util_5, sim_util_6, sim_util_7, sim_util_8, sim_util_9, sim_util_10 = parse_file("./utilization_simulation_ratio_10.txt")

    plt.figure(1)
    plt.xticks(range(1,11), ("1", "2", "3", "4", "5", "6", "7", "8", "9", "10"))
    line_1, = plt.plot(theo_depth, theo_util_5, label = r"theo", marker = "H", markerfacecolor = "none", markersize=markersize, color = "blue")
    line_2, = plt.plot(theo_depth, theo_util_6, label = r"theo", marker = "s", markerfacecolor = "none", markersize=markersize, color = "blue")
    line_3, = plt.plot(theo_depth, theo_util_7, label = r"theo", marker = "D", markerfacecolor = "none", markersize=markersize, color = "blue")
    line_4, = plt.plot(theo_depth, theo_util_8, label = r"theo", marker = "o", markerfacecolor = "none", markersize=markersize, color = "blue")
#    line_4, = plt.plot(theo_depth, theo_util_9, label = r"theo $\alpha$=0.9", marker = "^", markerfacecolor = "none", markersize=10, color = "blue")
#    line_4, = plt.plot(theo_depth, theo_util_10, label = r"theo $\alpha$=1.0", marker = "p", markerfacecolor = "none", markersize=10, color = "blue")

    sim_line_1, = plt.plot(sim_depth, sim_util_5, label = r"sim $\alpha$=0.5", marker = "x", markerfacecolor = "none", markersize=markersize, color = "red")
    sim_line_2, = plt.plot(sim_depth, sim_util_6, label = r"sim $\alpha$=0.6", marker = "+", markerfacecolor = "none", markersize=markersize, color = "red")
    sim_line_3, = plt.plot(sim_depth, sim_util_7, label = r"sim $\alpha$=0.7", marker = "*", markerfacecolor = "none", markersize=markersize, color = "red")
    sim_line_4, = plt.plot(sim_depth, sim_util_8, label = r"sim $\alpha$=0.8", marker = "|", markerfacecolor = "none", markersize=markersize, color = "red")
#    sim_line_4, = plt.plot(sim_depth, sim_util_9, label = r"sim $\alpha$=0.9", marker = ".", markerfacecolor = "none", markersize=10, color = "red")
#    sim_line_4, = plt.plot(sim_depth, sim_util_10, label = r"sim $\alpha$=1.0", marker = ",", markerfacecolor = "none", markersize=10, color = "red")

#    plt.legend(loc = 3, ncol = 2, mode = "expand")
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.text(5, 0.6, "m/n=1.0")
    plt.xlabel("Num. of Hashes")
    plt.ylabel("Utilization")
    plt.ylim(0.5, 1.05)
#    plt.title("m/n=1.0")
    plt.savefig("pipelined_tables_utilization_ratio_10.pdf", bbox_inches = "tight")
    plt.savefig("pipelined_tables_utilization_ratio_10.png", bbox_inches = "tight")
    plt.savefig("pipelined_tables_utilization_ratio_10.eps", bbox_inches = "tight")
    plt.close()

    ########## m/n=2.0 ##########
    theo_depth, theo_util_5, theo_util_6, theo_util_7, theo_util_8, theo_util_9, theo_util_10 = parse_file("./utilization_theory_ratio_20.txt")
    sim_depth, sim_util_5, sim_util_6, sim_util_7, sim_util_8, sim_util_9, sim_util_10 = parse_file("./utilization_simulation_ratio_20.txt")

    plt.figure(1)
    plt.xticks(range(1,11), ("1", "2", "3", "4", "5", "6", "7", "8", "9", "10"))
    line_1, = plt.plot(theo_depth, theo_util_5, label = r"theo", marker = "H", markerfacecolor = "none", markersize=markersize, color = "blue")
    line_2, = plt.plot(theo_depth, theo_util_6, label = r"theo", marker = "s", markerfacecolor = "none", markersize=markersize, color = "blue")
    line_3, = plt.plot(theo_depth, theo_util_7, label = r"theo", marker = "D", markerfacecolor = "none", markersize=markersize, color = "blue")
    line_4, = plt.plot(theo_depth, theo_util_8, label = r"theo", marker = "o", markerfacecolor = "none", markersize=markersize, color = "blue")
#    line_4, = plt.plot(theo_depth, theo_util_9, label = r"theo $\alpha$=0.9", marker = "^", markerfacecolor = "none", markersize=10, color = "blue")
#    line_4, = plt.plot(theo_depth, theo_util_10, label = r"theo $\alpha$=1.0", marker = "p", markerfacecolor = "none", markersize=10, color = "blue")

    sim_line_1, = plt.plot(sim_depth, sim_util_5, label = r"sim $\alpha$=0.5", marker = "x", markerfacecolor = "none", markersize=markersize, color = "red")
    sim_line_2, = plt.plot(sim_depth, sim_util_6, label = r"sim $\alpha$=0.6", marker = "+", markerfacecolor = "none", markersize=markersize, color = "red")
    sim_line_3, = plt.plot(sim_depth, sim_util_7, label = r"sim $\alpha$=0.7", marker = "*", markerfacecolor = "none", markersize=markersize, color = "red")
    sim_line_4, = plt.plot(sim_depth, sim_util_8, label = r"sim $\alpha$=0.8", marker = "|", markerfacecolor = "none", markersize=markersize, color = "red")
#    sim_line_4, = plt.plot(sim_depth, sim_util_9, label = r"sim $\alpha$=0.9", marker = ".", markerfacecolor = "none", markersize=10, color = "red")
#    sim_line_4, = plt.plot(sim_depth, sim_util_10, label = r"sim $\alpha$=1.0", marker = ",", markerfacecolor = "none", markersize=10, color = "red")

#    plt.legend(loc = 3, ncol = 2, mode = "expand")
    plt.text(5, 0.6, "m/n=2.0")
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Num. of Hashes")
    plt.ylabel("Utilization")
    plt.ylim(0.5, 1.05)
#    plt.title("m/n=2.0")
    plt.savefig("pipelined_tables_utilization_ratio_20.pdf", bbox_inches = "tight")
    plt.savefig("pipelined_tables_utilization_ratio_20.png", bbox_inches = "tight")
    plt.savefig("pipelined_tables_utilization_ratio_20.eps", bbox_inches = "tight")
    plt.close()
