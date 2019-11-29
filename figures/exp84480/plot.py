import matplotlib.pyplot as plt
import matplotlib
import matplotlib
import np
from matplotlib.patches import Ellipse

font = {'size':18}
matplotlib.rc('font', **font)


def parse_file(filename):
    filenames = []
    throughputs = []
    ave_mem_accesses = []
    ave_mem_accesses_basic = []
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            items = line.split(" ")
            if "filename:" == items[0]:
                filenames.append(items[1])
            if "throughput:" == items[0]:
                throughputs.append(float(items[1]))
            if "ave_mem_accesses:" == items[0]:
                ave_mem_accesses.append(float(items[1]))
            if "ave_mem_accesses_basic:" == items[0]:
                ave_mem_accesses_basic.append(float(items[1]))
    if 0 == len(ave_mem_accesses_basic):
        return filenames, throughputs, ave_mem_accesses
    else:
        return filenames, throughputs, ave_mem_accesses, ave_mem_accesses_basic
    

if __name__ == "__main__":
    d1_filenames, d1_throughputs, d1_ave_mem_accesses, d1_ave_mem_accesses_basic = parse_file("./result_hashflow_d1_84480.txt")
    d2_filenames, d2_throughputs, d2_ave_mem_accesses, d2_ave_mem_accesses_basic = parse_file("./result_hashflow_d2_84480.txt")
    d3_filenames, d3_throughputs, d3_ave_mem_accesses, d3_ave_mem_accesses_basic = parse_file("./result_hashflow_d3_84480.txt")
    d4_filenames, d4_throughputs, d4_ave_mem_accesses, d4_ave_mem_accesses_basic = parse_file("./result_hashflow_d4_84480.txt")

    plt.figure(1)
    plt.xticks(range(1, 11), ("#1", "#2", "#3", "#4", "#5", "#6", "#7", "#8", "#9", "#10"))
    plt.plot(range(1, 11), d1_throughputs, label = "HashFlow-d1", marker = "x", markersize=10)
    plt.plot(range(1, 11), d2_throughputs, label = "HashFlow-d2", marker = "^", markersize=10)
    plt.plot(range(1, 11), d3_throughputs, label = "HashFlow-d3", marker = "<", markersize=10)
    plt.plot(range(1, 11), d4_throughputs, label = "HashFlow-d4", marker = "o", markersize=10)
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Traffic Trace")
    plt.ylabel("Kpps")
    plt.savefig("throughput.pdf", bbox_inches = "tight")
    plt.savefig("throughput.png", bbox_inches = "tight")

    plt.figure(2)
    plt.xticks(range(1, 11), ("#1", "#2", "#3", "#4", "#5", "#6", "#7", "#8", "#9", "#10"))
    plt.plot(range(1, 11), d1_ave_mem_accesses, label = "HashFlow-d1", marker = "x", markersize=10)
    plt.plot(range(1, 11), d2_ave_mem_accesses, label = "HashFlow-d2", marker = "^", markersize=10)
#    plt.plot(range(1, 11), hf_ave_mem_accesses_basic, label = "HashFlow-basic", marker = "o", markersize=10)
    plt.plot(range(1, 11), d3_ave_mem_accesses, label = "HashFlow-d3", marker = "<", markersize=10)
    plt.plot(range(1, 11), d4_ave_mem_accesses, label = "HashFlow-d4", marker = "o", markersize=10)
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Traffic Trace")
    plt.ylabel("Ave. Mem. Accesses")
    plt.savefig("ave_mem_accesses.pdf", bbox_inches = "tight")
    plt.savefig("ave_mem_accesses.png", bbox_inches = "tight")
