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
    hf_filenames, hf_throughputs, hf_ave_mem_accesses, hf_ave_mem_accesses_basic = parse_file("./result_hashflow_84475.txt")
    hp_filenames, hp_throughputs, hp_ave_mem_accesses = parse_file("./result_hashpipe_84475.txt")
    es_filenames, es_throughputs, es_ave_mem_accesses = parse_file("./result_elasticsketch_84475.txt")
    fr_filenames, fr_throughputs, fr_ave_mem_accesses = parse_file("./result_flowradar_84475.txt")

    plt.figure(1)
    plt.xticks(range(1, 11), ("#1", "#2", "#3", "#4", "#5", "#6", "#7", "#8", "#9", "#10"))
    plt.plot(range(1, 11), hf_throughputs, label = "HashFlow", marker = "x", markersize=10)
    plt.plot(range(1, 11), hp_throughputs, label = "HashPipe", marker = "^", markersize=10)
    plt.plot(range(1, 11), es_throughputs, label = "ElasticSketch", marker = "<", markersize=10)
    plt.plot(range(1, 11), fr_throughputs, label = "FlowRadar", marker = "o", markersize=10)
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Traffic Trace")
    plt.ylabel("Throughput/Kpps")
    plt.savefig("throughput.pdf", bbox_inches = "tight")
    plt.savefig("throughput.png", bbox_inches = "tight")

    plt.figure(2)
    plt.xticks(range(1, 11), ("#1", "#2", "#3", "#4", "#5", "#6", "#7", "#8", "#9", "#10"))
    plt.plot(range(1, 11), hf_ave_mem_accesses, label = "HashFlow", marker = "x", markersize=10)
    plt.plot(range(1, 11), hp_ave_mem_accesses, label = "HashPipe", marker = "^", markersize=10)
#    plt.plot(range(1, 11), hf_ave_mem_accesses_basic, label = "HashFlow-basic", marker = "o", markersize=10)
    plt.plot(range(1, 11), es_ave_mem_accesses, label = "ElasticSketch", marker = "<", markersize=10)
#    plt.plot(range(1, 11), fr_ave_mem_accesses, label = "FlowRadar", marker = "o", markersize=10)
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Traffic Trace")
    plt.ylabel("Ave. Mem. Accesses")
    plt.savefig("ave_mem_accesses.pdf", bbox_inches = "tight")
    plt.savefig("ave_mem_accesses.png", bbox_inches = "tight")
