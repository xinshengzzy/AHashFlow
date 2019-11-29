import matplotlib.pyplot as plt
import matplotlib
import matplotlib
import np
from matplotlib.patches import Ellipse

font = {'size':18}
matplotlib.rc('font', **font)


def parse_file(filename):
    ratio1 = []
    ratio2 = []
    ratio3 = []
    ratio4 = []
    with open(filename, "r") as f:
        for line in f:
            if "#" == line[0]:
                continue
            line = line.strip()
            items = line.split(" ")
            ratio1.append(float(items[1]))
            ratio2.append(float(items[2]))
            ratio3.append(float(items[3]))
            ratio4.append(float(items[4]))
    return ratio1, ratio2, ratio3, ratio4
    

if __name__ == "__main__":
    ratio1, ratio2, ratio3, ratio4 = parse_file("./cache_hit_ratio.txt")
    plt.figure(1)
    plt.xticks(range(1, 11), ("#1", "#2", "#3", "#4", "#5", "#6", "#7", "#8", "#9", "#10"))
    plt.plot(range(1, 11), ratio1, label = "n_hashes=1", marker = "x", markersize=10)
    plt.plot(range(1, 11), ratio2, label = "n_hashes=2", marker = "^", markersize=10)
    plt.plot(range(1, 11), ratio3, label = "n_hashes=3", marker = "<", markersize=10)
    plt.plot(range(1, 11), ratio4, label = "n_hashes=4", marker = "o", markersize=10)
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Traffic Trace")
    plt.ylabel("Utilization Ratio")
    plt.savefig("cache_hit_ratio.pdf", bbox_inches = "tight")
    plt.savefig("cache_hit_ratio.png", bbox_inches = "tight")
