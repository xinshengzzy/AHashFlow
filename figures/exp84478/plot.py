import matplotlib.pyplot as plt
import matplotlib
import matplotlib
import np
from matplotlib.patches import Ellipse

font = {'size':26}
matplotlib.rc('font', **font)
markersize=18

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
    with open("caida_distribution.txt", "r") as f:
        line = f.readline().strip()
        lst = line.split(" ")
        caida_dist = [float(item) for item in lst]
    with open("tsinghua_distribution.txt", "r") as f:
        line = f.readline().strip()
        lst = line.split(" ")
        tsinghua_dist = [float(item) for item in lst]
    with open("hgc_distribution.txt", "r") as f:
        line = f.readline().strip()
        lst = line.split(" ")
        hgc_dist = [float(item) for item in lst]
    with open("telecom_distribution.txt", "r") as f:
        line = f.readline().strip()
        lst = line.split(" ")
        telecom_dist = [float(item) for item in lst]

    plt.figure(figsize=(6,5))
#    plt.semilogx(range(0, len(caida_dist)), caida_dist, color = "blue", label="CAIDA", marker="x", markersize = 8)
    plt.semilogx(range(0, len(caida_dist)), caida_dist, color = "blue", label="CAIDA")
#    plt.semilogx(range(0, len(tsinghua_dist)), tsinghua_dist, color = "red", label="Campus", marker="^", markersize = 8)
    plt.semilogx(range(0, len(tsinghua_dist)), tsinghua_dist, color = "red", label="Campus")
#    plt.semilogx(range(0, len(hgc_dist)), hgc_dist, color = "green", label="HGC", marker="<", markersize = 8)
    plt.semilogx(range(0, len(hgc_dist)), hgc_dist, color = "green", label="ISP1")
#    plt.semilogx(range(0, len(telecom_dist)), telecom_dist, color = "purple", label="Telecom", marker="o", markersize = 8)
    plt.semilogx(range(0, len(telecom_dist)), telecom_dist, color = "purple", label="ISP2")
#    plt.plot(range(1, 11), ratio2, label = "n_hashes=2", marker = "^", markersize=10)
#    plt.plot(range(1, 11), ratio3, label = "n_hashes=3", marker = "<", markersize=10)
#    plt.plot(range(1, 11), ratio4, label = "n_hashes=4", marker = "o", markersize=10)
#    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.legend(loc = 4)
    plt.xlabel("Flow Size in Pkts")
    plt.ylabel("CDF")
    plt.savefig("flow_size_distribution.pdf", bbox_inches = "tight")
    plt.savefig("flow_size_distribution.png", bbox_inches = "tight")
    plt.savefig("flow_size_distribution.eps", bbox_inches = "tight")
