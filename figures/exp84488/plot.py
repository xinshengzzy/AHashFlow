import matplotlib.pyplot as plt
import matplotlib
import matplotlib
from matplotlib.patches import Ellipse

font = {'size':26}
matplotlib.rc('font', **font)
markersize=18


def parse_file(filename):
    infile = open(filename, "r")
    n_flows = []
    cardinality = []
    flow_monitoring  = []
    heavy_hitter_detection_f1_score = []
    heavy_hitter_are = []
    flow_size_estimation = []
    for line in infile:
        line = line.strip()
        items = line.split(" ")
        if "n_flows:" == items[0]:
            n_flows.append(float(items[1]))
        if "re_of_cardinality:" == items[0]:
            cardinality.append(float(items[1]))
        if "fsc_of_flow_monitoring:" ==  items[0]:
            flow_monitoring.append(float(items[1]))
#        if "f1_score_of_heavy_hitter_detection:" == items[0]:
#            heavy_hitter_detection_f1_score.append(float(items[1]))
#        if "are_of_heavy_hitters:" == items[0]:
#            heavy_hitter_are.append(float(items[1]))
        if "are_of_flow_size_estimation:" == items[0]:
            flow_size_estimation.append(float(items[1]))
    infile.close()
    return n_flows, cardinality, flow_monitoring, flow_size_estimation

if __name__ == "__main__":
    alpha = []
    res_1 = []
    res_2 = []
    res_3 = []
    res_4 = []
    res_5 = []
    res_6 = []
    res_7 = []
    res_8 = []
#    res_ratio_18 = []
#    res_ratio_20 = []
    with open("improvement.txt", "r") as f:
        for line in f:
            if "#" == line[0]:
                continue
            items = line.split(" ")
            alpha.append(float(items[0]))
            res_1.append(float(items[1]))
            res_2.append(float(items[2]))
            res_3.append(float(items[3]))
            res_4.append(float(items[4]))
            res_5.append(float(items[5]))
            res_6.append(float(items[6]))
            res_7.append(float(items[7]))
            res_8.append(float(items[8]))
    print(alpha)
    plt.figure()
#    plt.xticks(range(0, 250001, 50000), ("0", "50K", "100K", "150K", "200K", "250K"))
    plt.plot(alpha, res_1, label = r"$\lambda$=1.0", color = 'blue', markerfacecolor="none", marker = "x", markersize = markersize)
    plt.plot(alpha, res_2, label = r"$\lambda$=1.2", color = 'red', markerfacecolor = "none", marker = "^", markersize = markersize)
    plt.plot(alpha, res_3, label = r"$\lambda$=1.4", color = 'green', markerfacecolor = "none", marker = "<", markersize = markersize)
    plt.plot(alpha, res_4, label = r"$\lambda$=1.6", color = 'purple', markerfacecolor = "none", marker = "o", markersize = markersize)
    plt.plot(alpha, res_5, label = r"$\lambda$=1.8", color = 'violet', markerfacecolor = "none", marker = "s", markersize = markersize)
    plt.plot(alpha, res_6, label = r"$\lambda$=2.0", color = 'orange', markerfacecolor="none", marker = 'D', markersize = markersize)
    plt.plot(alpha, res_6, label = r"$\lambda$=3.0", color = 'cyan', markerfacecolor="none", marker = 'p', markersize = markersize)
    plt.plot(alpha, res_6, label = r"$\lambda$=4.0", color = 'magenta', markerfacecolor="none", marker = '|', markersize = markersize)
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
#    plt.legend(loc = 2, ncol = 2, mode = "expand")
    plt.text(0.7, 0.075, r"$\lambda=m/n$")
    plt.xlabel(r"$\alpha$")
    plt.ylabel("Improvement")
    plt.ylim(-0.02, 0.1)
    plt.savefig("improvement.pdf", bbox_inches = "tight")
    plt.savefig("improvement.png", bbox_inches = "tight")
    plt.savefig("improvement.eps", bbox_inches = "tight")
    plt.close()

