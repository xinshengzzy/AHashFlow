import matplotlib.pyplot as plt
import matplotlib
import matplotlib
from matplotlib.patches import Ellipse

font = {'size':25}
matplotlib.rc('font', **font)


def parse_file(filename):
    results = dict()
    with open(filename, "r") as f:
        for line in f:
            if "#" == line[0]:
                continue
            line = line.strip()
            items = line.split("\t")
            key1 = "\t".join([items[0], items[2], items[3], items[4], "overall_are"])
            key2 = "\t".join([items[0], items[2], items[3], items[4], "f1_score"])
            key3 = "\t".join([items[0], items[2], items[3], items[4], "hhd_are"])
            value1 = float(items[5])
            value2 = float(items[6])
            value3 = float(items[7])
            results[key1] = value1
            results[key2] = value2
            results[key3] = value3
    return results

if __name__ == "__main__":
    results = parse_file("./res.txt")
    n_flows = range(50000, 150001, 10000)
    markersize=18

    ########## for F1 Score of Heavy Hitter Detection in CAIDA trace ##########
    thresh = "10"
    line1 = [] # for the HashFlow with beta=0.0
    line2 = [] # for the HashFlow with beta=0.5
    line3 = [] # for the HashFlow with beta=1.0
    line4 = [] # for the HashFlow with beta=2.0
    for item in n_flows:
        line1.append(results["\t".join(["CAIDA", str(item), "0.0", thresh, "f1_score"])])
        line2.append(results["\t".join(["CAIDA", str(item), "0.5", thresh, "f1_score"])])
        line3.append(results["\t".join(["CAIDA", str(item), "1.0", thresh, "f1_score"])])
        line4.append(results["\t".join(["CAIDA", str(item), "2.0", thresh, "f1_score"])])

    plt.figure()
    plt.ylim(0.5, 1.05)
    plt.xticks(range(50000, 150001, 20000), ("50K", "70K", "90K", "110K", "130K", "150K"))
    plt.plot(n_flows, line1, label = r"$\beta$=0.0", marker = "x", markerfacecolor="none", markersize=markersize, color = 'blue')
    plt.plot(n_flows, line2, label = r"$\beta$=0.5", marker = "^", markerfacecolor="none", markersize=markersize, color = 'red')
    plt.plot(n_flows, line3, label = r"$\beta$=1.0", marker = "<", markerfacecolor="none", markersize=markersize, color = 'green')
    plt.plot(n_flows, line4, label = r"$\beta$=2.0", marker = "o", markerfacecolor="none", markersize=markersize, color = 'purple')
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Num. of Flows")
    plt.ylabel("F1 Score")
    plt.savefig("caida_heavy_hitter_detection_f1_score.png", bbox_inches = "tight")
    plt.savefig("caida_heavy_hitter_detection_f1_score.eps", bbox_inches = "tight")
    plt.close()

    ########## for ARE of Heavy Hitter Detection in CAIDA trace ##########
    line1 = [] # for the HashFlow with beta=0.0
    line2 = [] # for the HashFlow with beta=0.5
    line3 = [] # for the HashFlow with beta=1.0
    line4 = [] # for the HashFlow with beta=2.0
    for item in n_flows:
        line1.append(results["\t".join(["CAIDA", str(item), "0.0", thresh, "hhd_are"])])
        line2.append(results["\t".join(["CAIDA", str(item), "0.5", thresh, "hhd_are"])])
        line3.append(results["\t".join(["CAIDA", str(item), "1.0", thresh, "hhd_are"])])
        line4.append(results["\t".join(["CAIDA", str(item), "2.0", thresh, "hhd_are"])])



    plt.figure()
    plt.ylim(-0.05, 0.5)
    #plt.xticks(range(0, 100001, 20000), ("0", "20K", "40K", "60K", "80K", "100K"))
    plt.xticks(range(50000, 150001, 20000), ("50K", "70K", "90K", "110K", "130K", "150K"))
    plt.plot(n_flows, line1, label = r"$\beta$=0.0", marker = "x", markerfacecolor="none", markersize=markersize, color = 'blue')
    plt.plot(n_flows, line2, label = r"$\beta$=0.5", marker = "^", markerfacecolor="none", markersize=markersize, color = 'red')
    plt.plot(n_flows, line3, label = r"$\beta$=1.0", marker = "<", markerfacecolor="none", markersize=markersize, color = 'green')
    plt.plot(n_flows, line4, label = r"$\beta$=2.0", marker = "o", markerfacecolor="none", markersize=markersize, color = 'purple')
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Num. of Flows")
    plt.ylabel("ARE")
    plt.savefig("caida_heavy_hitter_detection_are.png", bbox_inches = "tight")
    plt.savefig("caida_heavy_hitter_detection_are.eps", bbox_inches = "tight")
    plt.close()

