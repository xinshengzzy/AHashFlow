import matplotlib.pyplot as plt
import matplotlib
import matplotlib
import np
from matplotlib.patches import Ellipse

font = {'size':26}
matplotlib.rc('font', **font)
markersize=18


def parse_file(filename):
    infile = open(filename, "r")
    n_flows = []
    cardinality = []
    flow_set_coverage  = []
    heavy_hitter_f1_score = []
    heavy_hitter_are = []
    flow_size_estimation = []
    for line in infile:
        line = line.strip()
        if "----------" == line:
            continue
        else:
            items = line.split(" ")
            if "n_flows:" == items[0]:
                n_flows.append(float(items[1]))
            if "re_of_cardinality:" == items[0]:
                cardinality.append(float(items[1]))
            if "fsc_of_flow_monitoring:" ==  items[0]:
                flow_set_coverage.append(float(items[1]))
            if "f1_score_of_heavy_hitter_detection:" == items[0]:
                heavy_hitter_f1_score.append(float(items[1]))
            if "are_of_heavy_hitters:" == items[0]:
                heavy_hitter_are.append(float(items[1]))
            if "are_of_flow_size_estimation:" == items[0]:
                flow_size_estimation.append(float(items[1]))
    infile.close()
    return n_flows, cardinality, flow_set_coverage, heavy_hitter_f1_score, heavy_hitter_are, flow_size_estimation

if __name__ == "__main__":
    basic_n_flows, basic_cardinality, basic_flowset_coverage, basic_heavy_hitter_f1_score, basic_heavy_hitter_are, basic_flow_size_estimation = parse_file("./result_basic_hashflow_84454.txt")
    _06_n_flows, _06_cardinality, _06_flowset_coverage, _06_heavy_hitter_f1_score, _06_heavy_hitter_are, _06_flow_size_estimation = parse_file("./result_06_hashflow_84454.txt")
    _07_n_flows, _07_cardinality, _07_flowset_coverage, _07_heavy_hitter_f1_score, _07_heavy_hitter_are, _07_flow_size_estimation = parse_file("./result_07_hashflow_84454.txt")
    _08_n_flows, _08_cardinality, _08_flowset_coverage, _08_heavy_hitter_f1_score, _08_heavy_hitter_are, _08_flow_size_estimation = parse_file("./result_08_hashflow_84454.txt")

    plt.figure(1)
    plt.xticks(np.arange(0, 60001, 10000), ("0", "10K", "20K", "30K", "40K", "50K", "60K"))
    plt.plot(basic_n_flows[0:6], basic_flow_size_estimation[0:6], label = "Multi-hash", marker = "x", markerfacecolor="none", markersize=markersize, color = "blue")
    plt.plot(_06_n_flows[0:6], _06_flow_size_estimation[0:6], label = r"$\alpha$=0.6", marker = "^", markerfacecolor="none", markersize=markersize, color = "red")
    plt.plot(_07_n_flows[0:6], _07_flow_size_estimation[0:6], label = r"$\alpha$=0.7", marker = "<", markerfacecolor="none", markersize=markersize, color = "green")
    plt.plot(_08_n_flows[0:6], _08_flow_size_estimation[0:6], label = r"$\alpha$=0.8", marker = "o", markerfacecolor="none", markersize=markersize, color = "purple")
#    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.legend(loc = 1)
    plt.xlabel("Num. of Flows")
    plt.ylabel("ARE")
    plt.ylim(-0.05, 1)
    plt.savefig("flow_size_estimation_are.pdf", bbox_inches = "tight")
    plt.savefig("flow_size_estimation_are.png", bbox_inches = "tight")
    plt.savefig("flow_size_estimation_are.eps", bbox_inches = "tight")
    plt.close()

    plt.figure(2)
    plt.xticks(np.arange(0, 60001, 10000), ("0", "10K", "20K", "30K", "40K", "50K", "60K"))
    plt.plot(basic_n_flows[0:6], basic_heavy_hitter_are[0:6], label = "Multi-hash", marker = "x", markerfacecolor="none", markersize=markersize, color = "blue")
    plt.plot(_06_n_flows[0:6], _06_heavy_hitter_are[0:6], label = r"$\alpha$=0.6", marker = "^", markerfacecolor="none", markersize=markersize, color = "red")
    plt.plot(_07_n_flows[0:6], _07_heavy_hitter_are[0:6], label = r"$\alpha$=0.7", marker = "<", markerfacecolor="none", markersize=markersize, color = "green")
    plt.plot(_08_n_flows[0:6], _08_heavy_hitter_are[0:6], label = r"$\alpha$=0.8", marker = "o", markerfacecolor="none", markersize=markersize, color = "purple")
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Num. of Flows")
    plt.ylabel("ARE")
    plt.savefig("heavy_hitter_are.pdf", bbox_inches = "tight")
    plt.savefig("heavy_hitter_are.png", bbox_inches = "tight")
    plt.savefig("heavy_hitter_are.eps", bbox_inches = "tight")
    plt.close()

    plt.figure(3)
    plt.xticks(np.arange(0, 60001, 10000), ("0", "10K", "20K", "30K", "40K", "50K", "60K"))
    plt.plot(basic_n_flows[0:6], basic_flowset_coverage[0:6], label = "Multi-hash", marker = "x", markerfacecolor="none", markersize=markersize, color = "blue")
    plt.plot(_06_n_flows[0:6], _06_flowset_coverage[0:6], label = r"$\alpha$=0.6", marker = "^", markerfacecolor="none", markersize=markersize, color = "red")
    plt.plot(_07_n_flows[0:6], _07_flowset_coverage[0:6], label = r"$\alpha$=0.7", marker = "<", markerfacecolor="none", markersize=markersize, color = "green")
    plt.plot(_08_n_flows[0:6], _08_flowset_coverage[0:6], label = r"$\alpha$=0.8", marker = "o", markerfacecolor="none", markersize=markersize, color = "purple")
#    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.legend(loc = 3)
    plt.xlabel("Num. of Flows")
    plt.ylabel("FSC")
    plt.ylim(0, 1.06)
    plt.savefig("flow_monitoring_fsc.pdf", bbox_inches = "tight")
    plt.savefig("flow_monitoring_fsc.png", bbox_inches = "tight")
    plt.savefig("flow_monitoring_fsc.eps", bbox_inches = "tight")
    plt.close()

    plt.figure(4)
    plt.xticks(np.arange(0, 60001, 10000), ("0", "10K", "20K", "30K", "40K", "50K", "60K"))
    plt.plot(basic_n_flows[0:6], basic_heavy_hitter_f1_score[0:6], label = "Multi-hash", marker = "x", markerfacecolor="none", markersize=markersize, color = "blue")
    plt.plot(_06_n_flows[0:6], _06_heavy_hitter_f1_score[0:6], label = r"$\alpha$=0.6", marker = "^", markerfacecolor="none", markersize=markersize, color = "red")
    plt.plot(_07_n_flows[0:6], _07_heavy_hitter_f1_score[0:6], label = r"$\alpha$=0.7", marker = "<", markerfacecolor="none", markersize=markersize, color = "green")
    plt.plot(_08_n_flows[0:6], _08_heavy_hitter_f1_score[0:6], label = r"$\alpha$=0.8", marker = "o", markerfacecolor="none", markersize=markersize, color = "purple")
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Num. of Flows")
    plt.ylabel("F1 Score")
    plt.savefig("heavy_hitter_f1_score.pdf", bbox_inches = "tight")
    plt.savefig("heavy_hitter_f1_score.png", bbox_inches = "tight")
    plt.savefig("heavy_hitter_f1_score.eps", bbox_inches = "tight")
    plt.close()

    plt.figure(5)
    plt.xticks(np.arange(0, 60001, 10000), ("0", "10K", "20K", "30K", "40K", "50K", "60K"))
    plt.plot(basic_n_flows[0:6], basic_cardinality[0:6], label = "Multi-hash", marker = "x", markerfacecolor="none", markersize=markersize, color = "blue")
    plt.plot(_06_n_flows[0:6], _06_cardinality[0:6], label = r"$\alpha$=0.6", marker = "^", markerfacecolor="none", markersize=markersize, color = "red")
    plt.plot(_07_n_flows[0:6], _07_cardinality[0:6], label = r"$\alpha$=0.7", marker = "<", markerfacecolor="none", markersize=markersize, color = "green")
    plt.plot(_08_n_flows[0:6], _08_cardinality[0:6], label = r"$\alpha$=0.8", marker = "o", markerfacecolor="none", markersize=markersize, color = "purple")
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Num. of Flows")
    plt.ylabel("RE")
    plt.savefig("cardinality_re.pdf", bbox_inches = "tight")
    plt.savefig("cardinality_re.png", bbox_inches = "tight")
    plt.savefig("cardinality_re.eps", bbox_inches = "tight")
    plt.close()
