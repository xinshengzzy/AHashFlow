import matplotlib.pyplot as plt
import matplotlib
import matplotlib
import np
from matplotlib.patches import Ellipse

font = {'size':18}
matplotlib.rc('font', **font)


def parse_file(filename):
    infile = open(filename, "r")
    n_flows = []
    cardinality = []
    flow_set_coverage  = []
    heavy_hitter_detection_f1_score = []
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
                heavy_hitter_detection_f1_score.append(float(items[1]))
            if "are_of_heavy_hitters:" == items[0]:
                heavy_hitter_are.append(float(items[1]))
            if "are_of_flow_size_estimation:" == items[0]:
                flow_size_estimation.append(float(items[1]))
    

    infile.close()
    return n_flows, cardinality, flow_set_coverage, heavy_hitter_detection_f1_score, heavy_hitter_are, flow_size_estimation

if __name__ == "__main__":
    hf_n_flows, hf_cardinality, hf_flowset_coverage, hf_heavy_hitter_detection_f1_score, hf_heavy_hitter_are, hf_flow_size_estimation, = parse_file("./result_hashflow_84435.txt")
    hp_n_flows, hp_cardinality, hp_flowset_coverage, hp_heavy_hitter_detection_f1_score, hp_heavy_hitter_are, hp_flow_size_estimation, = parse_file("./result_hashpipe_84435.txt")
    es_n_flows, es_cardinality, es_flowset_coverage, es_heavy_hitter_detection_f1_score, es_heavy_hitter_are, es_flow_size_estimation, = parse_file("./result_elasticsketch_84435.txt")
    fr_n_flows, fr_cardinality, fr_flowset_coverage, fr_heavy_hitter_detection_f1_score, fr_heavy_hitter_are, fr_flow_size_estimation, = parse_file("./result_flowradar_84435.txt")

    plt.figure(1)
    plt.xticks(range(1, 11), ("#1", "#2", "#3", "#4", "#5", "#6", "#7", "#8", "#9", "#10"))
    plt.plot(range(1, 11), hf_flow_size_estimation, label = "HashFlow", marker = "x", markersize=10)
    plt.plot(range(1, 11), hp_flow_size_estimation, label = "HashPipe", marker = "^", markersize=10)
    plt.plot(range(1, 11), es_flow_size_estimation, label = "ElasticSketch", marker = "<", markersize=10)
    plt.plot(range(1, 11), fr_flow_size_estimation, label = "FlowRadar", marker = "o", markersize=10)
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Traffic Trace")
    plt.ylabel("ARE")
    plt.savefig("flow_size_estimation_are.pdf", bbox_inches = "tight")
    plt.savefig("flow_size_estimation_are.png", bbox_inches = "tight")

    plt.figure(2)
    plt.xticks(range(1, 11), ("#1", "#2", "#3", "#4", "#5", "#6", "#7", "#8", "#9", "#10"))
    plt.plot(range(1, 11), hf_heavy_hitter_are, label = "HashFlow", marker = "x", markersize=10)
    plt.plot(range(1, 11), hp_heavy_hitter_are, label = "HashPipe", marker = "^", markersize=10)
    plt.plot(range(1, 11), es_heavy_hitter_are, label = "ElasticSketch", marker = "<", markersize=10)
    plt.plot(range(1, 11), fr_heavy_hitter_are, label = "FlowRadar", marker = "o", markersize=10)
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Traffic Trace")
    plt.ylabel("ARE")
    plt.savefig("heavy_hitter_are.pdf", bbox_inches = "tight")
    plt.savefig("heavy_hitter_are.png", bbox_inches = "tight")

    plt.figure(3)
    plt.xticks(range(1, 11), ("#1", "#2", "#3", "#4", "#5", "#6", "#7", "#8", "#9", "#10"))
    plt.plot(range(1, 11), hf_flowset_coverage, label = "HashFlow", marker = "x", markersize=10)
    plt.plot(range(1, 11), hp_flowset_coverage, label = "HashPipe", marker = "^", markersize=10)
    plt.plot(range(1, 11), es_flowset_coverage, label = "ElasticSketch", marker = "<", markersize=10)
    plt.plot(range(1, 11), fr_flowset_coverage, label = "FlowRadar", marker = "o", markersize=10)
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Traffic Trace")
    plt.ylabel("FSC")
    plt.savefig("flow_monitoring_fsc.pdf", bbox_inches = "tight")
    plt.savefig("flow_monitoring_fsc.png", bbox_inches = "tight")

    plt.figure(4)
    plt.xticks(range(1, 11), ("#1", "#2", "#3", "#4", "#5", "#6", "#7", "#8", "#9", "#10"))
    plt.plot(range(1, 11), hf_heavy_hitter_detection_f1_score, label = "HashFlow", marker = "x", markersize=10)
    plt.plot(range(1, 11), hp_heavy_hitter_detection_f1_score, label = "HashPipe", marker = "^", markersize=10)
    plt.plot(range(1, 11), es_heavy_hitter_detection_f1_score, label = "ElasticSketch", marker = "<", markersize=10)
    plt.plot(range(1, 11), fr_heavy_hitter_detection_f1_score, label = "FlowRadar", marker = "o", markersize=10)
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Traffic Trace")
    plt.ylabel("F1 Score")
    plt.savefig("heavy_hitter_f1_score.pdf", bbox_inches = "tight")
    plt.savefig("heavy_hitter_f1_score.png", bbox_inches = "tight")

    plt.figure(5)
    plt.xticks(range(1, 11), ("#1", "#2", "#3", "#4", "#5", "#6", "#7", "#8", "#9", "#10"))
    plt.plot(range(1, 11), hf_cardinality, label = "HashFlow", marker = "x", markersize=10)
    plt.plot(range(1, 11), hp_cardinality, label = "HashPipe", marker = "^", markersize=10)
    plt.plot(range(1, 11), es_cardinality, label = "ElasticSketch", marker = "<", markersize=10)
    plt.plot(range(1, 11), fr_cardinality, label = "FlowRadar", marker = "o", markersize=10)
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Traffic Trace")
    plt.ylabel("RE")
    plt.savefig("cardinality_re.pdf", bbox_inches = "tight")
    plt.savefig("cardinality_re.png", bbox_inches = "tight")
