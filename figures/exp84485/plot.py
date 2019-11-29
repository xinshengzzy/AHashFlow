import matplotlib.pyplot as plt
import matplotlib
import matplotlib
import np
from matplotlib.patches import Ellipse

font = {'size':26}
matplotlib.rc('font', **font)
markersize = 18


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
########## For CAIDA trace ########
    hf_n_flows, hf_cardinality, hf_flow_monitoring, hf_fs_estimation= parse_file("./res_caida_HashFlow.txt")
    hp_n_flows, hp_cardinality, hp_flow_monitoring, hp_fs_estimation= parse_file("./res_caida_HashPipe.txt")
    es_n_flows, es_cardinality, es_flow_monitoring, es_fs_estimation = parse_file("./res_caida_ElasticSketch.txt")
    fr_n_flows, fr_cardinality, fr_flow_monitoring, fr_fs_estimation = parse_file("./res_caida_FlowRadar.txt")


    plt.figure()
    plt.xticks(range(0, 250001, 50000), ("0", "50K", "100K", "150K", "200K", "250K"))
    plt.plot(hf_n_flows, hf_flow_monitoring, label = "HF", marker = "x", markerfacecolor="none", markersize=markersize, color = 'blue')
    plt.plot(hp_n_flows, hp_flow_monitoring, label = "HP", marker = "^", markerfacecolor="none", markersize=markersize, color = 'red')
    plt.plot(es_n_flows, es_flow_monitoring, label = "ES", marker = "<", markerfacecolor="none", markersize=markersize, color = 'green')
    plt.plot(fr_n_flows, fr_flow_monitoring, label = "FR", marker = "o", markerfacecolor="none", markersize=markersize, color = 'purple')
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Num. of Flows")
    plt.ylabel("FSC")
    plt.savefig("caida_flow_monitoring_fsc.pdf", bbox_inches = "tight")
    plt.savefig("caida_flow_monitoring_fsc.png", bbox_inches = "tight")
    plt.savefig("caida_flow_monitoring_fsc.eps", bbox_inches = "tight")
    plt.close()

    plt.figure()
    plt.xticks(range(0, 250001, 50000), ("0", "50K", "100K", "150K", "200K", "250K"))
    plt.plot(hf_n_flows, hf_cardinality, label = "HF", marker = "x", markerfacecolor="none", markersize=markersize, color = 'blue')
    plt.plot(hp_n_flows, hp_cardinality, label = "HP", marker = "^", markerfacecolor="none", markersize=markersize, color = 'red')
    plt.plot(es_n_flows, es_cardinality, label = "ES", marker = "<", markerfacecolor="none", markersize=markersize, color = 'green')
    plt.plot(fr_n_flows, fr_cardinality, label = "FR", marker = "o", markerfacecolor="none", markersize=markersize, color = 'purple')
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Num. of Flows")
    plt.ylabel("RE")
    plt.ylim(-0.05, 1)
    plt.savefig("caida_cardinality_re.pdf", bbox_inches = "tight")
    plt.savefig("caida_cardinality_re.png", bbox_inches = "tight")
    plt.savefig("caida_cardinality_re.eps", bbox_inches = "tight")
    plt.close()

    plt.figure()
    plt.xticks(range(0, 100001, 20000), ("0", "20K", "40K", "60K", "80K", "100K"))
    plt.plot(hf_n_flows[0:10], hf_fs_estimation[0:10], label = "HF", marker = "x", markerfacecolor="none", markersize=markersize, color = 'blue')
    plt.plot(hp_n_flows[0:10], hp_fs_estimation[0:10], label = "HP", marker = "^", markerfacecolor="none", markersize=markersize, color = 'red')
    plt.plot(es_n_flows[0:10], es_fs_estimation[0:10], label = "ES", marker = "<", markerfacecolor="none", markersize=markersize, color = 'green')
    plt.plot(fr_n_flows[0:10], fr_fs_estimation[0:10], label = "FR", marker = "o", markerfacecolor="none", markersize=markersize, color = 'purple')
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Num. of Flows")
    plt.ylabel("ARE")
    plt.savefig("caida_flow_size_estimation_are.pdf", bbox_inches = "tight")
    plt.savefig("caida_flow_size_estimation_are.png", bbox_inches = "tight")
    plt.savefig("caida_flow_size_estimation_are.eps", bbox_inches = "tight")
    plt.close()

########### For Tsinghua Trace ##########
    hf_n_flows, hf_cardinality, hf_flow_monitoring, hf_fs_estimation = parse_file("./res_tsinghua_HashFlow.txt")
    hp_n_flows, hp_cardinality, hp_flow_monitoring, hp_fs_estimation = parse_file("./res_tsinghua_HashPipe.txt")
    es_n_flows, es_cardinality, es_flow_monitoring, es_fs_estimation = parse_file("./res_tsinghua_ElasticSketch.txt")
    fr_n_flows, fr_cardinality, fr_flow_monitoring, fr_fs_estimation = parse_file("./res_tsinghua_FlowRadar.txt")

    plt.figure()
    plt.xticks(range(0, 250001, 50000), ("0", "50K", "100K", "150K", "200K", "250K"))
    plt.plot(hf_n_flows, hf_flow_monitoring, label = "HF", marker = "x", markerfacecolor="none", markersize=markersize, color = 'blue')
    plt.plot(hp_n_flows, hp_flow_monitoring, label = "HP", marker = "^", markerfacecolor="none", markersize=markersize, color = 'red')
    plt.plot(es_n_flows, es_flow_monitoring, label = "ES", marker = "<", markerfacecolor="none", markersize=markersize, color = 'green')
    plt.plot(fr_n_flows, fr_flow_monitoring, label = "FR", marker = "o", markerfacecolor="none", markersize=markersize, color = 'purple')
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Num. of Flows")
    plt.ylabel("FSC")
    plt.savefig("tsinghua_flow_monitoring_fsc.pdf", bbox_inches = "tight")
    plt.savefig("tsinghua_flow_monitoring_fsc.png", bbox_inches = "tight")
    plt.savefig("tsinghua_flow_monitoring_fsc.eps", bbox_inches = "tight")
    plt.close()

    plt.figure()
    plt.xticks(range(0, 250001, 50000), ("0", "50K", "100K", "150K", "200K", "250K"))
    plt.plot(hf_n_flows, hf_cardinality, label = "HF", marker = "x", markerfacecolor="none", markersize=markersize, color = 'blue')
    plt.plot(hp_n_flows, hp_cardinality, label = "HP", marker = "^", markerfacecolor="none", markersize=markersize, color = 'red')
    plt.plot(es_n_flows, es_cardinality, label = "ES", marker = "<", markerfacecolor="none", markersize=markersize, color = 'green')
    plt.plot(fr_n_flows, fr_cardinality, label = "FR", marker = "o", markerfacecolor="none", markersize=markersize, color = 'purple')
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Num. of Flows")
    plt.ylabel("RE")
    plt.ylim(-0.05, 1)
    plt.savefig("tsinghua_cardinality_re.pdf", bbox_inches = "tight")
    plt.savefig("tsinghua_cardinality_re.png", bbox_inches = "tight")
    plt.savefig("tsinghua_cardinality_re.eps", bbox_inches = "tight")
    plt.close()

    plt.figure()
    plt.xticks(range(0, 100001, 20000), ("0", "20K", "40K", "60K", "80K", "100K"))
    plt.plot(hf_n_flows[0:10], hf_fs_estimation[0:10], label = "HF", marker = "x", markerfacecolor="none", markersize=markersize, color = 'blue')
    plt.plot(hp_n_flows[0:10], hp_fs_estimation[0:10], label = "HP", marker = "^", markerfacecolor="none", markersize=markersize, color = 'red')
    plt.plot(es_n_flows[0:10], es_fs_estimation[0:10], label = "ES", marker = "<", markerfacecolor="none", markersize=markersize, color = 'green')
    plt.plot(fr_n_flows[0:10], fr_fs_estimation[0:10], label = "FR", marker = "o", markerfacecolor="none", markersize=markersize, color = 'purple')
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Num. of Flows")
    plt.ylabel("ARE")
    plt.savefig("tsinghua_flow_size_estimation_are.pdf", bbox_inches = "tight")
    plt.savefig("tsinghua_flow_size_estimation_are.png", bbox_inches = "tight")
    plt.savefig("tsinghua_flow_size_estimation_are.eps", bbox_inches = "tight")
    plt.close()


########## For Telecom trace ##########
    hf_n_flows, hf_cardinality, hf_flow_monitoring, hf_fs_estimation = parse_file("./res_telecom_HashFlow.txt")
    hp_n_flows, hp_cardinality, hp_flow_monitoring, hp_fs_estimation = parse_file("./res_telecom_HashPipe.txt")
    es_n_flows, es_cardinality, es_flow_monitoring, es_fs_estimation = parse_file("./res_telecom_ElasticSketch.txt")
    fr_n_flows, fr_cardinality, fr_flow_monitoring, fr_fs_estimation = parse_file("./res_telecom_FlowRadar.txt")

    plt.figure()
    plt.xticks(range(0, 250001, 50000), ("0", "50K", "100K", "150K", "200K", "250K"))
    plt.plot(hf_n_flows, hf_flow_monitoring, label = "HF", marker = "x", markerfacecolor="none", markersize=markersize, color = 'blue')
    plt.plot(hp_n_flows, hp_flow_monitoring, label = "HP", marker = "^", markerfacecolor="none", markersize=markersize, color = 'red')
    plt.plot(es_n_flows, es_flow_monitoring, label = "ES", marker = "<", markerfacecolor="none", markersize=markersize, color = 'green')
    plt.plot(fr_n_flows, fr_flow_monitoring, label = "FR", marker = "o", markerfacecolor="none", markersize=markersize, color = 'purple')
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Num. of Flows")
    plt.ylabel("FSC")
    plt.savefig("telecom_flow_monitoring_fsc.pdf", bbox_inches = "tight")
    plt.savefig("telecom_flow_monitoring_fsc.png", bbox_inches = "tight")
    plt.savefig("telecom_flow_monitoring_fsc.eps", bbox_inches = "tight")
    plt.close()

    plt.figure()
    plt.xticks(range(0, 250001, 50000), ("0", "50K", "100K", "150K", "200K", "250K"))
    plt.plot(hf_n_flows, hf_cardinality, label = "HF", marker = "x", markerfacecolor="none", markersize=markersize, color = 'blue')
    plt.plot(hp_n_flows, hp_cardinality, label = "HP", marker = "^", markerfacecolor="none", markersize=markersize, color = 'red')
    plt.plot(es_n_flows, es_cardinality, label = "ES", marker = "<", markerfacecolor="none", markersize=markersize, color = 'green')
    plt.plot(fr_n_flows, fr_cardinality, label = "FR", marker = "o", markerfacecolor="none", markersize=markersize, color = 'purple')
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Num. of Flows")
    plt.ylabel("RE")
    plt.ylim(-0.05, 1)
    plt.savefig("telecom_cardinality_re.pdf", bbox_inches = "tight")
    plt.savefig("telecom_cardinality_re.png", bbox_inches = "tight")
    plt.savefig("telecom_cardinality_re.eps", bbox_inches = "tight")
    plt.close()

    plt.figure()
    plt.xticks(range(0, 100001, 20000), ("0", "20K", "40K", "60K", "80K", "100K"))
    plt.plot(hf_n_flows[0:10], hf_fs_estimation[0:10], label = "HF", marker = "x", markerfacecolor="none", markersize=markersize, color = 'blue')
    plt.plot(hp_n_flows[0:10], hp_fs_estimation[0:10], label = "HP", marker = "^", markerfacecolor="none", markersize=markersize, color = 'red')
    plt.plot(es_n_flows[0:10], es_fs_estimation[0:10], label = "ES", marker = "<", markerfacecolor="none", markersize=markersize, color = 'green')
    plt.plot(fr_n_flows[0:10], fr_fs_estimation[0:10], label = "FR", marker = "o", markerfacecolor="none", markersize=markersize, color = 'purple')
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Num. of Flows")
    plt.ylabel("ARE")
    plt.savefig("telecom_flow_size_estimation_are.pdf", bbox_inches = "tight")
    plt.savefig("telecom_flow_size_estimation_are.png", bbox_inches = "tight")
    plt.savefig("telecom_flow_size_estimation_are.eps", bbox_inches = "tight")
    plt.close()


########## For HGC trace ##########
    hf_n_flows, hf_cardinality, hf_flow_monitoring, hf_fs_estimation = parse_file("./res_hgc_HashFlow.txt")
    hp_n_flows, hp_cardinality, hp_flow_monitoring, hp_fs_estimation = parse_file("./res_hgc_HashPipe.txt")
    es_n_flows, es_cardinality, es_flow_monitoring, es_fs_estimation = parse_file("./res_hgc_ElasticSketch.txt")
    fr_n_flows, fr_cardinality, fr_flow_monitoring, fr_fs_estimation = parse_file("./res_hgc_FlowRadar.txt")

    plt.figure()
    plt.xticks(range(0, 250001, 50000), ("0", "50K", "100K", "150K", "200K", "250K"))
    plt.plot(hf_n_flows, hf_flow_monitoring, label = "HF", marker = "x", markerfacecolor="none", markersize=markersize, color = 'blue')
    plt.plot(hp_n_flows, hp_flow_monitoring, label = "HP", marker = "^", markerfacecolor="none", markersize=markersize, color = 'red')
    plt.plot(es_n_flows, es_flow_monitoring, label = "ES", marker = "<", markerfacecolor="none", markersize=markersize, color = 'green')
    plt.plot(fr_n_flows, fr_flow_monitoring, label = "FR", marker = "o", markerfacecolor="none", markersize=markersize, color = 'purple')
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Num. of Flows")
    plt.ylabel("FSC")
    plt.savefig("hgc_flow_monitoring_fsc.pdf", bbox_inches = "tight")
    plt.savefig("hgc_flow_monitoring_fsc.png", bbox_inches = "tight")
    plt.savefig("hgc_flow_monitoring_fsc.eps", bbox_inches = "tight")
    plt.close()

    plt.figure()
    plt.xticks(range(0, 250001, 50000), ("0", "50K", "100K", "150K", "200K", "250K"))
    plt.plot(hf_n_flows, hf_cardinality, label = "HF", marker = "x", markerfacecolor="none", markersize=markersize, color = 'blue')
    plt.plot(hp_n_flows, hp_cardinality, label = "HP", marker = "^", markerfacecolor="none", markersize=markersize, color = 'red')
    plt.plot(es_n_flows, es_cardinality, label = "ES", marker = "<", markerfacecolor="none", markersize=markersize, color = 'green')
    plt.plot(fr_n_flows, fr_cardinality, label = "FR", marker = "o", markerfacecolor="none", markersize=markersize, color = 'purple')
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Num. of Flows")
    plt.ylabel("RE")
    plt.ylim(-0.05, 1)
    plt.savefig("hgc_cardinality_re.pdf", bbox_inches = "tight")
    plt.savefig("hgc_cardinality_re.png", bbox_inches = "tight")
    plt.savefig("hgc_cardinality_re.eps", bbox_inches = "tight")
    plt.close()

    plt.figure()
    plt.xticks(range(0, 100001, 20000), ("0", "20K", "40K", "60K", "80K", "100K"))
    plt.plot(hf_n_flows[0:10], hf_fs_estimation[0:10], label = "HF", marker = "x", markerfacecolor="none", markersize=markersize, color = 'blue')
    plt.plot(hp_n_flows[0:10], hp_fs_estimation[0:10], label = "HP", marker = "^", markerfacecolor="none", markersize=markersize, color = 'red')
    plt.plot(es_n_flows[0:10], es_fs_estimation[0:10], label = "ES", marker = "<", markerfacecolor="none", markersize=markersize, color = 'green')
    plt.plot(fr_n_flows[0:10], fr_fs_estimation[0:10], label = "FR", marker = "o", markerfacecolor="none", markersize=markersize, color = 'purple')
    plt.legend(bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc = 3, ncol = 2, mode = "expand", borderaxespad = 0.0)
    plt.xlabel("Num. of Flows")
    plt.ylabel("ARE")
    plt.savefig("hgc_flow_size_estimation_are.pdf", bbox_inches = "tight")
    plt.savefig("hgc_flow_size_estimation_are.png", bbox_inches = "tight")
    plt.savefig("hgc_flow_size_estimation_are.eps", bbox_inches = "tight")
    plt.close()


