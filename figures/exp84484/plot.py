import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import numpy as np
import math
import matplotlib

font = {'size': 26}
matplotlib.rc('font', **font)
markersize = 18

def get_throughput(filename):
    throughputs = []
    with open(filename, "r") as f:
        for line in f:
            items = line.split(" ")
            if "throughput:" == items[0]:
                throughputs.append(float(items[1]))
    return throughputs

def mean(lst):
    return sum(lst)/float(len(lst))

def std(lst):
    m = mean(lst)
    std = 0.0
    for item in lst:
        std = std + ((item - m)**2)
    std = math.sqrt(std/len(lst))
    return std

def subtract(lst_a, lst_b):
    lst = []
    for i in range(len(lst_a)):
        lst.append(lst_a[i] - lst_b[i])
    return lst
    

if __name__ == "__main__":
    ########## For CAIDA trace ##########
    th_hf_caida = get_throughput("./throughput_caida_HashFlow.txt")
    th_hp_caida = get_throughput("./throughput_caida_HashPipe.txt")
    th_es_caida = get_throughput("./throughput_caida_ElasticSketch.txt")
    th_fr_caida = get_throughput("./throughput_caida_FlowRadar.txt")

    th_hf_tsinghua = get_throughput("./throughput_tsinghua_HashFlow.txt")
    th_hp_tsinghua = get_throughput("./throughput_tsinghua_HashPipe.txt")
    th_es_tsinghua = get_throughput("./throughput_tsinghua_ElasticSketch.txt")
    th_fr_tsinghua = get_throughput("./throughput_tsinghua_FlowRadar.txt")

    th_hf_hgc = get_throughput("./throughput_hgc_HashFlow.txt")
    th_hp_hgc = get_throughput("./throughput_hgc_HashPipe.txt")
    th_es_hgc = get_throughput("./throughput_hgc_ElasticSketch.txt")
    th_fr_hgc = get_throughput("./throughput_hgc_FlowRadar.txt")

    th_hf_telecom = get_throughput("./throughput_telecom_HashFlow.txt")
    th_hp_telecom = get_throughput("./throughput_telecom_HashPipe.txt")
    th_es_telecom = get_throughput("./throughput_telecom_ElasticSketch.txt")
    th_fr_telecom = get_throughput("./throughput_telecom_FlowRadar.txt")

    print("th_hf_telecom:", mean(th_hf_telecom))
    print("th_hp_telecom:", mean(th_hp_telecom))
    print("th_es_telecom:", mean(th_es_telecom))

    hf_min = [min(th_hf_caida), min(th_hf_tsinghua), min(th_hf_hgc), min(th_hf_telecom)]
    hf_max = [max(th_hf_caida), max(th_hf_tsinghua), max(th_hf_hgc), max(th_hf_telecom)]
    hf_mean = [mean(th_hf_caida), mean(th_hf_tsinghua), mean(th_hf_hgc), mean(th_hf_telecom)]
    hf_lower = subtract(hf_mean, hf_min)
    hf_upper = subtract(hf_max, hf_mean)

    hp_min = [min(th_hp_caida), min(th_hp_tsinghua), min(th_hp_hgc), min(th_hp_telecom)]
    hp_max = [max(th_hp_caida), max(th_hp_tsinghua), max(th_hp_hgc), max(th_hp_telecom)]
    hp_mean = [mean(th_hp_caida), mean(th_hp_tsinghua), mean(th_hp_hgc), mean(th_hp_telecom)]
    hp_lower = subtract(hp_mean, hp_min)
    hp_upper = subtract(hp_max, hp_mean)

    es_min = [min(th_es_caida), min(th_es_tsinghua), min(th_es_hgc), min(th_es_telecom)]
    es_max = [max(th_es_caida), max(th_es_tsinghua), max(th_es_hgc), max(th_es_telecom)]
    es_mean = [mean(th_es_caida), mean(th_es_tsinghua), mean(th_es_hgc), mean(th_es_telecom)]
    es_lower = subtract(es_mean, es_min)
    es_upper = subtract(es_max, es_mean)

    fr_min = [min(th_fr_caida), min(th_fr_tsinghua), min(th_fr_hgc), min(th_fr_telecom)]
    fr_max = [max(th_fr_caida), max(th_fr_tsinghua), max(th_fr_hgc), max(th_fr_telecom)]
    fr_mean = [mean(th_fr_caida), mean(th_fr_tsinghua), mean(th_fr_hgc), mean(th_fr_telecom)]
    fr_lower = subtract(fr_mean, fr_min)
    fr_upper = subtract(fr_max, fr_mean)

    pos = range(4)
    width = 0.2
    fig, ax = plt.subplots(figsize=(7, 5))
    plt.bar(pos, hf_mean, width, alpha=1.0, color='blue', label="HF")
    plt.bar([p + width for p in pos],
        hp_mean, width, alpha=1.0, color='red', label='HP')
    plt.bar([p + 2*width for p in pos],
        es_mean, width, alpha=1.0, color='green', label='ES')
    plt.bar([p + 3*width for p in pos],
        fr_mean, width, alpha=1.0, color='purple', label='FR')
    ax.set_ylabel('Kpps')
    ax.set_xlabel("Traces")
    ax.set_xticks([0.3, 1.3, 2.3, 3.3])
    ax.set_xticklabels(["CAIDA", "Campus", "ISP1", "ISP2"])
    plt.xlim(-0.2, 3.8)

    plt.legend(["HF", "HP", "ES", "FR"],  
        bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc=3, ncol=2, mode='expand', 
        borderaxespad = 0.0)



    plt.errorbar(pos, hf_mean, [hf_lower, hf_upper], fmt='.k', ecolor='gray', lw=3, capsize=5)
    plt.errorbar([p + width for p in pos], 
        hp_mean, [hp_lower, hp_upper], fmt='.k', ecolor='gray', lw=3, capsize=5)
    plt.errorbar([p + 2*width for p in pos], 
        es_mean, [es_lower, es_upper], fmt='.k', ecolor='gray', lw=3, capsize=5)
    plt.errorbar([p + 3*width for p in pos], 
        fr_mean, [fr_lower, fr_upper], fmt='.k', ecolor='gray', lw=3, capsize=5)
    plt.savefig('throughput.pdf', bbox_inches='tight')
    plt.savefig('throughput.png', bbox_inches='tight')
    plt.savefig('throughput.eps', bbox_inches='tight')
    
