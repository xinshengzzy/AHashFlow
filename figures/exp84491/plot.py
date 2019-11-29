import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import numpy as np
import math
import matplotlib

font = {'size': 25}
matplotlib.rc('font', **font)

def parse(filename):
    caida, tsinghua, hgc, telecom = [[],[],[],[]], [[],[],[],[]], [[],[],[],[]], [[],[],[],[]]
    with open(filename, "r") as f:
        for line in f:
            if "#" == line[0]:
                continue
            items = line.split("\t")
            if "Tsinghua" == items[0] and "100000" == items[1]:
                tsinghua[0].append((float(items[4]) - float(items[3]))/float(items[3]))
                tsinghua[1].append((float(items[5]) - float(items[3]))/float(items[3]))
                tsinghua[2].append((float(items[6]) - float(items[3]))/float(items[3]))
                tsinghua[3].append((float(items[7]) - float(items[3]))/float(items[3]))
            if "Telecom" == items[0] and "100000" == items[1]:
                telecom[0].append((float(items[4]) - float(items[3]))/float(items[3]))
                telecom[1].append((float(items[5]) - float(items[3]))/float(items[3]))
                telecom[2].append((float(items[6]) - float(items[3]))/float(items[3]))
                telecom[3].append((float(items[7]) - float(items[3]))/float(items[3]))
            if "CAIDA" == items[0] and "100000" == items[1]:
                caida[0].append((float(items[4]) - float(items[3]))/float(items[3]))
                caida[1].append((float(items[5]) - float(items[3]))/float(items[3]))
                caida[2].append((float(items[6]) - float(items[3]))/float(items[3]))
                caida[3].append((float(items[7]) - float(items[3]))/float(items[3]))
            if "HGC" == items[0] and "100000" == items[1]:
                hgc[0].append((float(items[4]) - float(items[3]))/float(items[3]))
                hgc[1].append((float(items[5]) - float(items[3]))/float(items[3]))
                hgc[2].append((float(items[6]) - float(items[3]))/float(items[3]))
                hgc[3].append((float(items[7]) - float(items[3]))/float(items[3]))
        #assert(10 == len(caida) and 10 == len(tsinghua) and 10 == len(hgc) and 10 == len(telecom))
        return caida, tsinghua, hgc, telecom

def mean(lst):
    return sum(lst)/float(len(lst))

if "__main__" == __name__:
    caida, tsinghua, hgc, telecom = parse("./res.txt")

    caida_min = [min(caida[i]) for i in range(4)]
    caida_max = [max(caida[i]) for i in range(4)]
    caida_mean = [mean(caida[i]) for i in range(4)]
    print "caida_min:", caida_min
    print "caida_max:", caida_max
    print "caida_mean:", caida_mean

    tsinghua_min = [min(tsinghua[i]) for i in range(4)]
    tsinghua_max = [max(tsinghua[i]) for i in range(4)]
    tsinghua_mean = [mean(tsinghua[i]) for i in range(4)]
    print "tsinghua_min:", tsinghua_min
    print "tsinghua_max:", tsinghua_max
    print "tsinghua_mean:", tsinghua_mean

    hgc_min = [min(hgc[i]) for i in range(4)]
    hgc_max = [max(hgc[i]) for i in range(4)]
    hgc_mean = [mean(hgc[i]) for i in range(4)]
    print "hgc_min:", hgc_min
    print "hgc_max:", hgc_max
    print "hgc_mean:", hgc_mean

    telecom_min = [min(telecom[i]) for i in range(4)]
    telecom_max = [max(telecom[i]) for i in range(4)]
    telecom_mean = [mean(telecom[i]) for i in range(4)]
    print "telecom_min:", telecom_min
    print "telecom_max:", telecom_max
    print "telecom_mean:", telecom_mean

    d1_min = [caida_min[0], tsinghua_min[0], hgc_min[0], telecom_min[0]]
    d2_min = [caida_min[1], tsinghua_min[1], hgc_min[1], telecom_min[1]]
    d3_min = [caida_min[2], tsinghua_min[2], hgc_min[2], telecom_min[2]]
    d4_min = [caida_min[3], tsinghua_min[3], hgc_min[3], telecom_min[3]]

    d1_max = [caida_max[0], tsinghua_max[0], hgc_max[0], telecom_max[0]]
    d2_max = [caida_max[1], tsinghua_max[1], hgc_max[1], telecom_max[1]]
    d3_max = [caida_max[2], tsinghua_max[2], hgc_max[2], telecom_max[2]]
    d4_max = [caida_max[3], tsinghua_max[3], hgc_max[3], telecom_max[3]]

    d1_mean = [caida_mean[0], tsinghua_mean[0], hgc_mean[0], telecom_mean[0]]
    d2_mean = [caida_mean[1], tsinghua_mean[1], hgc_mean[1], telecom_mean[1]]
    d3_mean = [caida_mean[2], tsinghua_mean[2], hgc_mean[2], telecom_mean[2]]
    d4_mean = [caida_mean[3], tsinghua_mean[3], hgc_mean[3], telecom_mean[3]]

    pos = range(4)
    width = 0.2
    fig, ax = plt.subplots(figsize=(7, 5))
    plt.bar(pos, d1_mean, width, alpha=1.0, color='blue', label="depth=1")
    plt.bar([p + width for p in pos], d2_mean, width, alpha=1.0, color='red', label='depth=2')
    plt.bar([p + 2*width for p in pos], d3_mean, width, alpha=1.0, color='green', label='depth=3')
    plt.bar([p + 3*width for p in pos], d4_mean, width, alpha=1.0, color='purple', label='depth=4')
    ax.set_ylabel('Resubmit Rate')
    ax.set_xlabel("Traces")
    ax.set_xticks([0.3, 1.3, 2.3, 3.3])
    ax.set_xticklabels(["CAIDA", "Campus", "ISP1", "ISP2"])
    plt.xlim(-0.2, 3.8)
    plt.ylim(0.0, 1.0)

    plt.legend(["depth=1", "depth=2", "depth=3", "depth=4"],  
        bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc=3, ncol=2, mode='expand', 
        borderaxespad = 0.0)

    plt.errorbar(pos, d1_mean, [d1_min, d1_max], fmt='.k', ecolor='gray', lw=3, capsize=5)
    plt.errorbar([p + width for p in pos], 
        d2_mean, [d2_min, d2_max], fmt='.k', ecolor='gray', lw=3, capsize=5)
    plt.errorbar([p + 2*width for p in pos], 
        d3_mean, [d3_min, d3_max], fmt='.k', ecolor='gray', lw=3, capsize=5)
    plt.errorbar([p + 3*width for p in pos], 
        d4_mean, [d4_min, d4_max], fmt='.k', ecolor='gray', lw=3, capsize=5)
    plt.savefig('increase_in_processing.png', bbox_inches='tight')
    plt.savefig('increase_in_processing.eps', bbox_inches='tight')


