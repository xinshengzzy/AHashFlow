import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import numpy as np
import math
import matplotlib

font = {'size': 18}
matplotlib.rc('font', **font)

def get_res(filename):
    ave_hashes = []
    ave_mem_access = []
    with open(filename, "r") as f:
        for line in f:
            if "#" == line[0]:
                continue
            items = line.split(" ")
            n_pkts = int(items[0])
            n_hashes = int(items[1])
            n_mem_access = int(items[2])
            ave_hashes.append(n_hashes/float(n_pkts))
            ave_mem_access.append(n_mem_access/float(n_pkts))
    return ave_hashes, ave_mem_access

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

def parse(filename):
    with open(filename, "r") as f:
        for line in f:
            if "#" == line[0]:
                continue
            items = line.split("\t")
            if "Tsinghua" == items[0] and "200000" == items[1]:
                tsinghua = [(float(x) - float(items[3]))/float(items[3]) for x in items[4:]]
            if "Telecom" == items[0] and "200000" == items[1]:
                telecom = [(float(x) - float(items[3]))/float(items[3]) for x in items[4:]]
            if "CAIDA" == items[0] and "200000" == items[1]:
                caida = [(float(x) - float(items[3]))/float(items[3]) for x in items[4:]]
            if "HGC" == items[0] and "200000" == items[1]:
                hgc = [(float(x) - float(items[3]))/float(items[3]) for x in items[4:]]
    print "caida:", caida
    print "tsinghua:", tsinghua
    print "hgc:", hgc
    print "telecom:", telecom
    d1 = [caida[0], tsinghua[0], hgc[0], telecom[0]]
    d2 = [caida[1], tsinghua[1], hgc[1], telecom[1]]
    d3 = [caida[2], tsinghua[2], hgc[2], telecom[2]]
    d4 = [caida[3], tsinghua[3], hgc[3], telecom[3]]
    return d1, d2, d3, d4
            
    

if __name__ == "__main__":
    d1, d2, d3, d4 = parse("./res.txt")

    pos = range(4)
    width = 0.2
    fig, ax = plt.subplots(figsize=(7, 5))
#    fig, ax = plt.subplots(figsize=(5, 5))
#    plt.figure()
    plt.bar(pos, d1, width, alpha=1.0, color='blue', label="depth=1")
    plt.bar([p + width for p in pos],
        d2, width, alpha=1.0, color='red', label='depth=2')
    plt.bar([p + 2*width for p in pos],
        d3, width, alpha=1.0, color='green', label='depth=3')
    plt.bar([p + 3*width for p in pos],
        d4, width, alpha=1.0, color='purple', label='depth=4')
    ax.set_ylabel('Increase in Processing')
    ax.set_xlabel("Traces")
    ax.set_xticks([0.3, 1.3, 2.3, 3.3])
    ax.set_xticklabels(["CAIDA", "Campus", "ISP1", "ISP2"])
    plt.xlim(-0.2, 3.8)

    plt.legend(["depth=1", "depth=2", "depth=3", "depth=4"],  
        bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc=3, ncol=2, mode='expand', 
        borderaxespad = 0.0)



#    plt.errorbar(pos, hash_hf_mean, [hash_hf_lower, hash_hf_upper], fmt='.k', ecolor='gray', lw=3, capsize=5)
#    plt.errorbar([p + width for p in pos], 
#        hash_hp_mean, [hash_hp_lower, hash_hp_upper], fmt='.k', ecolor='gray', lw=3, capsize=5)
#    plt.errorbar([p + 2*width for p in pos], 
#        hash_es_mean, [hash_es_lower, hash_es_upper], fmt='.k', ecolor='gray', lw=3, capsize=5)
#    plt.errorbar([p + 3*width for p in pos], 
#        hash_fr_mean, [hash_fr_lower, hash_fr_upper], fmt='.k', ecolor='gray', lw=3, capsize=5)
#    plt.savefig('ave_hash.pdf', bbox_inches='tight')
    plt.savefig('increase_in_processing.png', bbox_inches='tight')
    plt.savefig('increase_in_processing.eps', bbox_inches='tight')



