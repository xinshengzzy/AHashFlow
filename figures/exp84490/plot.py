import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import numpy as np
import math
import matplotlib

font = {'size': 26}
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
    

if __name__ == "__main__":
    hash_hf_caida, mem_hf_caida = get_res("./res_caida_HashFlow.txt")
    hash_hp_caida, mem_hp_caida = get_res("./res_caida_HashPipe.txt")
    hash_es_caida, mem_es_caida = get_res("./res_caida_ElasticSketch.txt")
    hash_fr_caida, mem_fr_caida = get_res("./res_caida_FlowRadar.txt")

    hash_hf_tsinghua, mem_hf_tsinghua = get_res("./res_tsinghua_HashFlow.txt")
    hash_hp_tsinghua, mem_hp_tsinghua = get_res("./res_tsinghua_HashPipe.txt")
    hash_es_tsinghua, mem_es_tsinghua = get_res("./res_tsinghua_ElasticSketch.txt")
    hash_fr_tsinghua, mem_fr_tsinghua = get_res("./res_tsinghua_FlowRadar.txt")

    hash_hf_hgc, mem_hf_hgc = get_res("./res_hgc_HashFlow.txt")
    hash_hp_hgc, mem_hp_hgc = get_res("./res_hgc_HashPipe.txt")
    hash_es_hgc, mem_es_hgc = get_res("./res_hgc_ElasticSketch.txt")
    hash_fr_hgc, mem_fr_hgc = get_res("./res_hgc_FlowRadar.txt")

    hash_hf_telecom, mem_hf_telecom = get_res("./res_telecom_HashFlow.txt")
    hash_hp_telecom, mem_hp_telecom = get_res("./res_telecom_HashPipe.txt")
    hash_es_telecom, mem_es_telecom = get_res("./res_telecom_ElasticSketch.txt")
    hash_fr_telecom, mem_fr_telecom = get_res("./res_telecom_FlowRadar.txt")

    ########## For Average Number of Hashes ##########
    hash_hf_min = [min(hash_hf_caida), min(hash_hf_tsinghua), min(hash_hf_hgc), min(hash_hf_telecom)]
    hash_hf_max = [max(hash_hf_caida), max(hash_hf_tsinghua), max(hash_hf_hgc), max(hash_hf_telecom)]
    hash_hf_mean = [mean(hash_hf_caida), mean(hash_hf_tsinghua), mean(hash_hf_hgc), mean(hash_hf_telecom)]
    hash_hf_lower = subtract(hash_hf_mean, hash_hf_min)
    hash_hf_upper = subtract(hash_hf_max, hash_hf_mean)

    hash_hp_min = [min(hash_hp_caida), min(hash_hp_tsinghua), min(hash_hp_hgc), min(hash_hp_telecom)]
    hash_hp_max = [max(hash_hp_caida), max(hash_hp_tsinghua), max(hash_hp_hgc), max(hash_hp_telecom)]
    hash_hp_mean = [mean(hash_hp_caida), mean(hash_hp_tsinghua), mean(hash_hp_hgc), mean(hash_hp_telecom)]
    hash_hp_lower = subtract(hash_hp_mean, hash_hp_min)
    hash_hp_upper = subtract(hash_hp_max, hash_hp_mean)


    hash_es_min = [min(hash_es_caida), min(hash_es_tsinghua), min(hash_es_hgc), min(hash_es_telecom)]
    hash_es_max = [max(hash_es_caida), max(hash_es_tsinghua), max(hash_es_hgc), max(hash_es_telecom)]
    hash_es_mean = [mean(hash_es_caida), mean(hash_es_tsinghua), mean(hash_es_hgc), mean(hash_es_telecom)]
    hash_es_lower = subtract(hash_es_mean, hash_es_min)
    hash_es_upper = subtract(hash_es_max, hash_es_mean)


    hash_fr_min = [min(hash_fr_caida), min(hash_fr_tsinghua), min(hash_fr_hgc), min(hash_fr_telecom)]
    hash_fr_max = [max(hash_fr_caida), max(hash_fr_tsinghua), max(hash_fr_hgc), max(hash_fr_telecom)]
    hash_fr_mean = [mean(hash_fr_caida), mean(hash_fr_tsinghua), mean(hash_fr_hgc), mean(hash_fr_telecom)]
    hash_fr_lower = subtract(hash_fr_mean, hash_fr_min)
    hash_fr_upper = subtract(hash_fr_max, hash_fr_mean)
    
#    print("hashflow:", hash_hf_mean)
#    print("hashpipe:", hash_hp_mean)

    pos = range(4)
    width = 0.2
    fig, ax = plt.subplots(figsize=(7, 5))
#    fig, ax = plt.subplots(figsize=(5, 5))
#    plt.figure()
    plt.bar(pos, hash_hf_mean, width, alpha=1.0, color='blue', label="HashFlow")
    plt.bar([p + width for p in pos],
        hash_hp_mean, width, alpha=1.0, color='red', label='HashPipe')
    plt.bar([p + 2*width for p in pos],
        hash_es_mean, width, alpha=1.0, color='green', label='ElasticSketch')
    plt.bar([p + 3*width for p in pos],
        hash_fr_mean, width, alpha=1.0, color='purple', label='FlowRadar')
    ax.set_ylabel('Ave. Num. of Hashes')
    ax.set_xlabel("Traces")
    ax.set_xticks([0.3, 1.3, 2.3, 3.3])
    ax.set_xticklabels(["CAIDA", "Campus", "ISP1", "ISP2"])
    plt.xlim(-0.2, 3.8)

    plt.legend(["HF", "HP", "ES", "FR"],  
        bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc=3, ncol=2, mode='expand', 
        borderaxespad = 0.0)



    plt.errorbar(pos, hash_hf_mean, [hash_hf_lower, hash_hf_upper], fmt='.k', ecolor='gray', lw=3, capsize=5)
    plt.errorbar([p + width for p in pos], 
        hash_hp_mean, [hash_hp_lower, hash_hp_upper], fmt='.k', ecolor='gray', lw=3, capsize=5)
    plt.errorbar([p + 2*width for p in pos], 
        hash_es_mean, [hash_es_lower, hash_es_upper], fmt='.k', ecolor='gray', lw=3, capsize=5)
    plt.errorbar([p + 3*width for p in pos], 
        hash_fr_mean, [hash_fr_lower, hash_fr_upper], fmt='.k', ecolor='gray', lw=3, capsize=5)
    plt.savefig('ave_hash.pdf', bbox_inches='tight')
    plt.savefig('ave_hash.png', bbox_inches='tight')
    plt.savefig('ave_hash.eps', bbox_inches='tight')


    ########## For Average Number of Memory Accesses ##########
    mem_hf_min = [min(mem_hf_caida), min(mem_hf_tsinghua), min(mem_hf_hgc), min(mem_hf_telecom)]
    mem_hf_max = [max(mem_hf_caida), max(mem_hf_tsinghua), max(mem_hf_hgc), max(mem_hf_telecom)]
    mem_hf_mean = [mean(mem_hf_caida), mean(mem_hf_tsinghua), mean(mem_hf_hgc), mean(mem_hf_telecom)]
    mem_hf_lower = subtract(mem_hf_mean, mem_hf_min)
    mem_hf_upper = subtract(mem_hf_max, mem_hf_mean)


    mem_hp_min = [min(mem_hp_caida), min(mem_hp_tsinghua), min(mem_hp_hgc), min(mem_hp_telecom)]
    mem_hp_max = [max(mem_hp_caida), max(mem_hp_tsinghua), max(mem_hp_hgc), max(mem_hp_telecom)]
    mem_hp_mean = [mean(mem_hp_caida), mean(mem_hp_tsinghua), mean(mem_hp_hgc), mean(mem_hp_telecom)]
    mem_hp_lower = subtract(mem_hp_mean, mem_hp_min)
    mem_hp_upper = subtract(mem_hp_max, mem_hp_mean)


    mem_es_min = [min(mem_es_caida), min(mem_es_tsinghua), min(mem_es_hgc), min(mem_es_telecom)]
    mem_es_max = [max(mem_es_caida), max(mem_es_tsinghua), max(mem_es_hgc), max(mem_es_telecom)]
    mem_es_mean = [mean(mem_es_caida), mean(mem_es_tsinghua), mean(mem_es_hgc), mean(mem_es_telecom)]
    mem_es_lower = subtract(mem_es_mean, mem_es_min)
    mem_es_upper = subtract(mem_es_max, mem_es_mean)


    mem_fr_min = [min(mem_fr_caida), min(mem_fr_tsinghua), min(mem_fr_hgc), min(mem_fr_telecom)]
    mem_fr_max = [max(mem_fr_caida), max(mem_fr_tsinghua), max(mem_fr_hgc), max(mem_fr_telecom)]
    mem_fr_mean = [mean(mem_fr_caida), mean(mem_fr_tsinghua), mean(mem_fr_hgc), mean(mem_fr_telecom)]
    mem_fr_lower = subtract(mem_fr_mean, mem_fr_min)
    mem_fr_upper = subtract(mem_fr_max, mem_fr_mean)

    print("hashflow:", mem_hf_mean)
    print("hashpipe:", mem_hp_mean)
    print("elasticksketch:", mem_es_mean)

    pos = range(4)
    width = 0.2
    fig, ax = plt.subplots(figsize=(7, 5))
    plt.bar(pos, mem_hf_mean, width, alpha=1.0, color='blue', label="HashFlow")
    plt.bar([p + width for p in pos],
        mem_hp_mean, width, alpha=1.0, color='red', label='HashPipe')
    plt.bar([p + 2*width for p in pos],
        mem_es_mean, width, alpha=1.0, color='green', label='ElasticSketch')
    plt.bar([p + 3*width for p in pos],
        mem_fr_mean, width, alpha=1.0, color='purple', label='FlowRadar')
    ax.set_ylabel('Ave. Num. of Mem. Access')
    ax.set_xlabel("Traces")
    ax.set_xticks([0.3, 1.3, 2.3, 3.3])
    ax.set_xticklabels(["CAIDA", "Campus", "ISP1", "ISP2"])
    plt.xlim(-0.2, 3.8)

    plt.legend(["HF", "HP", "ES", "FR"],  
        bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc=3, ncol=2, mode='expand', 
        borderaxespad = 0.0)



    plt.errorbar(pos, mem_hf_mean, [mem_hf_lower, mem_hf_upper], fmt='.k', ecolor='gray', lw=3, capsize=5)
    plt.errorbar([p + width for p in pos], 
        mem_hp_mean, [mem_hp_lower, mem_hp_upper], fmt='.k', ecolor='gray', lw=3, capsize=5)
    plt.errorbar([p + 2*width for p in pos], 
        mem_es_mean, [mem_es_lower, mem_es_upper], fmt='.k', ecolor='gray', lw=3, capsize=5)
    plt.errorbar([p + 3*width for p in pos], 
        mem_fr_mean, [mem_fr_lower, mem_fr_upper], fmt='.k', ecolor='gray', lw=3, capsize=5)
    plt.savefig('ave_mem.pdf', bbox_inches='tight')
    plt.savefig('ave_mem.png', bbox_inches='tight')
    plt.savefig('ave_mem.eps', bbox_inches='tight')


