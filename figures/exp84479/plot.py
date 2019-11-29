import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns
import numpy as np
import math
import matplotlib

font = {'size': 26}
matplotlib.rc('font', **font)

def get_are(filename):
    ares = []
    with open(filename, "r") as f:
        for line in f:
            items = line.split(" ")
            if "are_of_flow_size_estimation:" == items[0]:
                ares.append(float(items[1]))
    return ares

if __name__ == "__main__":
    ########## For CAIDA trace ##########
    d1_are = get_are("./res_HashFlow_d1.txt")
    d2_are = get_are("./res_HashFlow_d2.txt")
    d3_are = get_are("./res_HashFlow_d3.txt")
    d4_are = get_are("./res_HashFlow_d4.txt")
    print(d1_are)
    print(d2_are)
    print(d3_are)
    print(d4_are)

    pos = range(4)
    width = 0.2
    fig, ax = plt.subplots(figsize=(7, 5))
    plt.bar(pos, d1_are, width, alpha=1.0, color='blue', label="depth=1")
    plt.bar([p + width for p in pos],
        d2_are, width, alpha=1.0, color='red', label='depth=2')
    plt.bar([p + 2*width for p in pos],
        d3_are, width, alpha=1.0, color='green', label='depth=3')
    plt.bar([p + 3*width for p in pos],
        d4_are, width, alpha=1.0, color='purple', label='depth=4')
    ax.set_ylabel('ARE')
    ax.set_xlabel("Traces")
    ax.set_xticks([0.3, 1.3, 2.3, 3.3])
    ax.set_xticklabels(["CAIDA", "Campus", "ISP1", "ISP2"])
    plt.xlim(-0.2, 3.8)

#    plt.legend(["depth=1", "depth=2", "depth=3", "depth=4"],  
#        bbox_to_anchor=(0.0, 1.02, 1.0, 0.102), loc=2, ncol=4, mode='expand', 
#        borderaxespad = 0.0)
#    plt.legend(["depth=1", "depth=2", "depth=3", "depth=4"])
    plt.legend(loc=0)
    plt.ylim(0, 1)
    plt.savefig('are_with_depth.pdf', bbox_inches='tight')
    plt.savefig('are_with_depth.png', bbox_inches='tight')
    plt.savefig('are_with_depth.eps', bbox_inches='tight')
    
