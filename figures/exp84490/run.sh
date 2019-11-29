#!/bin/bash
n_flows=50
for trace in caida tsinghua hgc telecom
do
	cd /home/zongyi/P4/bmv2/targets/simple_switch/
	rm simple_switch.cpp
	cp ./simple_switch_"$trace"_"$n_flows"K.cpp simple_switch.cpp
	cd /home/zongyi/P4/bmv2/
	make install
	for alg in HashFlow HashPipe ElasticSketch FlowRadar
	do
		echo "#n_pkts n_hashes n_mem_access" > /home/zongyi/workspace/exp84490/res_"$trace"_"$alg".txt
		for i in 1 2 3
		do
			cd /home/zongyi/workspace/P4/$alg/
			./switch.sh&
			cd /home/zongyi/workspace/exp84490/
			echo $trace $alg
			python loop.py
			python controller.py --alg $alg --trace $trace
			pkill switch.sh
			pkill lt-simple
		done
	done
done
