def flow_size_dist(src, dst):
	d = {}
	n_flows = 0
	max_size = 0
	with open(src, "r") as f:
		for line in f:
			if "#" == line[0]:
				continue
			items = line.split(" ")
			flow_size = int(items[5])
			n_flows = n_flows + 1
			if flow_size > max_size:
				max_size = flow_size
			if flow_size in d:
				d[flow_size] = d[flow_size] + 1
			else:
				d[flow_size] = 1
	lst = [0]*(max_size+1)
	for i in range(1, max_size+1):
		if i in d:
			lst[i] = lst[i - 1] + d[i]
		else:
			lst[i] = lst[i - 1]
	length = len(lst)
	total_flow = lst[length - 1]
	for i in range(length):
		lst[i] = lst[i]/float(total_flow)
	l = " ".join([str(item) for item in lst])
	with open(dst, "w") as f:
		f.write(l)
	



if __name__ == "__main__":
	flow_size_dist("../trace/caida/tracefile", "./caida_distribution.txt")
	flow_size_dist("../trace/tsinghua/20140207-19", "./tsinghua_distribution.txt")
	flow_size_dist("../trace/hgc/tracefile", "./hgc_distribution.txt")
	flow_size_dist("../trace/telecom/tracefile", "./telecom_distribution.txt")
