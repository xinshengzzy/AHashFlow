from mytools import utility

THEORY = 1
SIMULATION = 2

def func(alg, ratio, filename):
	n_cells = 100000
	n_flows = int(ratio*n_cells)
	with open(filename, "w") as f:
		f.write("#depth alpha=0.5 alpha=0.6 alpha=0.7 alpha=0.8 alpha=0.9 alpha=1.0\n")
		for depth in range(1, 11):
			lst = []
			lst.append(depth)
			for alpha in range(5, 11):
				alpha = alpha*0.1
				if THEORY == alg:
					util = utility.pipelined_tables_utilization_theo(depth, alpha, ratio)
				elif SIMULATION == alg:
					util = utility.pipelined_tables_utilization_sim(depth, alpha, n_flows, n_cells)
				else:
					print "Wrong algorithm type."
					exit()
				lst.append(util)
			l = " ".join([str(item) for item in lst])
			f.write(l + "\n")

if "__main__" == __name__:
	func(THEORY, 1.0, "./utilization_theory_ratio_10.txt")
	func(THEORY, 2.0, "./utilization_theory_ratio_20.txt")
	func(SIMULATION, 1.0, "./utilization_simulation_ratio_10.txt")
	func(SIMULATION, 2.0, "./utilization_simulation_ratio_20.txt")
