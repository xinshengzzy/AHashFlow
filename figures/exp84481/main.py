from mytools import utility

def sim_utilization_calc(dstfile, coefficient):
	with open(dstfile, "w") as f:
		n_cells = 50000
		n_flows = int(coefficient*n_cells)
		for n_hashes in range(1, 11):
			temp = 0
			for i in range(10):
				temp = temp + utility.hash_table(n_flows = n_flows, n_cells = n_cells, n_hashes = n_hashes)
			temp = temp/10.0
			f.write(str(n_hashes) + " " + str(temp) + "\n")

def utilization_calc(dstfile, coefficient):
	with open(dstfile, "w") as f:
		e = 2.71828
		p = [0]*11
		p[0] = 1
		for i in range(1, 11):
			p[i] = p[i - 1]*((1/e)**p[i-1])*((1/e)**(coefficient - 1))
		u = [0]*11
		for i in range(1, 11):
			u[i] = 1 - p[i]
			f.write(str(i) + " " + str(u[i]) + "\n")

if __name__ == "__main__":
	utilization_calc("./utilization_coe_1.txt", 1.0)
	utilization_calc("./utilization_coe_2.txt", 2.0)
	utilization_calc("./utilization_coe_3.txt", 3.0)
	utilization_calc("./utilization_coe_4.txt", 4.0)

	sim_utilization_calc("./sim_utilization_coe_1.txt", 1.0)
	sim_utilization_calc("./sim_utilization_coe_2.txt", 2.0)
	sim_utilization_calc("./sim_utilization_coe_3.txt", 3.0)
	sim_utilization_calc("./sim_utilization_coe_4.txt", 4.0)
