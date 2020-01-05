import sys
import json
if "__main__" == __name__:
	assert(5 == len(sys.argv))
	n = int(sys.argv[1])
	alpha = float(sys.argv[2])
	n_points = int(sys.argv[3])
	outfile = sys.argv[4]
	zipf = [0]*(n + 1)
	for i in range(1, n+1):
		temp = 1.0/(i**alpha)
		zipf[i] = zipf[i-1] + temp
	for i in range(n + 1):
		zipf[i] = zipf[i]/zipf[-1]

	leap = 1.0/n_points
	idx = []
	value = []
	for i in range(0, n_points + 1):
		idx.append(i*leap)
		value.append(zipf[int(i*leap*n)])
	with open(outfile, "w") as f:
		json.dump([idx, value], f)
