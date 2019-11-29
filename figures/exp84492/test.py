import csv
filename = "/home/zongyi/Trace/ChinaTelecom/temp.csv"
n = 10
count = 0
with open(filename, "r") as f:
	reader = csv.reader(f, delimiter=",")
	for line in reader:
		print line[1]
		count = count + 1
		if count >= n:
			break
