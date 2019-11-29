import json

res1 = "./resForCAIDA.txt"
res2 = "./resForHGC.txt"

for i in range(100, -1, -1):
	print i

exit()

with open(res1, "r") as f:
	l = json.load(f)

cnt = 0
for item in l:
	if item > 0.5:
		cnt = cnt + 1
print "cnt:", cnt
print "ratio:", float(cnt)/len(l)
