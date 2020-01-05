n = 100000
alpha = 0.8
zipf = [0]*(n + 1)
for i in range(1, n+1):
	temp = 1.0/(i**alpha)
	zipf[i] = zipf[i-1] + temp

for i in range(n + 1):
	zipf[i] = zipf[i]/zipf[-1]
for item in zipf:
	print item
