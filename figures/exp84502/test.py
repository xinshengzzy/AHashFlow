import json

with open("CAIDA1.json", "r") as f:
	l = json.load(f)

print len(l[0])
