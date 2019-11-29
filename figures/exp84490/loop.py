#!/usr/lib/python2.7
import os.path
import os
import time
print "Enter the loop..."
flag = False
while not flag:
	flag = os.path.isfile("/home/zongyi/workspace/flag.cmd")
	time.sleep(1)
os.remove("/home/zongyi/workspace/flag.cmd")
print "Exit the loop!"
