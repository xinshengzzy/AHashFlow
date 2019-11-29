import argparse
from mytools import utility
from mytools.p4runtime import *
import time
import shutil
import sys

if __name__ == "__main__":
	args = get_parser().parse_args()
	filename = "res_" + args.trace + "_" + args.alg + ".txt"
	print "filename:", filename
	res = utility.dump_temp_register()
	l = " ".join([str(res[0]), str(res[1]), str(res[2])])	
	with open(filename, "a") as f:
		f.write(l + "\n")
