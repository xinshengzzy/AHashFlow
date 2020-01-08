import simulators.AHashFlow as AHashFlow
from my_constants import *

for n in [2, 4]:
	for gamma in range(10):
		AHashFlow.set_n(n)
		AHashFlow.set_gamma(gamma)
		ahf = AHashFlow.AHashFlow("./test.txt", TYPE_JSON, -1)
