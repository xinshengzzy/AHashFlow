from matplotlib.patches import Ellipse
import matplotlib.pyplot as plt

plt.figure(1)
e = Ellipse(xy = (5,5), width = 10, height = 10)
plt.plot(e)
plt.show()
