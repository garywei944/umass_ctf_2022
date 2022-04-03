import numpy as np

for i in range(int(1e10)):
    D = np.random.randint(0, 2, (16, 16))
    E = np.random.randint(0, 2, (16, 16))

    if not (D @ E == E @ D).any():
        print(i)
        print(D)
        print(E)
 