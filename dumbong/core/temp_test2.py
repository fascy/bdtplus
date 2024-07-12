import time
from collections import defaultdict

import gevent
vote = defaultdict()
count = set()
VS0 = tuple()
str1 = "SIDA-PCBC-1"
str2 = "SIDA-PCBC-2"
splitstrs = str2.split('-')
print(splitstrs)
last_e = int(splitstrs[-1])-1
splitstrs[2] = str(last_e)
print('-'.join(splitstrs))

print(len(tuple()))
vote[0] = (123)
vote[2] = (2234)
vote[3] = (32345)
Sigma = tuple(vote.items())[:2]
print(Sigma)
s_t = time.time()
has_sent = False
for i in range(100):
    if i <= 8:
        print("rec msg ", i)
        count.add(i)
    gevent.sleep(0.05)
    if len(count) == 10 and time.time()-s_t <= 1 and not has_sent:
        print("fastpasth")
        has_sent = True
    elif len(count) >= 3 and time.time()-s_t > 1 and not has_sent:
        print("normal path")
        has_sent = True