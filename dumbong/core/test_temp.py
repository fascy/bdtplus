import hashlib
import pickle
import time
from collections import defaultdict
from queue import Queue

import gevent
from gevent.event import Event

from gevent import Timeout


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


oks = defaultdict(lambda: defaultdict(lambda: list()))

oks[0]['aasd'].append((1, 2, 3, 4))
oks[0]['aasd'].append((5, 6, 7, 8))

for i in oks[0]:
    if len(oks[0][i]) >= 2:
        VS0 = tuple((oks[0][i][j][0], hash(oks[0][i][j][1])) for j in range(2))
        # print(oks[0][i][0][1])

count = set()
votes = defaultdict(lambda: dict())
decide_sent = [False] * 10

decides = defaultdict(lambda: Queue(1))


def handle(j):
    print("start to handle msg")
    Sigma = tuple(votes[j].items())
    print(Sigma)


def sub():
    print("start to count timeout in slot", j)
    gevent.sleep(2)
    if not decide_sent[j]:
        print("timeout~ start to handle msg in slot", j)
        handle(j)
        decide_sent[j] = True


def msg_handle():
    for j in range(5):


        for i in range(4):
            print("rec msg", j, ":", i)
            votes[j][i] = i
            if len(votes[j]) == 4 and not decide_sent[j]:
                print("len", len(votes[j]))
                handle(j)
                decide_sent[j] = True
                decides[j].put_nowait(votes[j])
                print("set!", j)
                break

            gevent.sleep(1)


t2 = gevent.spawn(msg_handle)


def one_slot():
    t = gevent.spawn(sub)
    print("============start slot ", j, "===============")


    print("============output slot ", j, decides[j].get(), "===============")




# msg.set()
for j in range(5):

    timeout = Timeout(4)
    # print(TIMEOUT)
    timeout.start()
    try:
        with gevent.Timeout(4, False):
            # with Timeout(TIMEOUT):
            # gevent.spawn(one_slot).join(timeout=Timeout)
            # if omitfast is False:

            one_slot()
            # else:
            #    while True:
            #        gevent.sleep(0.01)
    except Timeout as e:
        # slot_noncritical_signal.wait()
        # gevent.killall([recv_thread])
        print("Fastpath Timeout" + str(e))
    timeout.cancel()
    timeout.close()

t2.join()
