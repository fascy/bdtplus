import hashlib
import pickle
import random
from collections import deque

import gevent
from gevent import Greenlet
from gevent.queue import Queue

from crypto.threshsig.generate_keys import dealer
from crypto.ecdsa.ecdsa import pki, ecdsa_sign
from ngbdt.core.bolt import bolt
from crypto.threshsig.boldyreva import deserialize1
"""
fast path+ superfast path v1
"""

def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


def simple_router(N, maxdelay=0.0001, seed=None):
    """Builds a set of connected channels, with random delay
    @return (receives, sends)
    """
    rnd = random.Random(seed)
    #if seed is not None: print 'ROUTER SEED: %f' % (seed,)

    queues = [Queue() for _ in range(N)]
    def makeSend(i):
        def _send(j, o):
            delay = rnd.random() * maxdelay
            if j == -2:
                for t in range(N):
                    if t != i:
                        # print('SEND %8s slot%2d [%2d -> %2d]' % (o[0], o[1], i, t))
                        gevent.spawn_later(delay, queues[t].put, (i, o))
            else:
                # print('SEND %8s slot%2d [%2d -> %2d]' % (o[0], o[1], i, j))
                gevent.spawn_later(delay, queues[j].put, (i,o))
            # gevent.spawn_later(delay, queues[j].put, (i, o))

        return _send

    def makeRecv(j):
        def _recv():
            (i, o) = queues[j].get()
            print ('RECV %8s %2d [%2d -> %2d]' % (o[0], o[1], i, j))
            return (i, o)

        return _recv


    return ([makeSend(i) for i in range(N)],
            [makeRecv(j) for j in range(N)])


def _test_fast(N=4, f=1, leader=None, seed=None):
    # Test everything when runs are OK
    sid = 'sidA-BLOT-2'
    leader = 1

    BATCH_SIZE = 2
    SLOTS_NUM = 10
    TIMEOUT1 = 0.2
    TIMEOUT2 = 5
    GENESIS = hash('GENESIS')

    # Note thld siganture for CBC has a threshold different from common coin's
    PK1, SK1s = dealer(N, N - f)
    PK2s, SK2s = pki(N)

    inputs = [Queue() for _ in range(N)]
    outputs = [deque() for _ in range(N)]

    for i in range(N):
        for j in range(BATCH_SIZE * SLOTS_NUM):
            inputs[i].put("<Dummy TX " + str(j) + " from node " + str(i) + ">")

    sends, recvs = simple_router(N, seed=seed)

    threads = []
    last_leader=2
    last_tx = "<Dummy TX " + str(2) + " from node " + str(2) + ">" + "<Dummy TX " + str(2) + " from node " + str(2) + ">"
    k = 2
    digest1 = hash(str((k+1, hash(last_tx))))
    ok_sig = ecdsa_sign(SK2s[last_leader], digest1)
    for i in range(N):
        if i == 0:
            t = Greenlet(bolt, sid, i, N, f, leader,
                     inputs[i].get_nowait, outputs[i].append, SLOTS_NUM, BATCH_SIZE, TIMEOUT1, TIMEOUT2,
                     k, GENESIS, last_tx, ok_sig, last_leader,
                     PK2s, SK2s[i], recvs[i], sends[i], None, None)
        else:
            t = Greenlet(bolt, sid, i, N, f, leader,
                         inputs[i].get_nowait, outputs[i].append, SLOTS_NUM, BATCH_SIZE, TIMEOUT1, TIMEOUT2,
                         k, GENESIS, 0, 0, last_leader,
                         PK2s, SK2s[i], recvs[i], sends[i], None, None)

        t.start()
        threads.append(t)

    gevent.joinall(threads)
    (h, raw_Sigma, _) = threads[0].get()

    notarized_block = outputs[2].pop()
    print(notarized_block[0])

    print(hash((notarized_block[0][1], hash(notarized_block[0][3]))) == h)
    print(h, raw_Sigma)
    # print(PK1.verify_signature(raw_Sigma[], PK1.hash_message(h)))


def test_fast(N, f, seed):
    _test_fast(N=N, f=f, seed=seed)


if __name__ == '__main__':
    test_fast(4, 1, None)
