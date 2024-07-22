from gevent import monkey; monkey.patch_all(thread=False)

import hashlib
import json
import logging
import os
import pickle
import traceback
import gevent
import time
import numpy as np
from gevent import Greenlet
from gevent.event import Event
from gevent.queue import Queue
from collections import namedtuple
from enum import Enum


from bdtplus.core.superfastpath_3 import sufastpath
from crypto.threshsig.boldyreva import TBLSPrivateKey, TBLSPublicKey
from crypto.ecdsa.ecdsa import PrivateKey
from honeybadgerbft.exceptions import UnknownTagError
from crypto.ecdsa.ecdsa import ecdsa_sign, ecdsa_vrfy, PublicKey


def set_consensus_log(id: int):
    logger = logging.getLogger("consensus-node-"+str(id))
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s %(filename)s [line:%(lineno)d] %(funcName)s %(levelname)s %(message)s ')
    if 'log' not in os.listdir(os.getcwd()):
        os.mkdir(os.getcwd() + '/log')
    full_path = os.path.realpath(os.getcwd()) + '/log/' + "consensus-node-"+str(id) + ".log"
    file_handler = logging.FileHandler(full_path)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger

def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


class BroadcastTag(Enum):

    FAST = 'FAST'
    VIEW_CHANGE = 'VIEW_CHANGE'



BroadcastReceiverQueues = namedtuple(
    'BroadcastReceiverQueues', ('FAST','VIEW_CHANGE'))


def broadcast_receiver_loop(recv_func, recv_queues):
    while True:
        #gevent.sleep(0)
        sender, (tag, msg) = recv_func()
        if tag not in BroadcastTag.__members__:
            # TODO Post python 3 port: Add exception chaining.
            # See https://www.python.org/dev/peps/pep-3134/
            raise UnknownTagError('Unknown tag: {}! Must be one of {}.'.format(
                tag, BroadcastTag.__members__.keys()))
        recv_queue = recv_queues._asdict()[tag]
        try:
            recv_queue.put_nowait((sender, msg))
        except AttributeError as e:
            print("error", sender, (tag, msg))
            traceback.print_exc()


class SUFP():
    """Mule object used to run the protocol

    :param str sid: The base name of the common coin that will be used to
        derive a nonce to uniquely identify the coin.
    :param int pid: Node id.
    :param int Bfast: Batch size of transactions.
    :param int Bacs: Batch size of transactions.
    :param int N: Number of nodes in the network.
    :param int f: Number of faulty nodes that can be tolerated.
    :param TBLSPublicKey sPK: Public key of the (f, N) threshold signature.
    :param TBLSPrivateKey sSK: Signing key of the (f, N) threshold signature.
    :param TBLSPublicKey sPK1: Public key of the (N-f, N) threshold signature.
    :param TBLSPrivateKey sSK1: Signing key of the (N-f, N) threshold signature.
    :param list sPK2s: Public key(s) of ECDSA signature for all N parties.
    :param PrivateKey sSK2: Signing key of ECDSA signature.
    :param str ePK: Public key of the threshold encryption.
    :param str eSK: Signing key of the threshold encryption.
    :param send:
    :param recv:
    :param K: a test parameter to specify break out after K epochs
    """

    def __init__(self, sid, pid, S, T, Bfast, Bacs, N, f, l, sPK, sSK, sPK1, sSK1, sPK2s, sSK2, ePK, eSK, send, recv, K=3, mute=False, omitfast=False):

        self.SLOTS_NUM = S
        self.TIMEOUT = T
        self.FAST_BATCH_SIZE = Bfast
        self.FALLBACK_BATCH_SIZE = Bacs

        self.sid = sid
        self.id = pid
        self.N = N
        self.f = f
        self.sPK = sPK
        self.sSK = sSK
        self.sPK1 = sPK1
        self.sSK1 = sSK1
        self.sPK2s = sPK2s
        self.sSK2 = sSK2
        self.ePK = ePK
        self.eSK = eSK
        self._send = send
        self._recv = recv
        self.logger = set_consensus_log(pid)
        self.epoch = 0  # Current block number
        self.transaction_buffer = Queue()
        self._per_epoch_recv = {}  # Buffer of incoming messages
        self.leader = l
        self.K = K

        self.s_time = 0
        self.e_time = 0

        self.txcnt = 0
        self.txdelay = 0
        self.vcdelay = []

        self.mute = mute
        self.omitfast = omitfast

    def submit_tx(self, tx):
        """Appends the given transaction to the transaction buffer.

        :param tx: Transaction to append to the buffer.
        """
        # print('backlog_tx', self.id, tx)
        #if self.logger != None:
        #    self.logger.info('Backlogged tx at Node %d:' % self.id + str(tx))
        self.transaction_buffer.put_nowait(tx)

    def run_bft(self):
        """Run the Mule protocol."""

        if self.mute:
            muted_nodes = [each * 4 + 1 for each in range(int((self.N-1)/4))]
            if self.id in muted_nodes:
                #T = 0.00001
                while True:
                    time.sleep(10)

        #if self.mute:
        #    muted_nodes = [each * 3 + 1 for each in range(int((self.N-1)/3))]
        #    if self.id in muted_nodes:
        #        self._send = lambda j, o: time.sleep(100)
        #        self._recv = lambda: (time.sleep(100) for i in range(10000))

        def _recv_loop():
            """Receive messages."""
            while True:
                #gevent.sleep(0)
                try:
                    (sender, (r, msg)) = self._recv()
                    if self.id == self.leader:
                        print('recv', sender)
                    # Maintain an *unbounded* recv queue for each epoch
                    if r not in self._per_epoch_recv:
                        self._per_epoch_recv[r] = Queue()
                    # Buffer this message
                    self._per_epoch_recv[r].put_nowait((sender, msg))
                except:
                    continue

        #self._recv_thread = gevent.spawn(_recv_loop)
        self._recv_thread = Greenlet(_recv_loop)
        self._recv_thread.start()

        self.s_time = time.time()
        if self.logger != None:
            self.logger.info('Node %d starts to run at time:' % self.id + str(self.s_time))

        while True:

            # For each epoch
            e = self.epoch

            if e not in self._per_epoch_recv:
                self._per_epoch_recv[e] = Queue()

            def make_epoch_send(e):
                def _send(j, o):
                    self._send(j, (e, o))
                return _send

            send_e = make_epoch_send(e)
            recv_e = self._per_epoch_recv[e].get

            self._run_epoch(e, send_e, recv_e)

            # print('new block at %d:' % self.id, new_tx)
            #if self.logger != None:
            #    self.logger.info('Node %d Delivers Block %d: ' % (self.id, self.epoch) + str(new_tx))

            # print('buffer at %d:' % self.id, self.transaction_buffer)
            #if self.logger != None:
            #    self.logger.info('Backlog Buffer at Node %d:' % self.id + str(self.transaction_buffer))

            self.e_time = time.time()
            if self.logger != None:
                self.logger.info("node %d breaks in %f seconds in epoch %d with total delivered Txs %d and average delay %f" % (self.id, self.e_time-self.s_time, e, self.txcnt, self.txdelay) )
            else:
                print("node %d breaks in %f seconds with total delivered Txs %d and average delay %f" % (self.id, self.e_time-self.s_time, self.txcnt, self.txdelay))

            self.epoch += 1  # Increment the round
            if self.epoch >= self.K:
                break

            #gevent.sleep(0)

    def _recovery(self):
        # TODO: here to implement to recover blocks
        pass

    #
    def _run_epoch(self, e, send, recv):
        """Run one protocol epoch.

        :param int e: epoch id
        :param send:
        :param recv:
        """
        if self.logger != None:
            self.logger.info('Node enters epoch %d' % e)
        s_etime = time.time()
        sid = self.sid
        pid = self.id
        N = self.N
        f = self.f
        leader = self.leader

        T = self.TIMEOUT
        #if e == 0:
        #    T = 15
        #if self.mute:
        #    muted_nodes = [each * 3 + 1 for each in range(int((N-1)/3))]
        #    if leader in muted_nodes:
        #        T = 0.00001

        #S = self.SLOTS_NUM
        #T = self.TIMEOUT
        #B = self.FAST_BATCH_SIZE

        epoch_id = sid + 'FAST' + str(e)
        hash_genesis = hash(epoch_id)

        fast_recv = Queue()  # The thread-safe queue to receive the messages sent to fast_path of this epoch
        vc_recv = Queue()
        recv_queues = BroadcastReceiverQueues(
            FAST=fast_recv,
            VIEW_CHANGE=vc_recv
        )
        recv_t = gevent.spawn(broadcast_receiver_loop, recv, recv_queues)

        fast_blocks = Queue(1)  # The blocks that receives
        fixed_block = None
        latest_delivered_block = None
        latest_deliver_data = None

        viewchange_counter = 0
        viewchange_max_slot = 0

        def _setup_fastpath(leader):

            def fastpath_send(k, o):
                send(k, ('FAST', o))

            def fastpath_output(o):
                nonlocal latest_delivered_block, latest_deliver_data
                if not fast_blocks.empty():
                    fixed_block = fast_blocks.get()
                    #tx_cnt = str(latest_delivered_block).count("Dummy TX")
                    #self.txcnt += tx_cnt
                    #if self.logger is not None:
                    #    self.logger.info('Node %d Delivers Fastpath Block in Epoch %d at Slot %d with having %d TXs' % (self.id, self.epoch, latest_delivered_block[1], tx_cnt))
                latest_delivered_block, latest_deliver_data = o
                fast_blocks.put(o)

            fast_thread = gevent.spawn(sufastpath, epoch_id, pid, N, f, leader,
                                   self.transaction_buffer.get_nowait, fastpath_output,
                                   self.SLOTS_NUM, self.FAST_BATCH_SIZE, T,
                                   hash_genesis, self.sPK2s, self.sSK2,
                                   fast_recv.get, fastpath_send, logger=self.logger, omitfast=self.omitfast)

            return fast_thread

        # Start the fast path

        fast_thread = _setup_fastpath(leader)

        # Wait either view_change handler done or fast_path done
        vc_ready = gevent.event.Event()
        vc_ready.clear()
        suoutput = [None] *2

        def wait_for_fastpath():
            suoutput[0], suoutput[1] = fast_thread.get()
            # print(suoutput[1])
            vc_ready.set()
            if self.logger != None:
                self.logger.info('Fastpath of epoch %d completed' % e)
            (txcnt, tps, weighted_delay) = suoutput[1]


        gevent.spawn(wait_for_fastpath)

        #lst = [vc_thread, fast_thread]
        #for g in lst:
        #    g.link(lambda *args: ready.set())

        vc_ready.wait()

        start_vc = time.time()

        # Get the returned notarization of the fast path, which contains the combined Signature for the tip of chain
        notarization = suoutput
        try:
            if not fast_blocks.empty():
                fixed_block, fixed_data = fast_blocks.get()
            #notarization = fast_thread.get(block=False)
            if notarization is not None:
                assert fixed_block is not None
                # (epoch_txcnt, weighted_delay) = suoutput[1]
                # e_time = time.time()
                # self.txdelay = (self.txcnt * self.txdelay + epoch_txcnt * weighted_delay) / (self.txcnt + epoch_txcnt)
                # self.txcnt += epoch_txcnt
                # tps = int(epoch_txcnt) / (e_time - s_etime)
                (txcnt, tps, weighted_delay) = suoutput[1]
                if self.logger:
                    self.logger.info('Fastpath tps: %d delay %f' % (tps, weighted_delay))

                #assert hash(notarized_block_header) == notarized_block_hash

                send(leader, ('VIEW_CHANGE', (txcnt, weighted_delay, tps)))
                print(pid, "send vc!")
            # else:
            #     notarized_block_header = None
            #     o = (notarized_block_header, None)
            #     send(-1, ('VIEW_CHANGE', o))
        except AssertionError:
            print("Problematic notarization....")
        #except gevent.timeout.Timeout:
        #    assert notarization is None
        #    notarized_block_header = None
        #    o = (notarized_block_header, None)
        #    send(-1, ('VIEW_CHANGE', '', o))

        end_vc = time.time()
        count = 0
        de = 0
        t = 0

        if self.id == leader:
            while True:
                sender, msg = vc_recv.get()
                print("recv", sender, msg)
                cnt, delay, tps = msg
                de += delay
                t += tps
                count += 1
                if count == self.N:
                    print("=====================")
                    print("avg delay:", de/self.N)
                    print("avg tps  :", t/self.N)
                    print("=====================")
                    if self.logger:
                        self.logger.info('=====================')
                        self.logger.info('avg dealy: %f' % (de/self.N))
                        self.logger.info('avg tps  : %d', (t/self.N))
                        self.logger.info('=====================')
                    gevent.sleep(5)
                    break
        else:
            gevent.sleep(5)
        # if self.logger != None:
        #    self.logger.info('VIEW CHANGE costs time: %f' % (end_vc - start_vc) )
        # self.vcdelay.append(end_vc - start_vc)

        #print(("fast blocks: ", fast_blocks))


