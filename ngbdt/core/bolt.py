from gevent import monkey;

monkey.patch_all(thread=False)

import traceback
import time
from collections import defaultdict
from gevent.event import Event
from gevent.queue import Queue
from gevent import Timeout
from crypto.ecdsa.ecdsa import ecdsa_sign, ecdsa_vrfy, PublicKey
import os
import json
import gevent
import hashlib, pickle


def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()


def bolt(sid, pid, N, f, leader, get_input, output_notraized_block, Snum, Bsize, Tout1, Tout2, k, hash_genesis, ok_tx,
         ok_sig, leader_l, PK2s, SK2, recv, send, omitfast=False, logger=None):
    """Fast path+superfast path v1, Byzantine Safe Broadcast
    :param str sid: ``the string of identifier``
    :param int pid: ``0 <= pid < N``
    :param int N:  at least 3
    :param int f: fault tolerance, ``N >= 3f + 1``
    :param int leader: the pid of leading node
    :param get_input: a function to get input TXs, e.g., input() to get a transaction
    :param output_notraized_block: a function to deliver notraized blocks, e.g., output(block)

    :param list PK2s: an array of ``coincurve.PublicKey'', i.e., N public keys of ECDSA for all parties
    :param PublicKey SK2: ``coincurve.PrivateKey'', i.e., secret key of ECDSA
    :param float Tout1: timeout of super-fast path
    :param float Tout2: timeout of a slot
    :param int k: output of tcv-BA[id-1]
    :param int Snum: number of slots in a epoch
    :param int Bsize: batch size, i.e., the number of TXs in a batch
    :param hash_genesis: the hash of genesis block
    :param recv: function to receive incoming messages
    :param send: function to send outgoing messages
    :param bcast: function to broadcast a message
    :return tuple: False to represent timeout, and True to represent success
    """

    if logger is not None:
        logger.info("Entering fast path")
    # print("Entering fast path")
    TIMEOUT1 = Tout1
    TIMEOUT2 = Tout2
    SLOTS_NUM = Snum
    BATCH_SIZE = Bsize

    assert leader in range(N)
    slot_cur = 1

    hash_prev = hash_genesis
    pending_block = None
    notraized_block = None
    fixed_block = None

    # Leader's temp variables
    okers = defaultdict(lambda: set())
    oks = defaultdict(lambda: defaultdict(lambda: list()))
    voters = defaultdict(lambda: set())
    votes = defaultdict(lambda: dict())
    decides = defaultdict(lambda: Queue(1))

    ok_sent = False
    decide_sent = [False] * (SLOTS_NUM + 3)  # The first item of the list is not used

    msg_noncritical_signal = Event()
    msg_noncritical_signal.set()

    slot_noncritical_signal = Event()
    slot_noncritical_signal.set()

    s_times = [0] * (SLOTS_NUM + 3)
    e_times = [0] * (SLOTS_NUM + 3)
    txcnt = [0] * (SLOTS_NUM + 3)
    delay = [0] * (SLOTS_NUM + 3)

    epoch_txcnt = 0
    weighted_delay = 0
    flag = -2
    vote_thresh = [0] * (SLOTS_NUM + 3)
    def handle_messages():
        nonlocal leader, hash_prev, pending_block, notraized_block, fixed_block, voters, votes, slot_cur, k, leader_l, ok_sent, flag, vote_thresh


        while True:

            # gevent.sleep(0)

            (sender, msg) = recv()
            # logger.info("receving a fast path msg " + str((sender, msg)))

            assert sender in range(N)

            ########################
            # Enter critical block #
            ########################

            msg_noncritical_signal.clear()
            if msg[0] == 'OK' and k > 0 and pid == leader and len(okers[slot_cur]) < N - f:
                _, k_s, ok_tx_s, ok_sig_l, sig_ok_s = msg
                print(k_s, ok_tx_s, ok_sig_l, sig_ok_s, sender)
                digest1 = hash(str((k_s, hash(ok_tx_s))))
                if ok_tx_s == 0:
                    okers[slot_cur].add(sender)

                    oks[slot_cur][digest1].append((sender, ok_tx_s, ok_sig_l, sig_ok_s))
                else:
                    try:
                        assert ecdsa_vrfy(PK2s[sender], digest1, sig_ok_s)
                        if ok_tx_s != 0:
                            print("ver leader")
                            assert ecdsa_vrfy(PK2s[leader_l], digest1, ok_sig_l)
                    except AssertionError:
                        if logger is not None:
                            logger.info("ok signature failed!")
                        print("ok signature failed!")
                        msg_noncritical_signal.set()
                        continue
                    okers[slot_cur].add(sender)
                    oks[slot_cur][digest1].append((sender, ok_tx_s, ok_sig_l, sig_ok_s))
                if len(okers[slot_cur]) == N - f and not ok_sent:
                    # look for a majority ok_tx_s
                    for i in oks[slot_cur]:
                        print("=====", oks[slot_cur][i])
                        if len(oks[slot_cur][i]) >= f + 1 and oks[slot_cur][i][0][1] != 0:
                            # VS0:(i, H(txs_k+1), sig_l, sig_s)
                            VS0 = tuple((oks[slot_cur][i][j][0], hash(oks[slot_cur][i][j][1]), oks[slot_cur][i][j][2],
                                         oks[slot_cur][i][j][3]) for j in range(f + 1))
                            print("VS0:", VS0)
                            tx_batch = oks[slot_cur][i][0][1]
                            sig_s = ecdsa_sign(SK2, hash(str((slot_cur, hash(tx_batch)))))
                            send(-2, ('DECIDE', slot_cur, 0, tx_batch, VS0, sig_s))
                            decides[slot_cur].put_nowait((-1, hash_prev, VS0, tx_batch))
                            ok_sent = True
                            break
                    # majority does not exists
                    if ok_sent == False:
                        # VS0:(i, H(txs_k+1), sig_l, sig_s)
                        VS0 = tuple(
                            (oks[slot_cur][i][j][0], hash(oks[slot_cur][i][j][1]), oks[slot_cur][i][j][2],
                             oks[slot_cur][i][j][3]) for i in oks[slot_cur] for j in range(len(oks[slot_cur][i])))
                        # TXs = 0
                        tx_batch = json.dumps([get_input()] * BATCH_SIZE)
                        digest_de = hash(str((slot_cur, hash(tx_batch))))
                        sig_s = ecdsa_sign(SK2, digest_de)
                        send(-2, ('DECIDE', slot_cur, 0, tx_batch, VS0, sig_s))
                        decides[slot_cur].put_nowait((-1, hash_prev, VS0, tx_batch))

            if msg[0] == 'VOTE' and pid == leader:

                # s-1 hash_vote, sig_vote
                _, slot, hash_p, sig_p = msg
                # _, slot, hash_p, raw_sig_p, tx_batch, tx_sig = msg
                # sig_p = deserialize1(raw_sig_p)

                if sender not in voters[slot_cur]:

                    try:
                        assert slot + 1 == slot_cur
                    except AssertionError:
                        if logger is not None:
                            # logger.info("vote out of sync from node %d" % sender)
                            pass
                        # if slot < slot_cur:
                        #    if logger is not None: logger.info("Late vote from node %d! Not needed anymore..." % sender)
                        # else:
                        #    if logger is not None: logger.info("Too early vote from node %d! I do not decide earlier block yet..." % sender)
                        msg_noncritical_signal.set()
                        continue

                    try:
                        assert hash_p == hash_prev
                    except AssertionError:
                        if logger is not None:
                            logger.info("False vote from node %d though within the same slot!" % sender)
                        print("False vote from node", sender, "though within the same slot!")
                        msg_noncritical_signal.set()
                        continue

                    try:
                        assert ecdsa_vrfy(PK2s[sender], hash_p, sig_p)
                    except AssertionError:
                        if logger is not None:
                            logger.info("Vote signature failed!")
                        msg_noncritical_signal.set()
                        continue

                    voters[slot_cur].add(sender)
                    print("voters[", slot_cur, "]", voters[slot_cur], len(voters[slot_cur]))
                    votes[slot_cur][sender] = sig_p
                    if len(voters[slot_cur]) == N and time.time()-s_times[slot_cur]<= TIMEOUT1 and not decide_sent[slot_cur]:
                        print("slot:", slot_cur, "superfast!")
                        flag = 1
                        Sigma = tuple(votes[slot_cur].items())
                    elif len(voters[slot_cur]) >= N-f and time.time()-s_times[slot_cur]> TIMEOUT1 and not decide_sent[slot_cur]:
                        flag = 0
                        Sigma = tuple(votes[slot_cur].items())[:N-f]
                    elif len(voters[slot_cur]) >= N-f:
                        vote_thresh[slot_cur] = 1
                    if flag > -1:
                        # Sigma = tuple(votes[slot_cur].items())
                        if slot_cur == SLOTS_NUM + 1 or slot_cur == SLOTS_NUM + 2:
                            tx_batch = 'Dummy'
                        else:
                            try:
                                tx_batch = json.dumps([get_input()] * BATCH_SIZE)
                            except Exception as e:
                                tx_batch = json.dumps(['Dummy' for _ in range(BATCH_SIZE)])
                        digest_de = hash(str((slot_cur, hash(tx_batch))))
                        sig_s = ecdsa_sign(SK2, digest_de)
                        # _, slot, hash_p, batches, Sigma_p, sigma_l
                        send(-2, ('DECIDE', slot_cur, hash_prev, tx_batch, Sigma, sig_s))
                        # if logger is not None: logger.info("Decide made and sent")
                        decide_sent[slot_cur] = True
                        decides[slot_cur].put_nowait((flag, hash_p, Sigma, tx_batch))


            if msg[0] == "DECIDE" and pid != leader:
                # (slot, TXs, VSs-1, sigma_s)
                _, slot, hash_p, batches, Sigma_p, sigma_l = msg
                # print(pid, "recv decide in slot", msg)
                try:
                    assert slot == slot_cur
                except AssertionError:
                    if logger is not None:
                        # logger.info("Out of synchronization")
                        pass
                    msg_noncritical_signal.set()
                    continue

                ret = False
                # deal with slot 1
                if slot == 1:
                    if k == 0:
                        decides[slot_cur].put_nowait((-1, hash_p, tuple(), batches))
                    elif k > 0:
                        sig_l_c = 0

                        # VS0:(i, H(txs_k+1), sig_l, sig_s)
                        if len(Sigma_p) == f + 1:
                            count_i = 0
                            for item in Sigma_p:
                                vid, hash_tx, sig_l, sig_vid = item
                                if count_i == 0:
                                    digest1 = hash(str((k + 1, hash(batches))))
                                try:
                                    if count_i == 0:
                                        assert ecdsa_vrfy(PK2s[leader_l], digest1, sig_l)
                                        sig_l_c = sig_l
                                    assert sig_l_c == sig_l
                                    assert hash_tx == hash(batches)
                                    count_i += 1
                                except AssertionError:
                                    if logger is not None:
                                        logger.info("not a valid sig for last leader")
                                    print("not a valid sig for last leader", item[0])
                                    msg_noncritical_signal.set()
                                    ret = True
                                    break
                                try:
                                    assert ecdsa_vrfy(PK2s[vid], digest1, sig_vid)
                                except AssertionError:
                                    if logger is not None:
                                        logger.info("In s1, invalid sig in VS0")
                                    print("In s1, invalid sig in VS0", item[0])
                                    msg_noncritical_signal.set()
                                    ret = True
                                    break
                        if len(Sigma_p) == N - f:
                            hash_tx_l = defaultdict()
                            for item in Sigma_p:
                                vid, hash_tx, sig_l, sig_vid = item
                                if hash_tx in hash_tx_l.keys():
                                    try:
                                        assert hash_tx_l[hash_tx][0] == sig_l
                                        assert ecdsa_vrfy(PK2s[vid], hash_tx_l[hash_tx][1], sig_vid)
                                        print("hash_tx_l", hash_tx_l[hash_tx][2])
                                        hash_tx_l[hash_tx][2] = hash_tx_l[hash_tx][2]+1
                                        # check there does not exist majority sig for tx
                                        if hash_tx_l[hash_tx][2] == f + 1 and hash_tx != hash(0):
                                            print("there exists a majority in VS0")
                                            ret = True
                                            msg_noncritical_signal.set()
                                            break
                                    except AssertionError:
                                        if logger is not None:
                                            logger.info("In s1(N-F), invalid sig in VS0")
                                        print("In s1(N-F), invalid sig in VS0", item[0])
                                        ret = True
                                        msg_noncritical_signal.set()

                                        break
                                else:
                                    digest1 = hash(str((k + 1, hash_tx)))
                                    try:
                                        if hash_tx != hash(0):
                                            assert ecdsa_vrfy(PK2s[leader_l], digest1, sig_l)
                                        assert ecdsa_vrfy(PK2s[vid], digest1, sig_vid)
                                        hash_tx_l[hash_tx] =list((sig_l, digest1, 1))
                                    except AssertionError:
                                        if logger is not None:
                                            logger.info("In s1(N-F), invalid sig in VS0", item[0])
                                        print("In s1(N-F), invalid sig in VS0", item[0])
                                        ret = True
                                        msg_noncritical_signal.set()

                                        break
                        decides[slot_cur].put_nowait((-1, hash_p, Sigma_p, batches))

                if slot > 1:
                    # print("here")
                    try:
                        assert len(Sigma_p) >= N - f
                    except AssertionError:
                        if logger is not None:
                            logger.info("No enough ecdsa signatures!")
                        msg_noncritical_signal.set()
                        continue

                    # VS_{s-1}:{(i, sigma_{s-1,i})}
                    try:
                        for item in Sigma_p:
                            # print(Sigma_p)
                            (sender, sig_p) = item
                            assert ecdsa_vrfy(PK2s[sender], hash_p, sig_p)
                    except AssertionError:
                        if logger is not None:
                            logger.info("ecdsa signature failed!")
                        ret = True
                        msg_noncritical_signal.set()
                        continue
                    if len(Sigma_p) == 2 * f + 1:
                        flag = 0
                    else:
                        flag = 1
                    # print("here decide:", slot, flag)
                    # if pid != 2 and slot_cur == 5:
                    #     gevent.sleep(5)
                    decides[slot_cur].put_nowait((flag, hash_p, Sigma_p, batches))

                if ret:
                    continue



            msg_noncritical_signal.set()

            ########################
            # Leave critical block #
            ########################

    """
    One slot
    """

    def one_slot():
        nonlocal k, ok_sig, ok_tx, pending_block, notraized_block, fixed_block, hash_prev, slot_cur, epoch_txcnt, delay, e_times, s_times, txcnt, weighted_delay, flag, vote_thresh
        vote_thresh[slot_cur] = 0
        def handle_vote():
            gevent.sleep(TIMEOUT1)
            print(slot_cur)
            if vote_thresh[slot_cur] == 1 and not decide_sent[slot_cur]:
                Sigma = tuple(votes[slot_cur].items())[:N - f]
                if slot_cur == SLOTS_NUM + 1 or slot_cur == SLOTS_NUM + 2:
                    tx_batch = 'Dummy'
                else:
                    try:
                        tx_batch = json.dumps([get_input()] * BATCH_SIZE)
                    except Exception as e:
                        tx_batch = json.dumps(['Dummy' for _ in range(BATCH_SIZE)])
                digest_de = hash(str((slot_cur, hash(tx_batch))))
                sig_s = ecdsa_sign(SK2, digest_de)
                # _, slot, hash_p, batches, Sigma_p, sigma_l
                send(-2, ('DECIDE', slot_cur, hash_prev, tx_batch, Sigma, sig_s))
                # if logger is not None: logger.info("Decide made and sent")
                decide_sent[slot_cur] = True
                decides[slot_cur].put_nowait((flag, hash_prev, Sigma, tx_batch))

        t = gevent.spawn(handle_vote)
        # print('3')
        if logger is not None:
            logger.info("Entering slot %d" % slot_cur)
        print(pid, "Entering slot", slot_cur)
        flag = -2
        s_times[slot_cur] = time.time()
        if slot_cur == 1:
            try:
                if k > 0:
                    digest1 = hash(str((k + 1, hash(ok_tx))))
                    my_sig_ok = ecdsa_sign(SK2, digest1)
                    send(leader, ('OK', k + 1, ok_tx, ok_sig, my_sig_ok))

                if k == 0 and pid == leader:
                    tx_batch = json.dumps([get_input()] * BATCH_SIZE)
                    digest_de = hash(str((slot_cur, hash(tx_batch))))
                    sig_decide = ecdsa_sign(SK2, digest_de)
                    # proposal(id, s, hash_p, TXs, VS_0=bot, sigma_s)
                    send(-2, ('DECIDE', slot_cur, hash_prev, tx_batch, tuple(), sig_decide))
                    print("leader send slot 1 decide")
                    decides[slot_cur].put_nowait((-1, hash_prev, tuple(), tx_batch))
            except AttributeError as e:
                if logger is not None:
                    logger.info(traceback.print_exc())
                print(traceback.print_exc())
        if slot_cur > 1:
            # hash_vote = hash(str((slot_cur, hash(batches))))
            try:
                sig_vote = ecdsa_sign(SK2, hash_prev)
                if pid != -1:
                    send(leader, ('VOTE', slot_cur-1, hash_prev, sig_vote))
            except AttributeError as e:
                if logger is not None:
                    logger.info(traceback.print_exc())
                # print("?")


        # sig_prev = ecdsa_sign(SK2, hash_prev)
        # send(leader, ('VOTE', slot_cur, hash_prev, sig_prev))

        # print('4')

        (flag_d, h_p, Sigma_p, batches) = decides[slot_cur].get()  # Block to wait for the voted block
        # print(pid, "get decide in slot ", slot_cur, flag_d)
        ########################
        # Enter critical block #
        ########################

        slot_noncritical_signal.clear()
        msg_noncritical_signal.wait()
        if slot_cur == 1:
            if len(Sigma_p) == 0 or len(Sigma_p) == 2*f+1:
                pending_block = (sid, slot_cur, h_p, Sigma_p, batches)
                pending_block_header = (slot_cur, hash(batches))
                hash_prev = hash(pending_block_header)
            if len(Sigma_p) == f + 1:
                splitstrs = sid.split('-')
                last_e = int(splitstrs[-1]) - 1
                splitstrs[2] = str(last_e)
                last_e_id = '-'.join(splitstrs)
                pending_block = (last_e_id, k+1, h_p, Sigma_p, batches)
                pending_block_header = (k+1, hash(batches))
                hash_prev = hash(pending_block_header)
                print("pending", slot_cur)

        if slot_cur > 1 and pending_block is not None:

            if notraized_block is not None:
                fixed_block = notraized_block
                if fixed_block[0] == sid:
                    assert fixed_block[1] + 2 == slot_cur
                e_times[fixed_block[1]] = time.time()
                delay[fixed_block[1]] = e_times[fixed_block[1]] - s_times[fixed_block[1]]
                txcnt[fixed_block[1]] = str(fixed_block).count("Dummy TX")
                weighted_delay = (epoch_txcnt * weighted_delay + txcnt[fixed_block[1]] * delay[fixed_block[1]]) / (
                        epoch_txcnt + txcnt[fixed_block[1]])
                epoch_txcnt += txcnt[fixed_block[1]]
                if logger is not None:
                    logger.info('Fast block at Node %d for Epoch %s and Slot %d has delay and TXs: %s, %d' % (
                        pid, sid, fixed_block[1], str(delay[fixed_block[1]]), txcnt[fixed_block[1]]))
                print('Fast block at Node %d for Epoch %s and Slot %d has delay and TXs: %s, %d' % (
                    pid, sid, fixed_block[1], str(delay[fixed_block[1]]), txcnt[fixed_block[1]]))
                print("epoch_txcnt:", epoch_txcnt, "weighted_delay:", weighted_delay)
                fixed_block = None

            notraized_block = (pending_block[0], pending_block[1], pending_block[2], pending_block[4])
            if pending_block[0] == sid:
                assert notraized_block[1] + 1 == slot_cur

            if output_notraized_block is not None:
                output_notraized_block((notraized_block, (h_p, Sigma_p, (epoch_txcnt, weighted_delay))))

            if flag_d == 1 and notraized_block is not None:

                fixed_block = notraized_block


                if fixed_block is not None:
                    e_times[fixed_block[1]] = time.time()
                    delay[fixed_block[1]] = e_times[fixed_block[1]] - s_times[fixed_block[1]]
                    txcnt[fixed_block[1]] = str(fixed_block).count("Dummy TX")
                    weighted_delay = (epoch_txcnt * weighted_delay + txcnt[fixed_block[1]] * delay[fixed_block[1]]) / (
                            epoch_txcnt + txcnt[fixed_block[1]])
                    epoch_txcnt += txcnt[fixed_block[1]]
                    if logger is not None:
                        logger.info('Fast block at Node %d for Epoch %s and Slot %d has delay and TXs: %s, %d' % (
                            pid, sid, fixed_block[1], str(delay[fixed_block[1]]), txcnt[fixed_block[1]]))
                    print('Fast block2 at Node %d for Epoch %s and Slot %d has delay and TXs: %s, %d' % (
                            pid, sid, fixed_block[1], str(delay[fixed_block[1]]), txcnt[fixed_block[1]]))
                    print("epoch_txcnt:", epoch_txcnt, "weighted_delay:", weighted_delay)
                if output_notraized_block is not None:
                    output_notraized_block((notraized_block, (h_p, Sigma_p, (epoch_txcnt, weighted_delay))))

                notraized_block = None

            pending_block = (sid, slot_cur, h_p, Sigma_p, batches)
            print("pending", slot_cur)
            pending_block_header = (slot_cur, hash(batches))
            hash_prev = hash(pending_block_header)

        if logger is not None:
            logger.info("Leaving slot %d" % slot_cur)
        t.kill()
        slot_cur = slot_cur + 1
        slot_noncritical_signal.set()

        ########################
        # Leave critical block #
        ########################

    """
    Execute the slots
    """

    recv_thread = gevent.spawn(handle_messages)
    # gevent.sleep(0)

    ########################
    # Initial phase #
    ########################

    while slot_cur <= SLOTS_NUM + 2:

        # if logger is not None:
        #    logger.info("Enter fastpath's slot %d out of all %d slots" % (slot_cur, SLOTS_NUM))

        # print('0')

        # if logger is not None:
        #    logger.info("entering fastpath slot %d ..." % slot_cur)

        # print('1')

        msg_noncritical_signal.wait()
        slot_noncritical_signal.wait()

        # print('2')

        # timeout = Timeout(TIMEOUT, False)
        # timeout.start()

        timeout = Timeout(TIMEOUT2)
        # print(TIMEOUT)
        timeout.start()
        try:
            with gevent.Timeout(TIMEOUT2, False):
                # with Timeout(TIMEOUT):
                # gevent.spawn(one_slot).join(timeout=Timeout)
                # if omitfast is False:
                one_slot()
                # else:
                #    while True:
                #        gevent.sleep(0.01)
        except Timeout as e:
            msg_noncritical_signal.wait()
            slot_noncritical_signal.wait()
            gevent.killall([recv_thread])
            print("node " + str(pid) + " error: " + str(e))
            if logger is not None:
                logger.info("Fastpath Timeout!")
            break
        timeout.cancel()
        timeout.close()

    if logger is not None:
        logger.info("Leaves fastpath at %d slot" % (slot_cur))
    if pending_block[1] == slot_cur or pending_block[1] == SLOTS_NUM+2:
        return pending_block[2], pending_block[3], (epoch_txcnt, weighted_delay)  # represents fast_path successes

    else:
        return (0, 0, 0)
