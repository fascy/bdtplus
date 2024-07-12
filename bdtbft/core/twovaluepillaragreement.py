from gevent import monkey; monkey.patch_all(thread=False)
from datetime import datetime
import time
import gevent
from gevent.event import Event
from collections import defaultdict
import hashlib, pickle

def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()

def twovaluepillaragreement(sid, pid, N, f, coin, input, decide, receive, send, logger=None):
    """Binary consensus from [MMR14]. It takes an input ``vi`` and will
    finally write the decided value into ``decide`` channel.

    :param sid: session identifier
    :param pid: my id number
    :param N: the number of parties
    :param f: the number of byzantine parties
    :param coin: a ``common coin(r)`` is called to block until receiving a bit
    :param input: ``input()`` is called to receive an input
    :param decide: ``decide(0)`` or ``output(1)`` is eventually called
    :param send: send channel
    :param receive: receive channel
    :return: blocks until
    """
    # Messages received are routed to either a shared coin, the broadcast, or AUX
    est_values = defaultdict(lambda: defaultdict(lambda: set()))
    majs = defaultdict(lambda: defaultdict(lambda: set()))
    aux_values = defaultdict(lambda: defaultdict(lambda: set()))
    avals_values = defaultdict(lambda: defaultdict(lambda: set()))
    bval_sent = defaultdict(lambda: defaultdict(lambda: False))
    aux_sent = False
    delta = defaultdict(lambda: defaultdict(lambda: False))
    int_values = defaultdict(set)

    input_recived = False

    finish_sent = False
    finish_value = set()
    finish_cnt = 0

    # This event is triggered whenever int_values or aux_values changes
    bv_signal = Event()

    finish_signal = Event()

    def recv():

        nonlocal maj, finish_sent, est_values, bval_sent, int_values, aux_values, bv_signal, finish_value, finish_cnt

        while True:  # not finished[pid]:

            #gevent.sleep(0)

            (sender, msg) = receive()

            assert sender in range(N)

            if msg[0] == 'BVAL':
                # BV_Broadcast message
                _, r, (est, maj_r) = msg
                assert type(est) is int
                if sender in est_values[r][est]:
                    # FIXME: raise or continue? For now will raise just
                    # because it appeared first, but maybe the protocol simply
                    # needs to continue.
                    # print(f'Redundant EST received by {sender}', msg)

                    # raise RedundantMessageError(
                    #    'Redundant EST received {}'.format(msg))
                    continue

                est_values[r][est].add(sender)
                majs[r][maj_r].add(sender)
                # Relay after reaching first threshold
                if len(est_values[r][est]) >= f + 1 and not bval_sent[r][est]:
                    bval_sent[r][est] = True
                    est_values[r][est].add(sender)
                    majs[r][maj_r].add(sender)
                    send(-2, ('BVAL', r, (est, maj)))


                # Output after reaching second threshold
                if len(est_values[r][est]) == N - f:
                    int_values[r].add(est)
                    bv_signal.set()

            elif msg[0] == 'AUX':
                # Aux message
                _, r, (v, a) = msg
                assert type(v) is int
                if sender in aux_values[r][v]:
                    # FIXME: raise or continue? For now will raise just
                    # because it appeared first, but maybe the protocol simply
                    # needs to continue.
                    # print('Redundant AUX received', msg)
                    # raise RedundantMessageError(
                    #    'Redundant AUX received {}'.format(msg))
                    continue
                aux_values[r][v].add(sender)
                avals_values[r][a].add(sender)
                bv_signal.set()

            elif msg[0] == 'FINISH':
                _, _, v = msg
                assert type(v) == int
                finish_cnt = finish_cnt + 1
                finish_value.add(v)
                assert len(finish_value) == 1
                if finish_sent is False and finish_cnt >= f + 1:
                    decide(v)
                    send(-2, ('FINISH', '', list(finish_value)[0]))
                    finish_cnt = finish_cnt + 1
                    finish_sent = True
                if finish_cnt >= 2*f + 1:
                    finish_signal.set()

    # Translate mmr14 broadcast into coin.broadcast
    # _coin_broadcast = lambda (r, sig): broadcast(('COIN', r, sig))
    # _coin_recv = Queue()
    # coin = shared_coin(sid+'COIN', pid, N, f, _coin_broadcast, _coin_recv.get)

    finish_signal.clear()

    # Run the receive loop in the background
    _thread_recv = gevent.spawn(recv)

    # Block waiting for the input
    # print(pid, sid, 'PRE-ENTERING CRITICAL')

    vi = input()
    #if logger != None:
    #    logger.info("TCVBA %s gets input" % sid)

    # print(pid, sid, 'PRE-EXITING CRITICAL', vi)
    assert type(vi) is int

    cheap_coins = int.from_bytes(hash(sid), byteorder='big')
    r = 0
    maj = -1
    s_last = 0
    def main_loop():
        nonlocal r, maj, finish_sent, finish_cnt, s_last
        est = vi
        def V1(vals, b):
            if len(vals) == 1 and b in vals:
                return True
            return False
        def V2_ge(vals, b, t):
            if len(vals) == 1 and b in vals and len(vals[b]) >= t:
                return True
            elif len(vals) == 2 and b in vals and -1 in vals and len(vals[b]) >= t:
                return True
            return False
        def V2_l(vals, b, t):
            if len(vals) == 1 and b in vals and len(vals[b]) < t:
                return True
            elif len(vals) == 2 and b in vals and -1 in vals and len(vals[b]) < t:
                return True
            return False

        # if the two values are both in the vals
        def judge(vals):
            if len(vals) == 2 and -1 not in vals:
                return True
            elif len(vals) == 3:
                return True
            return False

        def majofmaj(vals):
            max = 0
            max_k = -1
            for k in vals.keys():
                if len(vals[k]) > max:
                    max = len(vals[k])
                    max_k = k
            return max_k

        while True:  # Unbounded number of rounds
            # print("debug", pid, sid, 'deciding', already_decided, "at epoch", r)

            #gevent.sleep(0)
            #if logger != None:
            #    logger.info("TCVBA %s enters round %d" % (sid, r))

            if not bval_sent[r][est]:
                bval_sent[r][est] = True
                send(-2, ('BVAL', r, (est, maj)))
                est_values[r][est].add(pid)
                majs[r][maj].add(pid)
            # print("debug", pid, sid, 'WAITS BIN VAL at epoch', r)

            while len(int_values[r]) == 0:
                # Block until a value is output
                #gevent.sleep(0)
                bv_signal.clear()
                bv_signal.wait()

            #if logger != None:
            #    logger.info("TCVBA %s gets BIN VAL at epoch %d" % (sid, r))
            # print("debug", pid, sid, 'GETS BIN VAL at epoch', r)

            b = next(iter(int_values[r]))  # take an element
            if r == 0:
                delta[r][b] = True
            elif b % 2 != s_last and V1(majs[r], b):
                delta[r][b] = True
            elif b % 2 == s_last and len(majs[r]) < 3 and (b in majs[r] or -1 in majs[r]):
                delta[r][b] = True
            if aux_sent == False:
                if delta[r][b] == True:
                    send(-2, ('AUX', r, (b, b)))
                    aux_values[r][b].add(pid)
                else:
                    send(-2, ('AUX', r, (-1, b)))
                    aux_values[r][-1].add(pid)
            avals_values[r][b].add(pid)
            bv_signal.set()

            while True:
                #gevent.sleep(0)
                len_int_values = len(int_values[r])
                assert len_int_values == 1 or len_int_values == 2
                if len_int_values == 1:
                    if len(aux_values[r][tuple(int_values[r])[0]]) >= N - f:
                        values = set(int_values[r])
                        break
                else:
                    if sum(len(aux_values[r][v]) for v in int_values[r]) >= N - f:
                        values = set(int_values[r])
                        break
                bv_signal.clear()
                bv_signal.wait()

            # Block until receiving the common coin value

            # print("debug", pid, sid, 'fetchs a coin at epoch', r)
            if r < 10:
                s = (cheap_coins >> r) & 1
            else:
                s = coin(r)
            # print("debug", pid, sid, 'gets a coin', s, 'at epoch', r)

            try:
                assert s in (0, 1)
            except AssertionError:
                s = s % 2

            # Set estimate
            if V2_ge(aux_values[r], b, 2 * f + 1):
                if b % 2 == s:
                    decide(b)
                    send(-2, ('FINISH', '', b))
                    finish_cnt = finish_cnt + 1
                    finish_sent = True
                    if finish_cnt >= 2 * f + 1:
                        finish_signal.set()
                est = b
                maj = b
            elif r > 0:
                if V1(aux_values[r], -1) or V2_l(aux_values[r], b, 2 * f + 1):
                    if V2_ge(avals_values[r], b, 2 * f + 1):
                        est = b
                        maj = b
                        if b % 2 == s and b % 2 == s_last:
                            decide(b)
                            send(-2, ('FINISH', '', b))
                            finish_cnt = finish_cnt + 1
                            finish_sent = True
                            if finish_cnt >= 2 * f + 1:
                                finish_signal.set()
                    elif judge(avals_values[r]) and b % 2 == s_last:
                        est = b
                        maj = b
            else:
                vals = tuple(values)
                assert len(values) == 2
                if vals[0] % 2 == s:
                    est = vals[0]
                else:
                    est = vals[1]
                maj = majofmaj(majs[r])

            if len(values) == 1:
                v = next(iter(values))
                assert type(v) is int
                if (v % 2) == s:
                    if finish_sent is False:
                        decide(v)
                        send(-2, ('FINISH', '', v))
                        finish_cnt = finish_cnt + 1
                        finish_sent = True
                        if finish_cnt >= 2 * f + 1:
                            finish_signal.set()
                est = v
            else:
                vals = tuple(values)
                assert len(values) == 2
                assert type(vals[0]) is int
                assert type(vals[1]) is int
                assert abs(vals[0] - vals[1]) == 1
                if vals[0] % 2 == s:
                    est = vals[0]
                else:
                    est = vals[1]
            # print('debug then decided:', already_decided, '%s' % sid)

            r += 1
            s_last = s
    _thread_main_loop = gevent.spawn(main_loop)

    finish_signal.wait()

    #if logger != None:
    #    logger.info("TCVBA %s completes at round %d" % (sid, r))

    _thread_recv.kill()
    _thread_main_loop.kill()
