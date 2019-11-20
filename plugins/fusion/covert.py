"""
Covert submission mechanism

- Open numerous connections at random times.
- Send data (component) at random times on random connections.
- Send more data (signature) at a later random time, but on the same connection.
- Close the connections at random times.
- Keep some spare connections in case of problems.

This is accomplished using a Scheduler with a thread pool.
"""

import socket, socks

from .scheduler import Scheduler
from .comms import open_connection, send_pb, recv_pb, pb

import time
import threading, sys
import math, random, secrets
from functools import partial
from collections import deque

from electroncash.util import PrintError

TOR_COOLDOWN_TIME = 660 #seconds

def is_tor_port(host, port):
    if not 0 <= port < 65536:
        return False
    try:
        socketclass = socket.socket
        try:
            # socket.socket could be monkeypatched (see lib/network.py),
            # in which case we need to get the real one.
            socketclass = socket._socketobject
        except AttributeError:
            pass
        s = socketclass(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect((host, port))
        # Tor responds uniquely to HTTP-like requests
        s.send(b"GET\n")
        if b"Tor is not an HTTP Proxy" in s.recv(1024):
            return True
    except socket.error:
        pass
    return False

class TorLimiter:
    # Holds a log of the times of connections during the last `lifetime`
    # seconds. At any time you can query `.count` to see how many.
    def __init__(self, lifetime):
        self.deque = deque()
        self.lifetime = lifetime
        self.lock = threading.Lock()
        self._count = 0

    def cleanup(self,):
        with self.lock:
            tnow = time.monotonic()
            while True:
                try:
                    item = self.deque[0]
                except IndexError:
                    return
                if item > tnow:
                    return
                self.deque.popleft()
                self._count -= 1

    @property
    def count(self,):
        self.cleanup()
        return self._count

    def bump(self,):
        t = time.monotonic() + self.lifetime
        with self.lock:
            self.deque.append(t)
            self._count += 1

limiter = TorLimiter(TOR_COOLDOWN_TIME)

class CovertSubmitter(PrintError):
    stopping = False

    def __init__(self, dest_addr, dest_port, ssl, tor_host, tor_port, scheduler, num_slots, num_spares, connect_timeout, submit_timeout):
        self.dest_addr = dest_addr
        self.dest_port = dest_port
        self.ssl = ssl

        if tor_host is None or tor_port is None:
            self.proxy_opts = None
        else:
            self.proxy_opts = dict(proxy_type = socks.SOCKS5, proxy_addr=tor_host, proxy_port = tor_port, proxy_rdns = True)

        self.scheduler = scheduler

        self.connect_timeout = connect_timeout
        self.submit_timeout = submit_timeout

        # If .stop() is called, it will use these times (settable with .set_stop_time)
        # to randomize the disconnection times. Note that .stop() may be called at any time
        # in case of a failure where there are no more spare connections left.
        self.stop_tstart = self.stop_tstop = scheduler.clock()

        self.lock = threading.Lock()

        # Our internal logic is as follows:
        #  - Sending of data happens on a "slot". That way, related data (with same slot number) gets sent on the same connection.
        #  - Each slot owns a particular connection, though it may yet be pending.
        #  - Once a connection is established and work exists for the slot, the work should be done ASAP.
        #    - Once work is happening, the slot's connection ownership is temporarily set to None to prevent more than one thread working at a time.
        #  - If a connection attempt or data submission fails, then the slot is immediately redirected to an unused spare connection, which may be pending or complete.
        #  - If a failure can find no spare connection, the entire process is stopped (using .stop).

        self.slot_connections = list(range(num_slots)) # which connection indices are owned by slots
        self.slot_work = [[] for _ in range(num_slots)] # jobs to be done on the slot immediately, once connection available.

        # Connections start out as None and then become a Connection object once they are established.
        self.connections = [None]*(num_slots + num_spares)
        self.unused_connections = list(range(num_slots, num_slots + num_spares))

        self.locks = [threading.Lock() for _ in range(num_slots)]

        # If too many failures occur, this will be set to the first exception.
        self.failure_exception = None

        self.randtag = secrets.token_urlsafe(12) # for proxy login
        self.rng = random.Random(secrets.token_bytes(32)) # for timings

    def randtime(self, tstart, tend):
        """ Random number between 0 and 1 according to raised cosine
        distribution. We use a raised cosine due to its highly smooth edges,
        which do not give away our exact start/end times.
        """
        x = math.acos(1 - 2 * self.rng.random()) / math.pi
        return tstart + (tend - tstart) * x

    def set_stop_times(self, tstart, tend):
        with self.lock:
            self.stop_tstart = tstart
            self.stop_tstop = tend

    def stop(self, _exception=None):
        """ Schedule any established connections to close at random times, and
        stop any pending connections and pending work.

        If some submissions are active when the connection actually closes, slightly
        weird things might happen. """
        with self.lock:
            if self.stopping:
                # already requested!
                return
            self.failure_exception = _exception
            self.stopping = True
            self.unused_connections = []

            for connection in self.connections:
                self._schedule_stop_connection(connection)

    def _schedule_stop_connection(self, connection):
        if connection is None:
            return
        t = self.randtime(self.stop_tstart, self.stop_tstop)
        self.scheduler.schedule_job(t, lambda jn, lag, c=connection: c.close())

    def schedule_connections(self, tstart, tend):
        for cnum in range(len(self.connections)):
            t = self.randtime(tstart, tend)
            self.scheduler.schedule_job(t, partial(self.run_connect, cnum))

    def schedule_submit(self, slot_num, tstart, tend, submsg, close_after = False):
        t = self.randtime(tstart, tend)
        self.scheduler.schedule_job(t, partial(self.run_submit, slot_num, submsg, close_after))

    def _reallocate_slot(self, slot_num, exception):
        try:
            self.slot_connections[slot_num] = self.unused_connections.pop()
        except IndexError:
            self.slot_connections[slot_num] = 'failed'
            self.stop(_exception = exception)

    # Run in worker threads
    def run_connect(self, connection_num, job_num, lag):
        if self.stopping:
            return
        tbegin = self.scheduler.clock()
        limiter.bump()
        try:
            if self.proxy_opts is None:
                proxy_opts = None
            else:
                unique = f'{self.randtag}_{connection_num}'
                proxy_opts = dict(proxy_username = unique, proxy_password = unique)
                proxy_opts.update(self.proxy_opts)
            connection = open_connection(self.dest_addr, self.dest_port, conn_timeout=self.connect_timeout, ssl=self.ssl, socks_opts = proxy_opts)
            tend = self.scheduler.clock()
            self.print_error(f"connection established. conn time: {lag:.3f}s+{(tend-tbegin):.3f}s")
        except Exception as e:
            exception = e
            connection = None
            tend = self.scheduler.clock()
            self.print_error(f"covert connection failed (after {lag:.3f}s+{(tend-tbegin):.3f}s): {e}")

        with self.lock:
            if self.stopping and connection is not None:
                # Oh, stop was signalled while we were connecting ...
                self._schedule_stop_connection(connection)
                return

            assert self.connections[connection_num] is None
            self.connections[connection_num] = connection

            # Find out if a slot owns us... if so, we should deal with that.
            try:
                slot_num = self.slot_connections.index(connection_num)
            except ValueError:
                return

        if connection is None:
            # A slot was waiting for us to connect, but we failed. Try another connection.
            self._reallocate_slot(slot_num, exception)

        self.try_work_on_slot(slot_num)

    def run_submit(self, slot_num, submsg, close_after, job_num, lag):
        def work(connection):
            send_pb(connection, pb.CovertMessage, submsg, timeout=self.submit_timeout)
            resmsg, mtype = recv_pb(connection, pb.CovertResponse, 'ok', 'error', timeout=self.submit_timeout)
            if mtype == 'error':
                self.stop(_exception = FusionError('error from server: ' + repr(resmsg.message)))
            if close_after:
                connection.close()
            self.print_error(f"covert work successful (lag={lag:.3f})")

        self.slot_work[slot_num].append(work)

        self.try_work_on_slot(slot_num)

    def try_work_on_slot(self, slot_num):
        while True:
            with self.lock:
                connection_num = self.slot_connections[slot_num]
                if not isinstance(connection_num, int):
                    # Slot is not available.
                    return

                connection = self.connections[connection_num]
                if connection is None:
                    # Connection not yet established.
                    return

                try:
                    work = self.slot_work[slot_num][0]
                except IndexError:
                    return

                # We now have an active connection and work to do.
                # Reserve this slot before we unlock.
                self.slot_connections[slot_num] = None

            # do the work
            try:
                if not self.stopping:
                    work(connection)
            except Exception as exception:
                self.print_error("covert work failed")
                # didn't succeed!
                # make sure connection is fully closed then try to get a new connection.
                connection.close()
                self._reallocate_slot(slot_num, exception)
                # import traceback ; traceback.print_exc(file=sys.stderr) # DEBUG
                continue
            # success - remove the work from queue and unreserve slot
            self.slot_work[slot_num].pop(0)
            self.slot_connections[slot_num] = connection_num
