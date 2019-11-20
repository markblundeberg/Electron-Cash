import threading
from heapq import heappush, heappop, heappushpop

class Scheduler:
    """A pool of threads to work on jobs at specified times. Once a job is
    to be run, a thread will pick it up as soon as possible. In case of
    congestion where all threads are busy, the jobs will be run as soon
    as possible, prioritizing the oldest jobs.

    - Use .schedule_job() to add a job.
    - Make sure to call either .stop() or .no_more_jobs(), as the threads
      will not clean themselves up.
    """

    _stopping = False
    _exit_when_done = False

    def __init__(self, clock, name=None, num_threads=4, stopfunc=None, inactive_timeout=1000):
        """
        `clock` should be a well-behaved clock, like time.monotonic
        `name` will be used for thread naming
        `num_threads` should be high enough that jobs won't get behind schedule
        `stopfunc` will be called at the end of threads
        `inactive_timeout` is for a backup sanity check: if a thread is inactive for this long, raise an exception.
        """

        self.clock = clock
        self.stopfunc = stopfunc
        self.inactive_timeout = inactive_timeout

        self.job_heap = []
        self.next_job_num = 0
        self.condition = threading.Condition()

        self.threadpool = []
        for i in range(num_threads):
            thread = threading.Thread(target=self.thread_mainloop, name=name and f'{name}-{i}')
            self.threadpool.append(thread)
            thread.daemon = True
            thread.start()

    def stop(self):
        """Initiate soft stopping: cancel all remaining jobs and make threads
        end. Returns immediately."""
        with self.condition:
            self._stopping = True
            self.job_heap = []
            self.condition.notify_all()

    def schedule_job(self, time, func):
        """Schedule `func(job_num, lag)` to be run at `time`.

        `job_num` will be the job's unique number (counted starting from 0) and
        `lag` is 0.0 for jobs that start on time, otherwise it is the delay in
        seconds.
        """
        with self.condition:
            job = (time, self.next_job_num, func)
            self.next_job_num += 1

            if not self.job_heap or job < self.job_heap[0]:
                # the new job is sooner than best job, so notify a thread
                # to possibly grab it. (maybe nothing happens, if that thread
                # has already popped a sooner job)
                self.condition.notify()
            heappush(self.job_heap, job)

    def no_more_jobs(self):
        """Tell the threads to exit once no more jobs are left."""
        with self.condition:
            self._exit_when_done = True
            self.condition.notify_all()

    def thread_mainloop(self,):
        myjob = None
        while True:
            with self.condition:
                if self._stopping:
                    break
                if myjob:
                    # Make sure we grab the soonest job.
                    myjob = heappushpop(self.job_heap, myjob)
                else:
                    # Don't have a job yet, so grab one.
                    try:
                        myjob = heappop(self.job_heap)
                    except IndexError:
                        if self._exit_when_done:
                            break
                        # No jobs yet. Wait for one to appear.
                        if not self.condition.wait(timeout = self.inactive_timeout):
                            raise RuntimeError("Scheduler was not stopped!") from None
                        continue
                jtime, jnum, jfunc = myjob
                delay = jtime - self.clock()
                if delay > 0 and self.condition.wait(timeout = delay):
                    # before we would start the job, we got notified.
                    continue

                # Time to run the job.
                # Before that, ping another thread to make sure that someone is
                # waiting for the next-best job.
                self.condition.notify()

            # Job runs outside condition lock
            jfunc(jnum, max(0., -delay))
            myjob = None

        if self.stopfunc:
            self.stopfunc()
