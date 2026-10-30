"""Small bounded thread pool. Mirror of worker_pool.cpp."""
import threading


def run_bounded_workers(task_count, budget, task, counters):
    """Run task(index) for 0..task_count-1 on budget.workers threads.

    hashlib releases the GIL for large updates, so hashing still gets real
    parallelism, matching the C++ worker pool behaviour.
    """
    if task_count == 0:
        return True
    lock = threading.Lock()
    stop = [False]
    next_index = [0]

    def worker():
        while not stop[0]:
            with lock:
                if next_index[0] >= task_count:
                    return
                index = next_index[0]
                next_index[0] += 1
            try:
                task(index)
            except Exception:
                stop[0] = True
                with lock:
                    if counters is not None:
                        counters.partial = True
                        if not counters.partial_reason:
                            counters.partial_reason = "worker_exception"

    workers = budget.workers if budget.workers > 0 else 1
    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return not stop[0]
