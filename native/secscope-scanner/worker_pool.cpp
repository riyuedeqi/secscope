#include "worker_pool.hpp"

#include <atomic>
#include <mutex>
#include <thread>

namespace secscope {
bool run_bounded_workers(std::size_t task_count, const ResourceBudget& budget,
                         const std::function<void(std::size_t)>& task, Counters* counters) {
    if (task_count == 0) return true;
    std::mutex mutex;
    std::atomic<bool> stop{false};
    std::size_t next = 0;
    auto worker = [&]() {
        while (!stop.load()) {
            std::size_t index = 0;
            {
                std::lock_guard<std::mutex> lock(mutex);
                if (next >= task_count) return;
                index = next++;
            }
            try {
                task(index);
            } catch (...) {
                stop.store(true);
                if (counters) {
                    std::lock_guard<std::mutex> lock(mutex);
                    counters->partial = true;
                    if (counters->partial_reason.empty()) counters->partial_reason = "worker_exception";
                }
            }
        }
    };
    std::vector<std::thread> threads;
    threads.reserve(budget.workers);
    for (unsigned i = 0; i < budget.workers; ++i) threads.emplace_back(worker);
    for (auto& thread : threads) thread.join();
    return !stop.load();
}
}
