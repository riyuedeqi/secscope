#ifndef SECSCOPE_WORKER_POOL_HPP
#define SECSCOPE_WORKER_POOL_HPP

#include "types.hpp"
#include <functional>
#include <vector>

namespace secscope {
bool run_bounded_workers(std::size_t task_count, const ResourceBudget& budget,
                         const std::function<void(std::size_t)>& task, Counters* counters);
}
#endif
