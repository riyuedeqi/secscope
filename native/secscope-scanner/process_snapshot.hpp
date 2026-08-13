#ifndef SECSCOPE_PROCESS_SNAPSHOT_HPP
#define SECSCOPE_PROCESS_SNAPSHOT_HPP

#include "types.hpp"

namespace secscope {
bool collect_process_snapshot(std::vector<ProcessRecord>* records, Counters* counters,
                              std::size_t max_processes = 32768);
bool write_process_snapshot(const std::string& path, const std::vector<ProcessRecord>& records);
}

#endif
