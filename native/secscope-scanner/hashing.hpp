#ifndef SECSCOPE_HASHING_HPP
#define SECSCOPE_HASHING_HPP

#include "types.hpp"

namespace secscope {
bool hash_file(const std::string& path, std::uint64_t max_bytes, InventoryRecord* record, Counters* counters);
}
#endif
