#ifndef SECSCOPE_FILE_INVENTORY_HPP
#define SECSCOPE_FILE_INVENTORY_HPP

#include "types.hpp"

namespace secscope {
bool collect_inventory(const ScannerConfig& config, std::vector<InventoryRecord>* records, Counters* counters);
bool write_inventory(const std::string& path, const std::vector<InventoryRecord>& records, const Counters& counters);
}
#endif
