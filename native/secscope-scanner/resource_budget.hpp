#ifndef SECSCOPE_RESOURCE_BUDGET_HPP
#define SECSCOPE_RESOURCE_BUDGET_HPP

#include "types.hpp"

namespace secscope {
ResourceBudget resolve_budget(const ScannerConfig& config);
bool budget_available(const ResourceBudget& budget, std::string* reason = nullptr);
}
#endif
