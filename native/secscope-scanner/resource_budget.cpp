#include "resource_budget.hpp"

#include <algorithm>
#include <cmath>
#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <string>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#ifdef __linux__
#include <sys/sysinfo.h>
#endif
#include <unistd.h>

namespace secscope {
namespace {
unsigned env_uint(const char* name, unsigned fallback) {
    const char* value = std::getenv(name);
    if (!value || !*value) return fallback;
    char* end = nullptr;
    unsigned long parsed = std::strtoul(value, &end, 10);
    return end && *end == '\0' && parsed > 0 && parsed <= 1000000UL ? static_cast<unsigned>(parsed) : fallback;
}
double env_double(const char* name, double fallback) {
    const char* value = std::getenv(name);
    if (!value || !*value) return fallback;
    char* end = nullptr;
    double parsed = std::strtod(value, &end);
    return end && *end == '\0' && parsed > 0.0 && parsed <= 1000.0 ? parsed : fallback;
}
std::uint64_t available_memory_mb() {
    std::ifstream input("/proc/meminfo");
    std::string key;
    std::uint64_t value = 0;
    std::string unit;
    while (input >> key >> value >> unit) {
        if (key == "MemAvailable:") return value / 1024;
    }
#ifdef __linux__
    struct sysinfo info{};
    return sysinfo(&info) == 0 ? (static_cast<std::uint64_t>(info.freeram) * info.mem_unit) / (1024 * 1024) : 0;
#else
    return 0;
#endif
}

double load_average() {
    double load = 0.0;
    std::ifstream input("/proc/loadavg");
    if (input) input >> load;
    return std::isfinite(load) && load >= 0.0 ? load : 0.0;
}

double psi_avg10(const char* path) {
    if (!path) return 0.0;
    std::ifstream input(path);
    std::string line;
    while (std::getline(input, line)) {
        const auto marker = line.find("avg10=");
        if (marker == std::string::npos) continue;
        char* end = nullptr;
        const double value = std::strtod(line.c_str() + marker + 6, &end);
        if (end && end != line.c_str() + marker + 6 && std::isfinite(value) && value >= 0.0) return value;
    }
    return 0.0;
}

bool rotational_storage_for(const std::vector<std::string>& roots) {
    struct stat status{};
    std::string path = roots.empty() ? "/" : roots.front();
    if (::stat(path.c_str(), &status) != 0) return false;
    const std::string device = "/sys/dev/block/" + std::to_string(major(status.st_dev)) + ":" + std::to_string(minor(status.st_dev)) + "/queue/rotational";
    std::ifstream input(device);
    int rotational = 0;
    return static_cast<bool>(input >> rotational) && rotational != 0;
}
}

ResourceBudget resolve_budget(const ScannerConfig& config) {
    ResourceBudget budget;
    const long online_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    budget.vcpus = online_cpus > 0 ? static_cast<unsigned>(std::min<long>(online_cpus, 1000000L)) : 1u;
    unsigned profile_cap = config.profile == "full" ? std::min(budget.vcpus, 8u) : std::min(budget.vcpus, 4u);
    unsigned requested = env_uint("SECSCOPE_NATIVE_WORKERS", profile_cap);
    budget.workers = std::max(1u, std::min(requested, profile_cap));
    std::uint64_t available = available_memory_mb();
    std::uint64_t default_memory = std::min<std::uint64_t>(256, std::max<std::uint64_t>(64, available / 8));
    budget.max_memory_mb = env_uint("SECSCOPE_NATIVE_MAX_MEMORY_MB", static_cast<unsigned>(default_memory));
    budget.max_load_factor = env_double("SECSCOPE_NATIVE_MAX_LOAD_FACTOR", 1.5);
    budget.stage_timeout_seconds = env_uint("SECSCOPE_NATIVE_STAGE_TIMEOUT", config.timeout_seconds);
    budget.io_psi_avg10 = psi_avg10("/proc/pressure/io");
    budget.memory_psi_avg10 = psi_avg10("/proc/pressure/memory");
    budget.rotational_storage = rotational_storage_for(config.roots);
    // Busy hosts keep the same scan limits and lower only native worker
    // parallelism. A high load must not turn a complete inspection into a
    // skipped inspection.
    if (load_average() > static_cast<double>(budget.vcpus) * budget.max_load_factor) {
        budget.workers = 1;
        budget.constrained = true;
    }
    if (available > 0 && available < 512) budget.workers = 1;
    else if (available > 0 && available < 1024) budget.workers = std::min(budget.workers, 2u);
    if (budget.io_psi_avg10 >= 10.0 || budget.memory_psi_avg10 >= 5.0) budget.workers = std::min(budget.workers, 2u);
    if (budget.rotational_storage && budget.workers > 2) budget.workers = 2;
    if (budget.workers > 1 && budget.max_memory_mb / budget.workers < 16) budget.workers = 1;
    budget.constrained = budget.workers < profile_cap || (available > 0 && available < 1024);
    return budget;
}

bool budget_available(const ResourceBudget& budget, std::string* reason) {
    // Load is handled by resolve_budget() through worker reduction. Do not
    // reject the scan: traversal depth, file count and timeout are detection
    // limits and must remain unchanged by host contention.
    (void)budget;
    (void)reason;
    return true;
}
}
