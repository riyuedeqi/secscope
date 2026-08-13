#ifndef SECSCOPE_SCANNER_TYPES_HPP
#define SECSCOPE_SCANNER_TYPES_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace secscope {

struct ResourceBudget {
    unsigned workers = 1;
    unsigned vcpus = 1;
    std::uint64_t max_memory_mb = 64;
    double max_load_factor = 1.5;
    unsigned stage_timeout_seconds = 120;
    bool constrained = false;
    double io_psi_avg10 = 0.0;
    double memory_psi_avg10 = 0.0;
    bool rotational_storage = false;
};

struct ScannerConfig {
    std::vector<std::string> roots;
    std::vector<std::string> exclude_names;
    std::vector<std::string> extensions;
    std::string output_dir;
    std::string profile = "daily-hunt";
    std::uint64_t max_files = 3000;
    unsigned max_depth = 5;
    std::uint64_t max_hash_bytes = 100ULL * 1024ULL * 1024ULL;
    unsigned timeout_seconds = 120;
    bool xdev = true;
    bool hash = true;
};

struct InventoryRecord {
    std::string path;
    std::uint64_t dev = 0;
    std::uint64_t inode = 0;
    std::uint64_t size = 0;
    std::int64_t mtime = 0;
    std::int64_t ctime = 0;
    std::int64_t priority_score = 0;
    std::string priority_reasons = "DEFAULT";
    std::string status = "CANDIDATE";
    std::string md5;
    std::string sha256;
    std::string error;
};

struct ProcessRecord {
    std::int64_t pid = 0;
    std::int64_t ppid = 0;
    std::uint64_t start_ticks = 0;
    std::string comm;
    std::string exe;
    std::string cmdline_hash;
    std::string state;
    std::vector<std::string> executable_maps;
};

struct SocketRecord {
    std::string protocol;
    std::string local_address;
    std::string remote_address;
    std::string state;
    std::uint64_t inode = 0;
    std::int64_t pid = 0;
};

struct Counters {
    std::uint64_t files_traversed = 0;
    std::uint64_t stat_calls = 0;
    std::uint64_t hash_computed = 0;
    std::uint64_t hash_failed = 0;
    std::uint64_t skipped = 0;
    std::uint64_t permission_denied = 0;
    std::uint64_t disappeared = 0;
    std::uint64_t symlink_skipped = 0;
    std::uint64_t unrepresentable = 0;
    std::uint64_t proc_pid_visits = 0;
    std::uint64_t proc_maps_visits = 0;
    std::uint64_t socket_snapshots = 0;
    std::uint64_t cache_hits = 0;
    std::uint64_t fallback_count = 0;
    bool partial = false;
    std::string partial_reason;
};

}
#endif
