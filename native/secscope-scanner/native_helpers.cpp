#include "native_helpers.hpp"

#include "candidate_discovery.hpp"
#include "hashing.hpp"
#include "native_io.hpp"
#include "web_access_parser.hpp"
#include "binary_analyzer.hpp"
#include "static_analyzer.hpp"
#include "runtime_snapshot.hpp"
#include "file_monitor.hpp"
#include "filesystem_facts.hpp"
#include "events_parser.hpp"
#include "process_control.hpp"

#include <chrono>
#include <cerrno>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <vector>
#include <cctype>

namespace {

struct BaselineEntry {
    std::string dev;
    std::string inode;
    std::string size;
    std::string mtime;
    std::string ctime;
    std::string md5;
    std::string sha256;
};

std::vector<std::string> split_tsv(const std::string& line) {
    std::vector<std::string> fields;
    std::size_t start = 0;
    while (true) {
        const auto tab = line.find('\t', start);
        fields.push_back(line.substr(start, tab == std::string::npos ? tab : tab - start));
        if (tab == std::string::npos) break;
        start = tab + 1;
    }
    return fields;
}

bool valid_digest(const std::string& value, std::size_t length) {
    if (value.size() != length) return false;
    for (const unsigned char item : value) {
        if (!std::isxdigit(item)) return false;
    }
    return true;
}

bool load_baseline(const std::string& path, const std::string& expected_cache_key,
                   const std::string& expected_analyzer, const std::string& expected_profile,
                   const std::string& expected_max_bytes, const std::string& expected_rules,
                   std::map<std::string, BaselineEntry>* entries) {
    if (path.empty()) return true;
    std::ifstream input(path);
    if (!input) return false;
    std::string line;
    bool first_line = true;
    bool compatible = expected_cache_key.empty();
    while (std::getline(input, line)) {
        if (first_line) {
            first_line = false;
            if (line.rfind("#secscope-file-inventory-v3\t", 0) == 0) {
                const auto header = split_tsv(line);
                compatible = expected_cache_key.empty() ||
                             (header.size() >= 8 && header[3] == expected_analyzer &&
                              header[4] == expected_profile && header[5] == expected_max_bytes &&
                              header[6] == expected_rules && header[7] == expected_cache_key);
                continue;
            }
            if (!expected_cache_key.empty()) compatible = false;
        }
        if (!compatible || line.empty() || line[0] == '#') continue;
        const auto fields = split_tsv(line);
        if (fields.size() < 8 || fields[0].empty() || !valid_digest(fields[5], 32) || !valid_digest(fields[6], 64)) continue;
        (*entries)[fields[0]] = BaselineEntry{fields[1], fields[2], fields[3], fields[4], fields[7], fields[5], fields[6]};
    }
    return true;
}

bool same_baseline(const BaselineEntry& baseline, const struct stat& status) {
    return baseline.dev == std::to_string(static_cast<std::uint64_t>(status.st_dev)) &&
           baseline.inode == std::to_string(static_cast<std::uint64_t>(status.st_ino)) &&
           baseline.size == std::to_string(static_cast<std::uint64_t>(status.st_size)) &&
           baseline.mtime == std::to_string(static_cast<std::int64_t>(status.st_mtime)) &&
           baseline.ctime == std::to_string(static_cast<std::int64_t>(status.st_ctime)) &&
           valid_digest(baseline.md5, 32) && valid_digest(baseline.sha256, 64);
}

int run_hash_files(const secscope::Arguments& args) {
    std::string error;
    if (!secscope::required_arguments(args, {"--input-list", "--output"}, &error)) {
        std::cerr << error << '\n';
        return 2;
    }
    std::ifstream input(secscope::argument(args, "--input-list"));
    secscope::AtomicOutput output(secscope::argument(args, "--output"));
    if (!input || !output.good()) {
        std::cerr << "cannot open hash-files input/output\n";
        return 2;
    }
    std::map<std::string, BaselineEntry> baseline;
    if (!load_baseline(secscope::argument(args, "--baseline"), secscope::argument(args, "--cache-key"),
                       secscope::argument(args, "--cache-analyzer-version"), secscope::argument(args, "--cache-profile"),
                       secscope::argument(args, "--cache-max-bytes"), secscope::argument(args, "--cache-rules"), &baseline)) {
        std::cerr << "cannot open hash-files baseline\n";
        return 2;
    }
    const std::uint64_t max_bytes = secscope::uint_argument(args, "--max-bytes", 100ULL * 1024ULL * 1024ULL,
                                                              1, 2ULL * 1024ULL * 1024ULL * 1024ULL);
    const std::size_t max_files = static_cast<std::size_t>(secscope::uint_argument(args, "--max-files", 50000, 1, 1000000));
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(secscope::uint_argument(args, "--timeout-seconds", 120, 1, 86400));
    output.stream() << "priority_score\tpriority_mtime\tpriority_size\tpath\tpriority_reasons"
                       "\tdev\tinode\tsize\tmtime\tctime\tstatus\tmd5\tsha256\terror\n";

    std::size_t scanned = 0;
    std::size_t cache_hits = 0;
    bool timed_out = false;
    bool max_files_reached = false;
    secscope::Counters counters;
    std::string line;
    while (std::getline(input, line)) {
        if (scanned >= max_files) {
            max_files_reached = true;
            break;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            timed_out = true;
            break;
        }
        if (line.empty()) continue;
        const auto fields = split_tsv(line);
        if (fields.size() < 4 || fields[3].empty() || fields[3].find('\r') != std::string::npos) continue;
        const std::string& path = fields[3];
        secscope::InventoryRecord record;
        record.path = path;
        struct stat status{};
        bool have_status = ::lstat(path.c_str(), &status) == 0;
        if (have_status) {
            record.dev = static_cast<std::uint64_t>(status.st_dev);
            record.inode = static_cast<std::uint64_t>(status.st_ino);
            record.size = status.st_size < 0 ? 0 : static_cast<std::uint64_t>(status.st_size);
            record.mtime = static_cast<std::int64_t>(status.st_mtime);
            record.ctime = static_cast<std::int64_t>(status.st_ctime);
        } else {
            record.status = errno == ENOENT ? "DELETED" : "UNREADABLE";
            record.error = errno == EACCES ? "permission_denied" : "lstat_failed";
        }
        const auto found = baseline.find(path);
        if (have_status && S_ISREG(status.st_mode) && found != baseline.end() && same_baseline(found->second, status)) {
            record.status = "REUSED";
            record.md5 = found->second.md5;
            record.sha256 = found->second.sha256;
            ++cache_hits;
            ++counters.cache_hits;
        } else if (have_status && S_ISREG(status.st_mode) && !S_ISLNK(status.st_mode)) {
            secscope::hash_file(path, max_bytes, &record, &counters);
        } else if (have_status) {
            record.status = S_ISLNK(status.st_mode) ? "SYMLINK_SKIPPED" : "SPECIAL_FILE_SKIPPED";
            record.error = S_ISLNK(status.st_mode) ? "symbolic_link" : "not_regular_file";
            ++counters.skipped;
        } else {
            ++counters.hash_failed;
        }
        const std::string dev = std::to_string(record.dev);
        const std::string inode = std::to_string(record.inode);
        const std::string size = std::to_string(record.size);
        const std::string mtime = std::to_string(record.mtime);
        const std::string ctime = std::to_string(record.ctime);
        output.stream() << secscope::clean_cell(fields[0]) << '\t'
                        << secscope::clean_cell(fields.size() > 1 ? fields[1] : "") << '\t'
                        << secscope::clean_cell(fields.size() > 2 ? fields[2] : "") << '\t'
                        << secscope::clean_cell(path) << '\t'
                        << secscope::clean_cell(fields.size() > 4 ? fields[4] : "DEFAULT") << '\t'
                        << dev << '\t' << inode << '\t' << size << '\t' << mtime << '\t' << ctime << '\t'
                        << secscope::clean_cell(record.status) << '\t' << secscope::clean_cell(record.md5) << '\t'
                        << secscope::clean_cell(record.sha256) << '\t' << secscope::clean_cell(record.error) << '\n';
        ++scanned;
    }
    if (input.bad()) return 2;
    if (std::chrono::steady_clock::now() >= deadline) timed_out = true;
    const bool partial = timed_out || max_files_reached;
    output.stream().flush();
    std::cout << "{\"status\":\"" << (partial ? "PARTIAL" : "SUCCESS") << "\",\"scanned\":" << scanned
              << ",\"cache_hits\":" << cache_hits << ",\"hash_computed\":" << counters.hash_computed
              << ",\"hash_failed\":" << counters.hash_failed << ",\"skipped\":" << counters.skipped
              << ",\"cache_key_checked\":" << (!secscope::argument(args, "--cache-key").empty() ? "true" : "false")
              << ",\"timed_out\":" << (timed_out ? "true" : "false")
              << ",\"max_files_reached\":" << (max_files_reached ? "true" : "false") << "}\n";
    return output.commit() ? 0 : 2;
}

}

namespace secscope {

bool is_native_helper_command(const std::string& command) {
    // Keep process control as an explicit helper command; scan/resume never
    // dispatches into this action path.
    static const std::set<std::string> commands{"discover-candidates", "parse-web-access", "analyze-binary", "analyze-static", "hash-files", "runtime-snapshot", "file-monitor", "filesystem-facts", "parse-events", "process-control"};
    return commands.count(command) != 0;
}

int run_native_helper(const std::string& command, int argc, char** argv) {
    const Arguments args = parse_arguments(argc, argv);
    if (command == "discover-candidates") return run_candidate_discovery(args);
    if (command == "parse-web-access") return run_web_access_parser(args);
    if (command == "analyze-binary") return run_binary_analyzer(args);
    if (command == "analyze-static") return run_static_analyzer(args);
    if (command == "hash-files") return run_hash_files(args);
    if (command == "runtime-snapshot") return run_runtime_snapshot(args);
    if (command == "file-monitor") return run_file_monitor(args);
    if (command == "filesystem-facts") return run_filesystem_facts(args);
    if (command == "parse-events") return run_events_parser(args);
    if (command == "process-control") return run_process_control(args);
    return 2;
}

}
