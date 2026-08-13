#include "checkpoint.hpp"
#include "file_inventory.hpp"
#include "hashing.hpp"
#include "process_snapshot.hpp"
#include "resource_budget.hpp"
#include "socket_snapshot.hpp"
#include "worker_pool.hpp"
#include "native_helpers.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <mutex>
#include <nlohmann/json.hpp>
#include <sstream>
#include <filesystem>
#include <vector>
#include <sys/stat.h>
#include <utility>
#include <unistd.h>

namespace {
constexpr std::size_t MAX_REQUEST_BYTES = 1024 * 1024;
constexpr std::size_t MAX_ARRAY_ITEMS = 1024;
constexpr std::size_t MAX_STRING_BYTES = 4096;
std::atomic<bool> cancelled{false};
void signal_handler(int) { cancelled.store(true); }
std::string read_all(const std::string& path) { std::ifstream in(path, std::ios::binary); if (!in) return {}; in.seekg(0, std::ios::end); auto size = in.tellg(); if (size < 0 || static_cast<std::uint64_t>(size) > MAX_REQUEST_BYTES) return {}; in.seekg(0, std::ios::beg); return std::string((std::istreambuf_iterator<char>(in)), {}); }
std::string json_escape(const std::string& value) { std::ostringstream out; for (unsigned char c : value) { switch (c) { case '\\': out << "\\\\"; break; case '"': out << "\\\""; break; case '\n': out << "\\n"; break; case '\r': out << "\\r"; break; case '\t': out << "\\t"; break; default: if (c < 0x20) out << "\\u00" << std::hex << static_cast<unsigned>(c); else out << static_cast<char>(c); } } return out.str(); }
using Json = nlohmann::json;

std::string bounded_string(const Json& value, const std::string& fallback) {
    if (!value.is_string()) return fallback;
    std::string result = value.get<std::string>();
    return result.size() <= MAX_STRING_BYTES ? result : fallback;
}

std::vector<std::string> bounded_array(const Json& object, const char* key, const std::vector<std::string>& fallback) {
    const auto found = object.find(key);
    if (found == object.end() || !found->is_array()) return fallback;
    std::vector<std::string> result;
    for (const auto& item : *found) {
        if (result.size() >= MAX_ARRAY_ITEMS) break;
        if (!item.is_string()) continue;
        const std::string value = item.get<std::string>();
        if (value.size() <= MAX_STRING_BYTES) result.push_back(value);
    }
    return result.empty() ? fallback : result;
}

std::uint64_t bounded_number(const Json& object, const char* key, std::uint64_t fallback) {
    const auto found = object.find(key);
    if (found == object.end() || !found->is_number_unsigned()) return fallback;
    return found->get<std::uint64_t>();
}

bool config_from_json(const std::string& text, secscope::ScannerConfig* config, std::string* error) {
    if (!config) return false;
    Json object;
    try {
        object = Json::parse(text);
    } catch (const std::exception& exception) {
        if (error) *error = std::string("invalid request JSON: ") + exception.what();
        return false;
    }
    if (!object.is_object()) { if (error) *error = "request JSON must be an object"; return false; }
    secscope::ScannerConfig c;
    c.profile = bounded_string(object.value("profile", Json("daily-hunt")), "daily-hunt");
    c.output_dir = bounded_string(object.value("output_dir", Json(".")), ".");
    c.roots = bounded_array(object, "roots", {"/tmp", "/var/tmp", "/dev/shm", "/etc", "/usr/local/bin", "/usr/local/sbin", "/opt", "/srv/www", "/var/www", "/usr/share/nginx", "/home", "/root"});
    c.exclude_names = bounded_array(object, "exclude_names", {"node_modules", ".git", ".svn", "__pycache__", "overlay2", "containers", "cache"});
    c.extensions = bounded_array(object, "extensions", {"sh", "bash", "zsh", "py", "pl", "rb", "php", "phtml", "jsp", "js", "jar", "war", "so", "ko", "elf", "bin", "run", "service", "timer", "socket", "path", "mount", "conf"});
    const auto profile_files = c.profile == "full" ? 12000ULL : (c.profile == "fast-hunt" ? 800ULL : 3000ULL);
    const auto profile_depth = c.profile == "full" ? 10ULL : (c.profile == "fast-hunt" ? 4ULL : 5ULL);
    const auto profile_hash = c.profile == "full" ? 512ULL * 1024 * 1024 : (c.profile == "fast-hunt" ? 30ULL * 1024 * 1024 : 100ULL * 1024 * 1024);
    const auto profile_timeout = c.profile == "full" ? 900ULL : (c.profile == "fast-hunt" ? 45ULL : 120ULL);
    c.max_files = std::min<std::uint64_t>(bounded_number(object, "max_files", profile_files), profile_files);
    c.max_depth = static_cast<unsigned>(std::min<std::uint64_t>(bounded_number(object, "max_depth", profile_depth), 64ULL));
    c.max_hash_bytes = std::min<std::uint64_t>(bounded_number(object, "max_hash_bytes", profile_hash), 1024ULL * 1024 * 1024);
    c.timeout_seconds = static_cast<unsigned>(std::min<std::uint64_t>(bounded_number(object, "timeout_seconds", profile_timeout), 86400ULL));
    *config = std::move(c);
    return true;
}
bool ensure_dir(const std::string& path) { std::error_code error; std::filesystem::create_directories(path, error); return !error; }
int scan(const secscope::ScannerConfig& config, const std::string& checkpoint_path, bool resume) {
    (void)resume;
    if (!ensure_dir(config.output_dir) || ::chmod(config.output_dir.c_str(), 0700) != 0) return 2;
    secscope::ResourceBudget budget = secscope::resolve_budget(config); std::string budget_reason;
    if (!secscope::budget_available(budget, &budget_reason)) { secscope::Checkpoint cp; cp.profile = config.profile; cp.status = "PARTIAL"; cp.reason = budget_reason; save_checkpoint(checkpoint_path, cp); return 3; }
    if (std::signal(SIGINT, signal_handler) == SIG_ERR ||
        std::signal(SIGTERM, signal_handler) == SIG_ERR) return 2;
    secscope::Counters counters; std::vector<secscope::InventoryRecord> records;
    auto started = std::chrono::steady_clock::now(); if (!secscope::collect_inventory(config, &records, &counters)) return 4;
    std::mutex hash_mutex; auto hash_start = std::chrono::steady_clock::now();
    if (config.hash) {
        secscope::run_bounded_workers(records.size(), budget, [&](std::size_t index) {
            if (cancelled.load()) return;
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - hash_start).count() >= budget.stage_timeout_seconds) {
                cancelled.store(true); std::lock_guard<std::mutex> lock(hash_mutex); counters.partial = true; counters.partial_reason = "hash_stage_timeout"; return;
            }
            secscope::Counters local;
            secscope::hash_file(records[index].path, config.max_hash_bytes, &records[index], &local);
            std::lock_guard<std::mutex> lock(hash_mutex);
            counters.hash_computed += local.hash_computed; counters.hash_failed += local.hash_failed; counters.skipped += local.skipped;
        }, &counters);
    }
    auto process_start = std::chrono::steady_clock::now(); std::vector<secscope::ProcessRecord> processes; secscope::collect_process_snapshot(&processes, &counters); secscope::write_process_snapshot(config.output_dir + "/process-snapshot.json", processes);
    std::vector<secscope::SocketRecord> sockets; secscope::collect_socket_snapshot(&sockets, &counters); secscope::write_socket_snapshot(config.output_dir + "/socket-snapshot.tsv", sockets);
    if (!secscope::write_inventory(config.output_dir + "/file-inventory-current.tsv", records, counters)) return 5;
    secscope::Checkpoint cp; cp.profile = config.profile; cp.completed = records.size(); cp.total = records.size(); cp.status = (cancelled.load() || counters.partial) ? "PARTIAL" : "SUCCESS"; cp.reason = counters.partial_reason; save_checkpoint(checkpoint_path, cp);
    auto elapsed = [](auto a, auto b) { return std::chrono::duration_cast<std::chrono::microseconds>(b-a).count(); };
    std::ofstream summary(config.output_dir + "/summary.json", std::ios::trunc); if (!summary) return 6;
    summary << "{\"schema_version\":1,\"engine\":\"native\",\"profile\":\"" << json_escape(config.profile) << "\",\"status\":\"" << cp.status << "\",\"workers\":" << budget.workers << ",\"resource_budget\":{\"vcpus\":" << budget.vcpus << ",\"max_memory_mb\":" << budget.max_memory_mb << ",\"load_factor_limit\":" << budget.max_load_factor << ",\"io_psi_avg10\":" << budget.io_psi_avg10 << ",\"memory_psi_avg10\":" << budget.memory_psi_avg10 << ",\"rotational_storage\":" << (budget.rotational_storage ? "true" : "false") << ",\"constrained\":" << (budget.constrained ? "true" : "false") << "},\"files\":" << records.size() << ",\"processes\":" << processes.size() << ",\"sockets\":" << sockets.size() << ",\"counters\":{\"files_traversed\":" << counters.files_traversed << ",\"stat_calls\":" << counters.stat_calls << ",\"hash_computed\":" << counters.hash_computed << ",\"hash_failed\":" << counters.hash_failed << ",\"permission_denied\":" << counters.permission_denied << ",\"disappeared\":" << counters.disappeared << ",\"symlink_skipped\":" << counters.symlink_skipped << ",\"proc_pid_visits\":" << counters.proc_pid_visits << ",\"proc_maps_visits\":" << counters.proc_maps_visits << ",\"socket_snapshots\":" << counters.socket_snapshots << "},\"stages_us\":{\"inventory\":" << elapsed(started, hash_start) << ",\"hash\":" << elapsed(hash_start, process_start) << "}}\n";
    return 0;
}
}

int main(int argc, char** argv) {
    if (argc < 2) { std::cerr << "usage: scanner self-test|capabilities|scan|resume|discover-candidates|parse-web-access|parse-events|filesystem-facts|analyze-binary|analyze-static|hash-files|runtime-snapshot|file-monitor [options]\n"; return 2; }
    std::string command = argv[1];
    if (secscope::is_native_helper_command(command)) return secscope::run_native_helper(command, argc - 2, argv + 2);
    if (command == "capabilities") { std::cout << "{\"schema_version\":1,\"protocol_version\":2,\"linux_only\":true,\"openssl\":true,\"hash_analyzer_version\":\"" << secscope::NATIVE_HASH_ANALYZER_VERSION << "\",\"features\":[\"file_inventory\",\"hashing\",\"process_snapshot\",\"socket_snapshot\",\"worker_pool\",\"checkpoint\",\"native_candidate_discovery\",\"native_web_access_parser\",\"native_static_analyzer\",\"native_binary_analyzer\",\"native_hash_files\",\"native_file_monitor\",\"native_runtime_collector\",\"native_filesystem_facts\",\"native_events_parser\"]}\n"; return 0; }
    if (command == "self-test") { secscope::ScannerConfig c; c.roots = {"/tmp"}; c.max_files = 4; c.max_depth = 1; c.output_dir = "/tmp/secscope-native-self-test"; secscope::Counters counters; std::vector<secscope::InventoryRecord> records; return secscope::collect_inventory(c, &records, &counters) ? 0 : 1; }
    std::string request, checkpoint = ".secscope-checkpoint.json"; for (int i = 2; i < argc; ++i) { if (std::string(argv[i]) == "--request" && i + 1 < argc) request = argv[++i]; else if (std::string(argv[i]) == "--checkpoint" && i + 1 < argc) checkpoint = argv[++i]; }
    if ((command == "scan" || command == "resume") && request.empty()) { std::cerr << "--request is required\n"; return 2; }
    if (command == "scan" || command == "resume") {
        struct stat request_stat{};
        const std::string request_json = read_all(request);
        if (::lstat(request.c_str(), &request_stat) != 0 || !S_ISREG(request_stat.st_mode) || (request_stat.st_mode & 077) != 0 || request_stat.st_uid != ::getuid() || request_json.empty()) {
            std::cerr << "request must be a regular file owned by the invoking user with mode 0600 or stricter\n";
            return 2;
        }
        secscope::ScannerConfig config;
        std::string config_error;
        if (!config_from_json(request_json, &config, &config_error)) {
            std::cerr << config_error << '\n';
            return 2;
        }
        return scan(config, checkpoint, command == "resume");
    }
    std::cerr << "unknown command\n"; return 2;
}
