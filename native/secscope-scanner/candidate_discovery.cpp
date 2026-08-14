#include "candidate_discovery.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cerrno>
#include <deque>
#include <dirent.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <sys/stat.h>
#include <unordered_set>
#include <vector>

namespace secscope {
namespace {

using Clock = std::chrono::steady_clock;
using Json = nlohmann::json;

const std::unordered_set<std::string> CODE = {
    ".php", ".phtml", ".phar", ".jsp", ".jspx", ".asp", ".aspx", ".ashx",
    ".asmx", ".cs", ".vb", ".java", ".class", ".js", ".mjs", ".cjs", ".py",
    ".pl", ".rb", ".ps1", ".config", ".htaccess"};
const std::unordered_set<std::string> ARCHIVE = {
    ".jar", ".war", ".ear", ".zip", ".tar", ".tgz", ".gz", ".nupkg"};
const std::unordered_set<std::string> BINARY = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".ocx", ".drv",
    ".so", ".ko", ".elf", ".bin", ".run"};
const std::unordered_set<std::string> DISGUISE = {
    ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".txt", ".log",
    ".cache", ".dat", ".tmp", ".bin", ".conf", ".xml", ".json"};
const std::unordered_set<std::string> EXCLUDED = {
    ".git", ".svn", "node_modules", "__pycache__", "$recycle.bin",
    "system volume information"};

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string classify(const std::string& path) {
    const std::string value = lower(path);
    const std::string extension = std::filesystem::path(value).extension().string();
    if (CODE.count(extension)) return "code";
    if (BINARY.count(extension)) return "binary";
    if (ARCHIVE.count(extension) || (value.size() >= 7 && value.substr(value.size() - 7) == ".tar.gz")) return "archive";
    if (DISGUISE.count(extension)) return "disguise";
    const std::string base = std::filesystem::path(value).filename().string();
    if (extension.empty() || (!base.empty() && base.front() == '.')) return "code";
    return "other";
}

int root_priority(const std::string& path) {
    const std::string value = lower(absolute_lexical_path(path));
    for (const char* root : {"/tmp", "/var/tmp", "/dev/shm", "/var/www", "/srv/www", "/home"}) {
        const std::string prefix(root);
        if (value == prefix || (value.size() > prefix.size() && value.compare(0, prefix.size(), prefix) == 0 && value[prefix.size()] == '/')) return 3;
    }
    if (value.rfind("/etc", 0) == 0 || value.rfind("/usr/local", 0) == 0) return 2;
    return 1;
}

bool excluded_path(const std::string& path, const std::vector<std::string>& prefixes) {
    const std::string absolute = absolute_lexical_path(path);
    for (const auto& prefix : prefixes) {
        if (prefix == "/" || absolute == prefix ||
            (absolute.size() > prefix.size() && absolute.compare(0, prefix.size(), prefix) == 0 && absolute[prefix.size()] == '/')) return true;
    }
    return false;
}

struct WalkReport {
    std::map<std::string, std::deque<std::string>> queues;
    std::uint64_t discovered = 0;
    std::uint64_t skipped_symlink = 0;
    std::uint64_t skipped_depth = 0;
    std::uint64_t errors = 0;
    std::uint64_t skipped_budget = 0;
    bool timed_out = false;
};

WalkReport walk_root(const std::string& root, unsigned max_depth,
                     Clock::time_point deadline, std::size_t per_class_limit,
                     const std::vector<std::string>& excluded_prefixes) {
    WalkReport report;
    for (const char* name : {"code", "binary", "archive", "disguise", "other"}) report.queues[name] = {};
    std::vector<std::pair<std::string, unsigned>> stack{{root, 0}};
    std::uint64_t visited = 0;
    while (!stack.empty() && Clock::now() < deadline) {
        const auto current = std::move(stack.back());
        stack.pop_back();
        DIR* directory = ::opendir(current.first.c_str());
        if (!directory) { ++report.errors; continue; }
        errno = 0;
        while (dirent* entry = ::readdir(directory)) {
            if ((entry->d_name[0] == '.' && entry->d_name[1] == '\0') ||
                (entry->d_name[0] == '.' && entry->d_name[1] == '.' && entry->d_name[2] == '\0')) continue;
            ++visited;
            if (visited % 256 == 0 && Clock::now() >= deadline) break;
            const std::string path = current.first == "/" ? "/" + std::string(entry->d_name) : current.first + "/" + entry->d_name;
            if (excluded_path(path, excluded_prefixes)) continue;
            struct stat status{};
            if (::lstat(path.c_str(), &status) != 0) { ++report.errors; continue; }
            if (S_ISLNK(status.st_mode)) { ++report.skipped_symlink; continue; }
            if (S_ISDIR(status.st_mode)) {
                if (EXCLUDED.count(lower(entry->d_name))) continue;
                if (current.second < max_depth) stack.emplace_back(path, current.second + 1);
                else ++report.skipped_depth;
                continue;
            }
            if (!S_ISREG(status.st_mode)) continue;
            ++report.discovered;
            const std::string group = classify(path);
            if (group != "other" || entry->d_name[0] == '.') {
                auto& queue = report.queues[group];
                if (queue.size() < per_class_limit) queue.push_back(absolute_lexical_path(path));
                else ++report.skipped_budget;
            }
        }
        if (errno != 0) ++report.errors;
        ::closedir(directory);
    }
    report.timed_out = Clock::now() >= deadline;
    return report;
}

}

int run_candidate_discovery(const Arguments& args) {
    std::string error;
    if (!required_arguments(args, {"--roots-file", "--output-list", "--coverage-jsonl"}, &error)) {
        std::cerr << error << '\n'; return 2;
    }
    const std::size_t max_files = static_cast<std::size_t>(uint_argument(args, "--max-files", 1600, 1, 50000));
    const std::size_t root_quota = static_cast<std::size_t>(uint_argument(args, "--root-quota", 240, 1, 10000));
    const unsigned max_depth = static_cast<unsigned>(uint_argument(args, "--max-depth", 10, 1, 64));
    const auto timeout = std::chrono::seconds(uint_argument(args, "--timeout-seconds", 90, 1, 3600));
    const auto deadline = Clock::now() + timeout;
    std::vector<std::string> excluded_prefixes;
    for (const auto& item : arguments(args, "--exclude-prefix")) {
        if (!item.empty()) excluded_prefixes.push_back(absolute_lexical_path(item));
    }
    std::sort(excluded_prefixes.begin(), excluded_prefixes.end());
    excluded_prefixes.erase(std::unique(excluded_prefixes.begin(), excluded_prefixes.end()), excluded_prefixes.end());

    std::ifstream roots_input(argument(args, "--roots-file"));
    if (!roots_input) { std::cerr << "cannot open roots file\n"; return 2; }
    std::vector<std::string> roots;
    std::set<std::string> seen_roots;
    std::string line;
    while (std::getline(roots_input, line)) {
        line = trim_line(std::move(line));
        if (line.empty()) continue;
        const std::string root = absolute_lexical_path(line);
        struct stat status{};
        if (::lstat(root.c_str(), &status) != 0 || !S_ISDIR(status.st_mode) || S_ISLNK(status.st_mode)) continue;
        if (seen_roots.insert(root).second) roots.push_back(root);
    }
    std::sort(roots.begin(), roots.end(), [](const std::string& left, const std::string& right) {
        const int left_priority = root_priority(left), right_priority = root_priority(right);
        return left_priority != right_priority ? left_priority > right_priority : left < right;
    });

    AtomicOutput candidates(argument(args, "--output-list"));
    AtomicOutput coverage(argument(args, "--coverage-jsonl"));
    if (!candidates.good() || !coverage.good()) { std::cerr << "cannot create discovery output\n"; return 2; }
    const std::size_t fair_quota = std::min(root_quota, std::max<std::size_t>(1, max_files / std::max<std::size_t>(1, roots.size())));
    std::size_t selected = 0;
    std::uint64_t expected = 0;
    std::uint64_t errors = 0;
    std::set<std::string> selected_paths;
    for (const auto& root : roots) {
        if (Clock::now() >= deadline || selected >= max_files) {
            coverage.stream() << Json{{"root", root}, {"selected", 0}, {"status", "NOT_STARTED_TOTAL_LIMIT"}}.dump() << '\n';
            continue;
        }
        WalkReport report = walk_root(root, max_depth, deadline, fair_quota, excluded_prefixes);
        expected += report.discovered;
        errors += report.errors;
        std::size_t picked = 0;
        const std::vector<std::string> order{"code", "binary", "archive", "disguise", "other"};
        bool available = true;
        while (picked < fair_quota && selected < max_files && available) {
            available = false;
            for (const auto& group : order) {
                auto& queue = report.queues[group];
                if (queue.empty()) continue;
                available = true;
                const std::string candidate = queue.front();
                queue.pop_front();
                if (!selected_paths.insert(candidate).second) continue;
                candidates.stream() << candidate << '\n';
                ++picked; ++selected;
                if (picked >= fair_quota || selected >= max_files) break;
            }
        }
        const bool partial = report.timed_out || report.skipped_depth > 0 || report.errors > 0 || report.skipped_budget > 0 || report.discovered > picked;
        Json skip_reasons = Json::array();
        if (report.skipped_budget > 0) skip_reasons.push_back("budget");
        if (report.skipped_depth > 0) skip_reasons.push_back("depth");
        if (report.timed_out) skip_reasons.push_back("timeout");
        if (report.errors > 0) skip_reasons.push_back("errors");
        coverage.stream() << Json{{"discovered", report.discovered}, {"errors", report.errors},
            {"error_count", report.errors}, {"expected_files", report.discovered}, {"scanned_files", picked},
            {"reason", partial ? "time/depth/quota bound" : ""}, {"root", root},
            {"selected", picked}, {"skipped_files", report.discovered > picked ? report.discovered - picked : 0},
            {"skip_reasons", skip_reasons}, {"skipped_budget", report.skipped_budget}, {"skipped_depth", report.skipped_depth},
            {"skipped_symlink", report.skipped_symlink}, {"status", partial ? "PARTIAL" : "COMPLETE"},
            {"timed_out", report.timed_out}}.dump() << '\n';
    }
    const bool timed_out = Clock::now() >= deadline;
    coverage.stream() << Json{{"fair_root_quota", fair_quota}, {"max_files", max_files},
        {"roots", roots.size()}, {"selected", selected}, {"expected_files", expected}, {"scanned_files", selected},
        {"skipped_files", expected > selected ? expected - selected : 0}, {"error_count", errors},
        {"summary", true}, {"timeout", timed_out}}.dump() << '\n';
    if (!candidates.commit() || !coverage.commit()) { std::cerr << "cannot commit discovery output\n"; return 2; }
    std::cout << Json{{"roots", roots.size()}, {"selected", selected},
        {"status", timed_out || selected >= max_files ? "PARTIAL" : "SUCCESS"}}.dump() << '\n';
    return 0;
}

}
