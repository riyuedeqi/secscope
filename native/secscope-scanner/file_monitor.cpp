#include "file_monitor.hpp"

#include "hashing.hpp"
#include "native_io.hpp"
#include "types.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cerrno>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <nlohmann/json.hpp>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {
using Json = nlohmann::json;

struct BaselineEntry {
    std::string path;
    std::string dev;
    std::string inode;
    std::string size;
    std::string mtime;
    std::string ctime;
    std::string md5;
    std::string sha256;
};

struct Candidate {
    std::size_t index = 0;
    std::string priority_score;
    std::string priority_mtime;
    std::string priority_size;
    std::string path;
    std::string priority_reasons = "DEFAULT";
};

struct Behavior {
    std::string priority = "NORMAL";
    std::string priority_score;
    std::string priority_reasons;
    std::string size;
    std::string action;
    std::string path;
    std::string sev;
    std::string confidence;
    std::string md5;
    std::string sha256;
    std::string reason;
    std::string context;
};

struct Finding {
    std::string severity;
    std::string category = "filesystem";
    std::string summary;
    std::string evidence;
    std::string recommendation = "核查来源、变更窗口、包归属、进程树和网络目的；确认恶意后再隔离";
    std::string mitre = "T1105";
    std::string rule_id;
    std::string entity;
    std::string raw_refs = "file-changes.tsv,suspicious-files.tsv,file-inventory-current.tsv";
    std::string finding_type;
    std::string confidence;
    std::string judgment_basis = "基于本轮本机只读证据与规则条件；严重度表示处置优先级，不等同于已经确认入侵。";
    std::string escalation_conditions = "若出现恶意哈希、执行与外连、持久化或多源终端防护命中，应提高风险等级";
    std::string evidence_domains;
    std::string counter_evidence;
    std::string timeline;
};

struct FileMonitorCounters {
    std::uint64_t scanned = 0;
    std::uint64_t skipped = 0;
    std::uint64_t hash_success = 0;
    std::uint64_t hash_reused = 0;
    std::uint64_t hash_failed = 0;
    std::uint64_t changes = 0;
    std::uint64_t suspicious = 0;
    std::uint64_t observe = 0;
    std::uint64_t added_small = 0;
    std::uint64_t small_priority = 0;
    std::uint64_t file_findings = 0;
    bool timed_out = false;
    bool max_files_reached = false;
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

std::string lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool valid_digest(const std::string& value, std::size_t length) {
    if (value.size() != length) return false;
    for (unsigned char item : value) if (!std::isxdigit(item)) return false;
    return true;
}

std::unordered_set<std::string> csv_set(const std::string& csv) {
    std::unordered_set<std::string> result;
    std::string item;
    std::stringstream stream(csv);
    while (std::getline(stream, item, ',')) {
        item = lower_copy(secscope::trim_line(item));
        item.erase(std::remove_if(item.begin(), item.end(), [](unsigned char c) { return std::isspace(c); }), item.end());
        if (!item.empty()) result.insert(item);
    }
    return result;
}

bool has_hash(const std::unordered_set<std::string>& values, const std::string& digest) {
    return !digest.empty() && values.find(lower_copy(digest)) != values.end();
}

bool critical_persistence_path(const std::string& path) {
    if (path == "/etc/passwd" || path == "/etc/shadow" || path == "/etc/group" || path == "/etc/gshadow" ||
        path == "/etc/sudoers" || path == "/etc/crontab" || path == "/etc/rc.local" ||
        path == "/etc/ld.so.preload" || path == "/etc/ld.preload" || path == "/etc/profile") return true;
    const std::vector<std::string> prefixes{"/etc/sudoers.d/", "/etc/cron.d/", "/var/spool/cron/", "/etc/pam.d/", "/etc/systemd/system/", "/etc/profile.d/"};
    for (const auto& prefix : prefixes) if (path.rfind(prefix, 0) == 0) return true;
    const std::vector<std::string> suffixes{"/.ssh/authorized_keys", "/.bashrc", "/.bash_profile", "/.profile", "/.zshrc"};
    for (const auto& suffix : suffixes) if (path.size() >= suffix.size() && path.compare(path.size() - suffix.size(), suffix.size(), suffix) == 0) return true;
    return path == "/root/.bashrc" || path == "/root/.bash_profile" || path == "/root/.profile" || path == "/root/.zshrc";
}

bool same_baseline(const BaselineEntry& baseline, const struct stat& status) {
    return baseline.dev == std::to_string(static_cast<std::uint64_t>(status.st_dev)) &&
           baseline.inode == std::to_string(static_cast<std::uint64_t>(status.st_ino)) &&
           baseline.size == std::to_string(static_cast<std::uint64_t>(status.st_size)) &&
           baseline.mtime == std::to_string(static_cast<std::int64_t>(status.st_mtime)) &&
           baseline.ctime == std::to_string(static_cast<std::int64_t>(status.st_ctime)) &&
           valid_digest(baseline.md5, 32) && valid_digest(baseline.sha256, 64);
}

bool load_baseline(const std::string& path, const std::string& expected_cache_key,
                   const std::string& expected_analyzer, const std::string& expected_profile,
                   const std::string& expected_max_bytes, const std::string& expected_rules,
                   std::map<std::string, BaselineEntry>* by_path,
                   std::unordered_map<std::string, std::string>* inode_to_path,
                   bool* baseline_available) {
    if (baseline_available) *baseline_available = false;
    if (path.empty()) return true;
    std::ifstream input(path);
    if (!input) {
        struct stat status {};
        if (::stat(path.c_str(), &status) != 0 && errno == ENOENT) {
            // A first scan has no inventory yet. Treat a missing baseline as
            // an empty baseline, while preserving hard failures for existing
            // but unreadable/invalid paths.
            return true;
        }
        return false;
    }
    std::string line;
    bool first_line = true;
    bool compatible = expected_cache_key.empty();
    bool header_seen = false;
    while (std::getline(input, line)) {
        if (first_line) {
            first_line = false;
            if (line.rfind("#secscope-file-inventory-v3\t", 0) == 0) {
                header_seen = true;
                const auto header = split_tsv(line);
                compatible = expected_cache_key.empty() ||
                             (header.size() >= 8 && header[3] == expected_analyzer && header[4] == expected_profile &&
                              header[5] == expected_max_bytes && header[6] == expected_rules && header[7] == expected_cache_key);
                if (compatible && baseline_available) *baseline_available = true;
                continue;
            }
            if (!expected_cache_key.empty()) compatible = false;
        }
        if (!compatible || line.empty() || line[0] == '#') continue;
        const auto fields = split_tsv(line);
        if (fields.size() < 8 || fields[0].empty() || !valid_digest(fields[5], 32) || !valid_digest(fields[6], 64)) continue;
        BaselineEntry entry{fields[0], fields[1], fields[2], fields[3], fields[4], fields[7], fields[5], fields[6]};
        (*by_path)[entry.path] = entry;
        (*inode_to_path)[entry.dev + ":" + entry.inode] = entry.path;
    }
    if (!header_seen && expected_cache_key.empty() && baseline_available) *baseline_available = true;
    return true;
}

std::vector<Candidate> load_candidates(const std::string& path) {
    std::ifstream input(path);
    std::vector<Candidate> result;
    std::string line;
    std::size_t index = 0;
    while (std::getline(input, line)) {
        const auto fields = split_tsv(line);
        if (fields.size() < 4 || fields[3].empty() || fields[3] == "path") continue;
        Candidate candidate;
        candidate.index = index++;
        candidate.priority_score = fields[0];
        candidate.priority_mtime = fields.size() > 1 ? fields[1] : "";
        candidate.priority_size = fields.size() > 2 ? fields[2] : "";
        candidate.path = fields[3];
        candidate.priority_reasons = fields.size() > 4 && !fields[4].empty() ? fields[4] : "DEFAULT";
        result.push_back(candidate);
    }
    return result;
}

void append_unique(std::unordered_map<std::string, std::vector<std::string>>* index, const std::string& key, const std::string& value, std::size_t max_items = 8) {
    if (key.empty() || value.empty()) return;
    auto& values = (*index)[key];
    if (std::find(values.begin(), values.end(), value) == values.end() && values.size() < max_items) values.push_back(value);
}

struct ContextIndexes {
    std::unordered_map<std::string, std::vector<std::string>> process_by_path;
    std::unordered_map<std::string, std::vector<std::string>> network_by_pid;
    std::unordered_map<std::string, std::vector<std::string>> persistence_by_path;
    std::unordered_map<std::string, std::string> package_by_path;
    std::string package_status = "UNAVAILABLE";
};

void load_process_context(const std::string& path, const std::unordered_set<std::string>& candidates, ContextIndexes* indexes) {
    if (path.empty()) return;
    std::ifstream input(path);
    if (!input) return;
    std::string line;
    bool header = true;
    while (std::getline(input, line)) {
        if (header) { header = false; continue; }
        const auto f = split_tsv(line);
        if (f.size() < 18) continue;
        const std::string& instance = f[0];
        const std::string& pid = f[2];
        const std::string& ppid = f[4];
        const std::string& uid = f[6];
        const std::string& exe = f[10];
        const std::string& package = f[11];
        const std::string& argv = f[17];
        const std::string service = "unassociated";
        const std::string display = "PID=" + pid + "|instance=" + instance + "|exe=" + exe + "|user=" + uid + "|cmdline=" + argv + "|ppid=" + ppid + "|service=" + service + "|package=" + package;
        append_unique(&indexes->process_by_path, exe, display);
        if (candidates.find(exe) != candidates.end()) append_unique(&indexes->process_by_path, exe, display);
        std::stringstream args(argv);
        std::string token;
        while (args >> token) {
            if (candidates.find(token) != candidates.end()) append_unique(&indexes->process_by_path, token, display);
        }
    }
}

void load_socket_context(const std::string& path, ContextIndexes* indexes) {
    if (path.empty()) return;
    std::ifstream input(path);
    if (!input) return;
    std::string line;
    bool header = true;
    while (std::getline(input, line)) {
        if (header) { header = false; continue; }
        const auto f = split_tsv(line);
        if (f.size() < 6 || f[5].empty() || f[5] == "0") continue;
        const std::string formatted = "protocol=" + f[0] + " local=" + f[1] + " remote=" + f[2] + " state=" + f[3] + " inode=" + f[4] + " pid=" + f[5];
        append_unique(&indexes->network_by_pid, f[5], formatted, 5);
    }
}

std::vector<std::filesystem::path> persistence_roots() {
    return {"/etc/systemd/system", "/etc/cron.d", "/etc/crontab", "/var/spool/cron"};
}

void scan_persistence_references(const std::unordered_set<std::string>& candidates, ContextIndexes* indexes) {
    if (candidates.empty()) return;
    std::vector<std::string> candidate_list(candidates.begin(), candidates.end());
    for (const auto& root : persistence_roots()) {
        std::error_code ec;
        if (!std::filesystem::exists(root, ec)) continue;
        std::vector<std::filesystem::path> files;
        if (std::filesystem::is_regular_file(root, ec)) files.push_back(root);
        else {
            std::filesystem::recursive_directory_iterator it(root, std::filesystem::directory_options::skip_permission_denied, ec), end;
            for (; !ec && it != end; it.increment(ec)) {
                if (!it->is_regular_file(ec) || it->is_symlink(ec)) continue;
                files.push_back(it->path());
            }
        }
        for (const auto& file : files) {
            std::ifstream input(file);
            if (!input) continue;
            std::string line;
            std::uint64_t lineno = 0;
            std::uint64_t bytes = 0;
            while (std::getline(input, line)) {
                bytes += line.size();
                if (bytes > 4ULL * 1024ULL * 1024ULL) break;
                ++lineno;
                for (const auto& candidate : candidate_list) {
                    if (line.find(candidate) != std::string::npos) {
                        append_unique(&indexes->persistence_by_path, candidate, file.string() + ":" + std::to_string(lineno) + ":" + secscope::clean_cell(line), 5);
                    }
                }
            }
        }
    }
}

void load_dpkg_packages(const std::unordered_set<std::string>& candidates, ContextIndexes* indexes) {
    std::filesystem::path info("/var/lib/dpkg/info");
    std::error_code ec;
    if (!std::filesystem::is_directory(info, ec)) return;
    indexes->package_status = "AVAILABLE";
    std::filesystem::directory_iterator it(info, std::filesystem::directory_options::skip_permission_denied, ec), end;
    for (; !ec && it != end; it.increment(ec)) {
        const auto path = it->path();
        const std::string filename = path.filename().string();
        if (filename.size() <= 5 || filename.compare(filename.size() - 5, 5, ".list") != 0) continue;
        std::ifstream input(path);
        if (!input) continue;
        const std::string package = filename.substr(0, filename.size() - 5);
        std::string package_path;
        while (std::getline(input, package_path)) {
            if (candidates.find(package_path) != candidates.end() && indexes->package_by_path.find(package_path) == indexes->package_by_path.end()) {
                indexes->package_by_path[package_path] = package + ": " + package_path;
            }
        }
    }
}

std::string join(const std::vector<std::string>& values, const std::string& sep) {
    std::string result;
    for (const auto& value : values) result += result.empty() ? value : sep + value;
    return result;
}

std::string process_context_for(const ContextIndexes& indexes, const std::string& path) {
    const auto found = indexes.process_by_path.find(path);
    return found == indexes.process_by_path.end() ? "" : join(found->second, ",");
}

std::string network_context_for(const ContextIndexes& indexes, const std::string& process_context) {
    std::string result;
    std::size_t pos = 0;
    while ((pos = process_context.find("PID=", pos)) != std::string::npos) {
        pos += 4;
        std::size_t end = pos;
        while (end < process_context.size() && std::isdigit(static_cast<unsigned char>(process_context[end]))) ++end;
        const std::string pid = process_context.substr(pos, end - pos);
        const auto found = indexes.network_by_pid.find(pid);
        if (found != indexes.network_by_pid.end()) {
            const std::string joined = join(found->second, "\n");
            result += result.empty() ? joined : "\n" + joined;
        }
        pos = end;
    }
    return result;
}

std::string persistence_context_for(const ContextIndexes& indexes, const std::string& path) {
    const auto found = indexes.persistence_by_path.find(path);
    return found == indexes.persistence_by_path.end() ? "" : join(found->second, "\n");
}

std::string package_owner_for(const ContextIndexes& indexes, const std::string& path) {
    const auto found = indexes.package_by_path.find(path);
    return found == indexes.package_by_path.end() ? "" : found->second;
}

std::string safe_num(const std::string& value, const std::string& fallback = "0") {
    return !value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char c) { return std::isdigit(c); }) ? value : fallback;
}

void emit_finding(std::ostream& out, const Finding& finding) {
    Json row{{"severity", finding.severity}, {"category", finding.category}, {"summary", finding.summary}, {"evidence", finding.evidence},
             {"recommendation", finding.recommendation}, {"mitre", finding.mitre}, {"rule_id", finding.rule_id}, {"entity", finding.entity},
             {"raw_refs", finding.raw_refs}, {"finding_type", finding.finding_type}, {"confidence", finding.confidence},
             {"judgment_basis", finding.judgment_basis}, {"escalation_conditions", finding.escalation_conditions},
             {"evidence_domains", finding.evidence_domains}, {"counter_evidence", finding.counter_evidence}, {"timeline", finding.timeline}};
    out << row.dump() << '\n';
}

Behavior assess_change(const std::string& action, const secscope::InventoryRecord& record, const Candidate& candidate,
                       const std::string& moved_from, const ContextIndexes& indexes,
                       std::uint64_t small_priority_bytes, const std::string& maintenance_active,
                       const std::unordered_set<std::string>& malicious_hashes, Finding* finding) {
    const std::string process_context = process_context_for(indexes, record.path);
    const std::string network_context = network_context_for(indexes, process_context);
    const std::string persistence_context = persistence_context_for(indexes, record.path);
    const std::string package_owner = package_owner_for(indexes, record.path);
    std::string sev = "OBSERVE";
    std::string confidence = "LOW";
    std::string reason = "仅检测到文件清单变化，尚无危险行为关联";
    std::string finding_type = "SECURITY_ANOMALY";
    std::string rule = "FS-FILE-CHANGE";
    std::string domains = "FILE";
    if (has_hash(malicious_hashes, record.md5) || has_hash(malicious_hashes, record.sha256)) {
        sev = "CRITICAL"; confidence = "HIGH"; reason = "命中组织确认恶意哈希"; finding_type = "SECURITY_THREAT"; rule = "FS-MALICIOUS-HASH"; domains = "FILE,INTEGRITY";
    } else if (!network_context.empty()) {
        sev = "HIGH"; confidence = "HIGH"; reason = "变化文件正被进程执行并存在网络连接"; finding_type = "SECURITY_THREAT"; domains = "FILE,PROCESS,NETWORK";
    } else if (!process_context.empty() && (record.path.rfind("/tmp/", 0) == 0 || record.path.rfind("/var/tmp/", 0) == 0 || record.path.rfind("/dev/shm/", 0) == 0)) {
        sev = "HIGH"; confidence = "MEDIUM"; reason = "临时目录变化文件正在执行，但未发现当前网络关联"; domains = "FILE,PROCESS";
    } else if (critical_persistence_path(record.path)) {
        sev = "MEDIUM"; confidence = "MEDIUM"; reason = "认证、提权或持久化关键文件发生变化"; domains = "FILE,PERSISTENCE";
    } else if (!process_context.empty() || !persistence_context.empty()) {
        sev = "MEDIUM"; confidence = "MEDIUM"; reason = "变化文件关联当前进程或持久化配置"; domains = "FILE";
        if (!process_context.empty()) domains += ",PROCESS";
        if (!persistence_context.empty()) domains += ",PERSISTENCE";
    } else if (action == "MODIFIED" && (record.path.rfind("/etc/", 0) == 0 || record.path.rfind("/usr/local/bin/", 0) == 0 || record.path.rfind("/usr/local/sbin/", 0) == 0)) {
        sev = "LOW"; confidence = "MEDIUM"; reason = "敏感配置或本地程序路径内容发生变化";
    }
    std::string priority = "NORMAL";
    if (action == "ADDED" && record.size < small_priority_bytes) {
        priority = "SMALL_ADDED";
        reason = "新增小文件优先监测（< " + std::to_string(small_priority_bytes / 1024) + " KB）；" + reason;
    }
    reason = "优先分=" + safe_num(candidate.priority_score) + "（" + candidate.priority_reasons + "）；" + reason;
    if (!package_owner.empty()) reason += "；包归属=" + package_owner;
    if (!moved_from.empty()) reason = "从 " + moved_from + " 移动；" + reason;
    const std::string context = "process=" + (process_context.empty() ? "none" : process_context) + "; network=" + (network_context.empty() ? "none" : network_context) +
                                "; persistence=" + (persistence_context.empty() ? "none" : persistence_context) + "; package=" + (package_owner.empty() ? "unowned" : package_owner) +
                                "; moved_from=" + (moved_from.empty() ? "none" : moved_from);
    Behavior behavior{priority, safe_num(candidate.priority_score), candidate.priority_reasons, std::to_string(record.size), action, record.path, sev, confidence, record.md5, record.sha256, reason, context};
    if (finding) {
        finding->severity = sev;
        finding->summary = "文件行为 " + action + ": " + record.path;
        finding->evidence = "size=" + std::to_string(record.size) + "; priority=" + priority + "; priority_score=" + safe_num(candidate.priority_score) +
                            "; priority_reasons=" + candidate.priority_reasons + "; MD5=" + (record.md5.empty() ? "N/A" : record.md5) +
                            "; SHA256=" + (record.sha256.empty() ? "N/A" : record.sha256) + "; " + context + "; 原因=" + reason;
        finding->rule_id = rule;
        finding->entity = record.path;
        finding->finding_type = finding_type;
        finding->confidence = confidence;
        finding->evidence_domains = domains;
        finding->counter_evidence = "包归属=" + (package_owner.empty() ? "unowned" : package_owner) + "；维护窗口=" + maintenance_active + "；批准哈希未命中";
        finding->timeline = "FILE|" + action + " " + record.path + ";PROCESS|" + (process_context.empty() ? "none" : process_context) +
                            ";NETWORK|" + (network_context.empty() ? "none" : network_context) + ";PERSISTENCE|" + (persistence_context.empty() ? "none" : persistence_context);
    }
    return behavior;
}

} // namespace

namespace secscope {

int run_file_monitor(const Arguments& args) {
    std::string error;
    if (!required_arguments(args, {"--input-list", "--inventory-output", "--changes-output", "--errors-output", "--suspicious-output", "--findings-output", "--summary-output"}, &error)) {
        std::cerr << error << '\n';
        return 2;
    }
    const std::string input_list = argument(args, "--input-list");
    std::ifstream candidate_input(input_list);
    if (!candidate_input) {
        std::cerr << "cannot open file-monitor input list\n";
        return 2;
    }
    const auto candidates = load_candidates(input_list);
    if (candidate_input.bad()) {
        std::cerr << "cannot read file-monitor input list\n";
        return 2;
    }
    std::unordered_set<std::string> candidate_paths;
    for (const auto& candidate : candidates) candidate_paths.insert(candidate.path);

    std::map<std::string, BaselineEntry> baseline;
    std::unordered_map<std::string, std::string> baseline_inode_to_path;
    bool baseline_available = false;
    if (!load_baseline(argument(args, "--baseline"), argument(args, "--cache-key"), argument(args, "--cache-analyzer-version"),
                       argument(args, "--cache-profile"), argument(args, "--cache-max-bytes"), argument(args, "--cache-rules"),
                       &baseline, &baseline_inode_to_path, &baseline_available)) {
        std::cerr << "cannot open file-monitor baseline\n";
        return 2;
    }
    for (const auto& item : baseline) candidate_paths.insert(item.first);

    ContextIndexes indexes;
    load_process_context(argument(args, "--process-context"), candidate_paths, &indexes);
    load_socket_context(argument(args, "--socket-tsv"), &indexes);
    scan_persistence_references(candidate_paths, &indexes);
    load_dpkg_packages(candidate_paths, &indexes);

    AtomicOutput inventory(argument(args, "--inventory-output"));
    AtomicOutput changes(argument(args, "--changes-output"));
    AtomicOutput errors(argument(args, "--errors-output"));
    AtomicOutput suspicious(argument(args, "--suspicious-output"));
    AtomicOutput findings(argument(args, "--findings-output"));
    AtomicOutput summary(argument(args, "--summary-output"));
    if (!inventory.good() || !changes.good() || !errors.good() || !suspicious.good() || !findings.good() || !summary.good()) return 2;

    const std::uint64_t max_bytes = uint_argument(args, "--max-bytes", 100ULL * 1024ULL * 1024ULL, 1, 2ULL * 1024ULL * 1024ULL * 1024ULL);
    const std::uint64_t max_files = uint_argument(args, "--max-files", 50000, 1, 1000000);
    const std::uint64_t small_priority_bytes = uint_argument(args, "--small-priority-bytes", 200ULL * 1024ULL, 1, 1024ULL * 1024ULL * 1024ULL);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(uint_argument(args, "--timeout-seconds", 120, 1, 86400));
    const auto approved_hashes = csv_set(argument(args, "--approved-hashes"));
    const auto malicious_hashes = csv_set(argument(args, "--malicious-hashes"));
    const std::string maintenance_active = argument(args, "--maintenance-active", "false");

    inventory.stream() << argument(args, "--inventory-header", "#secscope-file-inventory-v3\tnative\tnative\tnative-hash-files-v2\tunknown\t0\tunknown\tunknown") << '\n';
    changes.stream() << "";
    errors.stream() << "";
    suspicious.stream() << "priority\tpriority_score\tpriority_reasons\tsize_bytes\taction\tpath\tseverity\tconfidence\tmd5\tsha256\treason\tcontext\n";

    FileMonitorCounters counters;
    std::unordered_set<std::string> current_paths;
    std::unordered_map<std::string, std::string> current_inode_to_path;
    bool partial = false;

    for (const auto& candidate : candidates) {
        if (counters.scanned >= max_files) { counters.max_files_reached = true; partial = true; break; }
        if (std::chrono::steady_clock::now() >= deadline) { counters.timed_out = true; partial = true; break; }
        InventoryRecord record;
        record.path = candidate.path;
        if (candidate.priority_reasons.find("ADDED_SMALL") != std::string::npos) ++counters.small_priority;
        struct stat st{};
        const bool have_status = ::lstat(record.path.c_str(), &st) == 0;
        bool hash_attempted = false;
        if (have_status) {
            record.dev = static_cast<std::uint64_t>(st.st_dev);
            record.inode = static_cast<std::uint64_t>(st.st_ino);
            record.size = st.st_size < 0 ? 0 : static_cast<std::uint64_t>(st.st_size);
            record.mtime = static_cast<std::int64_t>(st.st_mtime);
            record.ctime = static_cast<std::int64_t>(st.st_ctime);
        } else {
            record.status = errno == ENOENT ? "DELETED" : "UNREADABLE";
            record.error = errno == EACCES ? "permission_denied" : "lstat_failed";
        }
        const auto baseline_found = baseline.find(record.path);
        secscope::Counters hash_counters;
        if (have_status && S_ISREG(st.st_mode) && baseline_found != baseline.end() && same_baseline(baseline_found->second, st)) {
            record.status = "REUSED";
            record.md5 = baseline_found->second.md5;
            record.sha256 = baseline_found->second.sha256;
            ++counters.hash_reused;
        } else if (have_status && S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
            hash_attempted = true;
            hash_file(record.path, max_bytes, &record, &hash_counters);
            if (record.status == "SUCCESS") ++counters.hash_success;
        } else if (have_status) {
            record.status = S_ISLNK(st.st_mode) ? "SYMLINK_SKIPPED" : "SPECIAL_FILE_SKIPPED";
            record.error = S_ISLNK(st.st_mode) ? "symbolic_link" : "not_regular_file";
        }
        ++counters.scanned;
        if (!(record.status == "SUCCESS" || record.status == "REUSED")) {
            ++counters.skipped;
            if (hash_attempted) ++counters.hash_failed;
            errors.stream() << clean_cell(record.path) << '\t' << clean_cell(record.status) << '\t' << clean_cell(record.error.empty() ? "native_hash_failed" : record.error) << '\n';
            continue;
        }
        current_paths.insert(record.path);
        const std::string inode_key = std::to_string(record.dev) + ":" + std::to_string(record.inode);
        current_inode_to_path[inode_key] = record.path;
        inventory.stream() << clean_cell(record.path) << '\t' << record.dev << '\t' << record.inode << '\t' << record.size << '\t' << record.mtime << '\t' << clean_cell(record.md5) << '\t' << clean_cell(record.sha256) << '\t' << record.ctime << '\n';

        std::string action;
        std::string old_path;
        if (baseline_available && baseline_found != baseline.end()) {
            if (baseline_found->second.sha256 != record.sha256) action = "MODIFIED";
        } else if (baseline_available) {
            const auto moved = baseline_inode_to_path.find(inode_key);
            if (moved != baseline_inode_to_path.end()) { action = "MOVED"; old_path = moved->second; }
            else action = "ADDED";
        }
        if (action.empty()) continue;
        ++counters.changes;
        const std::string priority = action == "ADDED" && record.size < small_priority_bytes ? "SMALL_ADDED" : "NORMAL";
        changes.stream() << action << '\t' << clean_cell(record.path) << '\t' << clean_cell(old_path) << '\t' << clean_cell(record.md5) << '\t' << clean_cell(record.sha256) << '\t' << record.size << '\t' << priority << '\t' << safe_num(candidate.priority_score) << '\t' << clean_cell(candidate.priority_reasons) << '\n';
        if (has_hash(approved_hashes, record.md5) || has_hash(approved_hashes, record.sha256)) continue;
        Finding finding;
        Behavior behavior = assess_change(action, record, candidate, old_path, indexes, small_priority_bytes, maintenance_active, malicious_hashes, &finding);
        suspicious.stream() << behavior.priority << '\t' << behavior.priority_score << '\t' << clean_cell(behavior.priority_reasons) << '\t' << behavior.size << '\t' << behavior.action << '\t' << clean_cell(behavior.path) << '\t' << behavior.sev << '\t' << behavior.confidence << '\t' << clean_cell(behavior.md5) << '\t' << clean_cell(behavior.sha256) << '\t' << clean_cell(behavior.reason) << '\t' << clean_cell(behavior.context) << '\n';
        emit_finding(findings.stream(), finding);
        ++counters.file_findings;
        if (behavior.sev == "OBSERVE") ++counters.observe; else ++counters.suspicious;
        if (behavior.priority == "SMALL_ADDED") ++counters.added_small;
    }

    if (!partial && baseline_available) {
        Candidate deleted_candidate;
        deleted_candidate.priority_score = "0";
        deleted_candidate.priority_reasons = "DELETED_BASELINE";
        for (const auto& item : baseline) {
            const auto& old = item.second;
            if (current_paths.find(old.path) != current_paths.end()) continue;
            const std::string inode_key = old.dev + ":" + old.inode;
            if (current_inode_to_path.find(inode_key) != current_inode_to_path.end()) continue;
            deleted_candidate.path = old.path;
            if (critical_persistence_path(old.path)) {
                deleted_candidate.priority_score = safe_num(argument(args, "--priority-persistence-path", "100"));
                deleted_candidate.priority_reasons = "PERSISTENCE_PATH";
            } else {
                deleted_candidate.priority_score = "0";
                deleted_candidate.priority_reasons = "DELETED_BASELINE";
            }
            InventoryRecord deleted_record;
            deleted_record.path = old.path;
            deleted_record.size = std::strtoull(old.size.c_str(), nullptr, 10);
            deleted_record.md5 = old.md5;
            deleted_record.sha256 = old.sha256;
            ++counters.changes;
            changes.stream() << "DELETED\t" << clean_cell(old.path) << "\t\t" << clean_cell(old.md5) << '\t' << clean_cell(old.sha256) << '\t' << clean_cell(old.size) << "\tNORMAL\t" << deleted_candidate.priority_score << '\t' << deleted_candidate.priority_reasons << '\n';
            if (has_hash(approved_hashes, deleted_record.md5) || has_hash(approved_hashes, deleted_record.sha256)) continue;
            Finding finding;
            Behavior behavior = assess_change("DELETED", deleted_record, deleted_candidate, "", indexes, small_priority_bytes, maintenance_active, malicious_hashes, &finding);
            suspicious.stream() << behavior.priority << '\t' << behavior.priority_score << '\t' << clean_cell(behavior.priority_reasons) << '\t' << behavior.size << '\t' << behavior.action << '\t' << clean_cell(behavior.path) << '\t' << behavior.sev << '\t' << behavior.confidence << '\t' << clean_cell(behavior.md5) << '\t' << clean_cell(behavior.sha256) << '\t' << clean_cell(behavior.reason) << '\t' << clean_cell(behavior.context) << '\n';
            emit_finding(findings.stream(), finding);
            ++counters.file_findings;
            if (behavior.sev == "OBSERVE") ++counters.observe; else ++counters.suspicious;
        }
    }

    const bool outputs_ok = inventory.commit() && changes.commit() && errors.commit() && suspicious.commit() && findings.commit();
    if (!outputs_ok) return 2;
    const std::string status = partial ? "PARTIAL" : "SUCCESS";
    Json result{{"schema_version", 1}, {"status", status}, {"scanned", counters.scanned}, {"skipped", counters.skipped},
                {"hash_success", counters.hash_success}, {"hash_reused", counters.hash_reused}, {"hash_failed", counters.hash_failed},
                {"changes", counters.changes}, {"suspicious", counters.suspicious}, {"observe", counters.observe},
                {"added_small", counters.added_small}, {"small_priority", counters.small_priority}, {"file_findings", counters.file_findings},
                {"timed_out", counters.timed_out}, {"max_files_reached", counters.max_files_reached},
                {"baseline_mode", !baseline_available}, {"package_index_status", indexes.package_status},
                {"process_index_paths", indexes.process_by_path.size()}, {"socket_index_pids", indexes.network_by_pid.size()}};
    summary.stream() << result.dump() << '\n';
    return summary.commit() ? 0 : 2;
}

} // namespace secscope
