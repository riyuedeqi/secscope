#include "file_inventory.hpp"

#include <algorithm>
#include <chrono>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <set>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_set>

namespace secscope {
namespace {
constexpr std::size_t MAX_DISPLAY_PATH = 4096;
bool unsafe_tsv(const std::string& value) {
    return value.find('\t') != std::string::npos || value.find('\n') != std::string::npos || value.find('\r') != std::string::npos;
}
bool excluded(const ScannerConfig& config, const char* name) {
    for (const auto& item : config.exclude_names) if (item == name) return true;
    return false;
}
bool candidate_extension(const ScannerConfig& config, const std::string& path) {
    auto dot = path.find_last_of('.');
    if (dot == std::string::npos || path.find_last_of('/') > dot) return true;
    std::string extension = path.substr(dot + 1);
    std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    for (auto allowed : config.extensions) {
        std::transform(allowed.begin(), allowed.end(), allowed.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (allowed == extension) return true;
    }
    return false;
}
std::int64_t score(const ScannerConfig& config, const std::string& path, const struct stat& st, std::string* reasons) {
    std::int64_t value = 0;
    std::vector<std::string> why;
    if ((st.st_mode & S_IXUSR) != 0) { value += 90; why.emplace_back("EXECUTABLE"); }
    if (candidate_extension(config, path)) { value += 40; why.emplace_back("SUSPICIOUS_EXTENSION"); }
    if (path.rfind("/tmp/", 0) == 0 || path.rfind("/var/tmp/", 0) == 0 || path.rfind("/dev/shm/", 0) == 0) {
        value += 90; why.emplace_back("TMP_EXECUTABLE");
    }
    if (path.rfind("/var/www/", 0) == 0 || path.rfind("/srv/www/", 0) == 0 || path.rfind("/home/", 0) == 0) {
        value += 80; why.emplace_back("WEB_OR_USER_ROOT");
    }
    if (!path.empty() && path.find_last_of('/') != std::string::npos &&
        path.substr(path.find_last_of('/') + 1).find('.') == std::string::npos) {
        value += 45; why.emplace_back("EXTENSIONLESS_CONTENT");
    }
    if (path.rfind("/etc/", 0) == 0 || path.find("/.ssh/authorized_keys") != std::string::npos) {
        value += 100; why.emplace_back("PERSISTENCE_PATH");
    }
    if (reasons) {
        *reasons = why.empty() ? "DEFAULT" : "";
        for (const auto& item : why) *reasons += (*reasons == "" ? "" : ",") + item;
    }
    return value;
}
bool walk_directory(int directory_fd, const std::string& display_path, unsigned depth, const ScannerConfig& config,
                    dev_t root_dev, std::chrono::steady_clock::time_point deadline,
                    std::vector<InventoryRecord>* records, Counters* counters) {
    if (depth > config.max_depth || records->size() >= config.max_files) return true;
    if (std::chrono::steady_clock::now() >= deadline) {
        if (counters) {
            counters->partial = true;
            if (counters->partial_reason.empty()) counters->partial_reason = "inventory_stage_timeout";
        }
        return false;
    }
    int scan_fd = ::dup(directory_fd);
    if (scan_fd < 0) { if (errno == EACCES && counters) ++counters->permission_denied; return false; }
    DIR* directory = ::fdopendir(scan_fd);
    if (!directory) { ::close(scan_fd); return false; }
    errno = 0;
    while (dirent* entry = ::readdir(directory)) {
        if (std::chrono::steady_clock::now() >= deadline) {
            if (counters) {
                counters->partial = true;
                if (counters->partial_reason.empty()) counters->partial_reason = "inventory_stage_timeout";
            }
            break;
        }
        if (entry->d_name[0] == '.' && (entry->d_name[1] == '\0' || (entry->d_name[1] == '.' && entry->d_name[2] == '\0'))) continue;
        if (excluded(config, entry->d_name)) continue;
        if (counters) ++counters->files_traversed;
        struct stat st{};
        if (::fstatat(directory_fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
            if (counters) { ++counters->stat_calls; if (errno == EACCES) ++counters->permission_denied; else if (errno == ENOENT) ++counters->disappeared; }
            continue;
        }
        if (counters) ++counters->stat_calls;
        std::string path = display_path == "/" ? "/" + std::string(entry->d_name) : display_path + "/" + entry->d_name;
        if (path.size() > MAX_DISPLAY_PATH) { if (counters) ++counters->unrepresentable; continue; }
        if (S_ISLNK(st.st_mode)) { if (counters) ++counters->symlink_skipped; continue; }
        if (S_ISDIR(st.st_mode)) {
            if (!config.xdev || st.st_dev == root_dev) {
                int child = ::openat(directory_fd, entry->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
                if (child >= 0) { walk_directory(child, path, depth + 1, config, root_dev, deadline, records, counters); ::close(child); }
                else if (counters && errno == EACCES) ++counters->permission_denied;
            }
            continue;
        }
        if (!S_ISREG(st.st_mode) || (((st.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) && !candidate_extension(config, path))) continue;
        if (unsafe_tsv(path)) { if (counters) ++counters->unrepresentable; continue; }
        InventoryRecord record;
        record.path = path;
        record.dev = static_cast<std::uint64_t>(st.st_dev);
        record.inode = static_cast<std::uint64_t>(st.st_ino);
        record.size = static_cast<std::uint64_t>(st.st_size);
        record.mtime = static_cast<std::int64_t>(st.st_mtime);
        record.ctime = static_cast<std::int64_t>(st.st_ctime);
        record.priority_score = score(config, path, st, &record.priority_reasons);
        records->push_back(std::move(record));
        if (records->size() >= config.max_files) break;
    }
    if (errno != 0 && counters) counters->partial = true;
    ::closedir(directory);
    return true;
}
}

bool collect_inventory(const ScannerConfig& config, std::vector<InventoryRecord>* records, Counters* counters) {
    if (!records || !counters) return false;
    records->clear();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(config.timeout_seconds);
    for (const auto& root : config.roots) {
        if (std::chrono::steady_clock::now() >= deadline) {
            counters->partial = true;
            if (counters->partial_reason.empty()) counters->partial_reason = "inventory_stage_timeout";
            break;
        }
        if (root.size() > MAX_DISPLAY_PATH) { ++counters->unrepresentable; continue; }
        struct stat st{};
        if (::lstat(root.c_str(), &st) != 0) { ++counters->disappeared; continue; }
        if (S_ISLNK(st.st_mode)) { ++counters->symlink_skipped; continue; }
        if (S_ISREG(st.st_mode)) {
            if (unsafe_tsv(root)) { ++counters->unrepresentable; continue; }
            InventoryRecord record;
            record.path = root;
            record.dev = st.st_dev; record.inode = st.st_ino; record.size = st.st_size;
            record.mtime = st.st_mtime; record.ctime = st.st_ctime;
            record.priority_score = score(config, root, st, &record.priority_reasons);
            records->push_back(std::move(record));
            ++counters->files_traversed; ++counters->stat_calls;
            continue;
        }
        int fd = ::open(root.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) { if (errno == EACCES) ++counters->permission_denied; continue; }
        walk_directory(fd, root == "/" ? "/" : root, 0, config, st.st_dev, deadline, records, counters);
        ::close(fd);
        if (records->size() >= config.max_files) { counters->partial = true; counters->partial_reason = "max_files"; break; }
    }
    std::sort(records->begin(), records->end(), [](const InventoryRecord& a, const InventoryRecord& b) {
        if (a.priority_score != b.priority_score) return a.priority_score > b.priority_score;
        if (a.mtime != b.mtime) return a.mtime > b.mtime;
        if (a.size != b.size) return a.size < b.size;
        return a.path < b.path;
    });
    return true;
}

bool write_inventory(const std::string& path, const std::vector<InventoryRecord>& records, const Counters& counters) {
    std::string temp = path + ".tmp";
    std::ofstream output(temp, std::ios::binary | std::ios::trunc);
    if (!output) return false;
    output << "priority\tpriority_score\tpriority_reasons\tsize_bytes\tpath\tdev\tinode\tmtime\tctime\tstatus\tmd5\tsha256\terror\n";
    for (const auto& record : records) {
        output << (record.priority_score > 0 ? "SCORED" : "NORMAL") << '\t' << record.priority_score << '\t'
               << record.priority_reasons << '\t' << record.size << '\t' << record.path << '\t' << record.dev << '\t'
               << record.inode << '\t' << record.mtime << '\t' << record.ctime << '\t' << record.status << '\t'
               << record.md5 << '\t' << record.sha256 << '\t' << record.error << '\n';
    }
    output.flush();
    if (!output) return false;
    output.close();
    return ::rename(temp.c_str(), path.c_str()) == 0;
}
}
