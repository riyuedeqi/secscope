#include "filesystem_facts.hpp"

#include <chrono>
#include <cerrno>
#include <ctime>
#include <cstdint>
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <pwd.h>
#include <set>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unordered_map>
#include <utility>
#include <vector>
#include <unistd.h>

namespace secscope {
namespace {

using Json = nlohmann::json;
using Clock = std::chrono::steady_clock;

constexpr std::size_t MAX_PATH_BYTES = 4096;
constexpr std::size_t MAX_FILES = 50000000;
constexpr std::size_t MAX_DIRS = 5000000;

struct Outputs {
    AtomicOutput suid;
    AtomicOutput weird_suid;
    AtomicOutput unowned;
    AtomicOutput large;
    AtomicOutput recent;
    AtomicOutput persistence;
    AtomicOutput coverage;

    explicit Outputs(const Arguments& args)
        : suid(argument(args, "--suid-output")),
          weird_suid(argument(args, "--weird-suid-output")),
          unowned(argument(args, "--unowned-output")),
          large(argument(args, "--large-output")),
          recent(argument(args, "--recent-output")),
          persistence(argument(args, "--persistence-output")),
          coverage(argument(args, "--coverage-jsonl")) {}

    bool good() const {
        return suid.good() && weird_suid.good() && unowned.good() && large.good() &&
               recent.good() && persistence.good() && coverage.good();
    }

    bool commit() {
        return suid.commit() && weird_suid.commit() && unowned.commit() && large.commit() &&
               recent.commit() && persistence.commit() && coverage.commit();
    }
};

struct Facts {
    std::uint64_t visited = 0;
    std::uint64_t files = 0;
    std::uint64_t directories = 0;
    std::uint64_t stat_calls = 0;
    std::uint64_t symlink_skipped = 0;
    std::uint64_t permission_denied = 0;
    std::uint64_t disappeared = 0;
    std::uint64_t unrepresentable = 0;
    std::uint64_t suid = 0;
    std::uint64_t weird_suid = 0;
    std::uint64_t unowned = 0;
    std::uint64_t large = 0;
    std::uint64_t recent = 0;
    std::uint64_t persistence = 0;
    bool partial = false;
    std::string reason;
};

void mark_partial(Facts* facts, const char* reason) {
    if (!facts) return;
    facts->partial = true;
    if (facts->reason.empty() && reason) facts->reason = reason;
}

bool unsafe_path(const std::string& path) {
    return path.empty() || path.size() > MAX_PATH_BYTES || path.find('\t') != std::string::npos ||
           path.find('\r') != std::string::npos || path.find('\n') != std::string::npos;
}

bool under(const std::string& path, const char* prefix) {
    const std::string value(prefix);
    return path == value || (path.size() > value.size() && path.compare(0, value.size(), value) == 0 && path[value.size()] == '/');
}

bool excluded_root_tree(const std::string& path, const std::string& root) {
    if (root != "/") return false;
    return under(path, "/proc") || under(path, "/sys") || under(path, "/snap");
}

bool lookup_user(uid_t uid, std::unordered_map<unsigned long, bool>* cache) {
    const auto key = static_cast<unsigned long>(uid);
    const auto found = cache->find(key);
    if (found != cache->end()) return found->second;
    struct passwd entry{};
    struct passwd* result = nullptr;
    char buffer[65536]{};
    const bool present = ::getpwuid_r(uid, &entry, buffer, sizeof(buffer), &result) == 0 && result != nullptr;
    (*cache)[key] = present;
    return present;
}

bool lookup_group(gid_t gid, std::unordered_map<unsigned long, bool>* cache) {
    const auto key = static_cast<unsigned long>(gid);
    const auto found = cache->find(key);
    if (found != cache->end()) return found->second;
    struct group entry{};
    struct group* result = nullptr;
    char buffer[65536]{};
    const bool present = ::getgrgid_r(gid, &entry, buffer, sizeof(buffer), &result) == 0 && result != nullptr;
    (*cache)[key] = present;
    return present;
}

bool persistence_path(const std::string& path) {
    static const std::set<std::string> exact{
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers",
        "/etc/crontab", "/etc/ld.so.preload", "/etc/rc.local", "/etc/profile"};
    static const char* prefixes[] = {
        "/etc/sudoers.d/", "/etc/cron.d/", "/var/spool/cron/", "/etc/pam.d/",
        "/etc/systemd/system/", "/etc/profile.d/"};
    static const char* suffixes[] = {"/.ssh/authorized_keys", "/.bashrc", "/.bash_profile", "/.profile", "/.zshrc"};
    if (exact.count(path) != 0) return true;
    for (const char* prefix : prefixes) if (path.rfind(prefix, 0) == 0) return true;
    for (const char* suffix : suffixes) {
        const std::string value(suffix);
        if (path.size() >= value.size() && path.compare(path.size() - value.size(), value.size(), value) == 0) return true;
    }
    return false;
}

std::string child_path(const std::string& directory, const char* name) {
    return directory == "/" ? "/" + std::string(name) : directory + "/" + name;
}

bool visit_directory(const std::string& root, const std::string& directory, unsigned depth, unsigned max_depth,
                     dev_t root_dev, Clock::time_point deadline, std::uint64_t max_files, std::uint64_t recent_cutoff,
                     Outputs* outputs, Facts* facts, std::unordered_map<unsigned long, bool>* users,
                     std::unordered_map<unsigned long, bool>* groups) {
    if (!outputs || !facts || !users || !groups) return false;
    if (Clock::now() >= deadline) { mark_partial(facts, "timeout"); return false; }
    DIR* handle = ::opendir(directory.c_str());
    if (!handle) {
        if (errno == EACCES || errno == EPERM) ++facts->permission_denied;
        else ++facts->disappeared;
        mark_partial(facts, errno == EACCES || errno == EPERM ? "permission_denied" : "directory_open_failed");
        return false;
    }
    ++facts->directories;
    errno = 0;
    while (dirent* entry = ::readdir(handle)) {
        if (Clock::now() >= deadline) { mark_partial(facts, "timeout"); break; }
        if (facts->files >= max_files) { mark_partial(facts, "max_files"); break; }
        if ((entry->d_name[0] == '.' && entry->d_name[1] == '\0') ||
            (entry->d_name[0] == '.' && entry->d_name[1] == '.' && entry->d_name[2] == '\0')) continue;
        ++facts->visited;
        const std::string path = child_path(directory, entry->d_name);
        if (excluded_root_tree(path, root)) continue;
        struct stat status{};
        ++facts->stat_calls;
        if (::lstat(path.c_str(), &status) != 0) {
            if (errno == EACCES || errno == EPERM) ++facts->permission_denied;
            else if (errno == ENOENT) ++facts->disappeared;
            mark_partial(facts, errno == EACCES || errno == EPERM ? "permission_denied" : "file_disappeared");
            continue;
        }
        if (S_ISLNK(status.st_mode)) { ++facts->symlink_skipped; continue; }
        if (S_ISDIR(status.st_mode)) {
            if (status.st_dev != root_dev) continue;
            if (depth >= max_depth) { mark_partial(facts, "max_depth"); continue; }
            if (facts->directories >= MAX_DIRS) { mark_partial(facts, "directory_budget"); break; }
            visit_directory(root, path, depth + 1, max_depth, root_dev, deadline, max_files, recent_cutoff,
                            outputs, facts, users, groups);
            continue;
        }
        if (!S_ISREG(status.st_mode)) continue;
        ++facts->files;
        if (unsafe_path(path)) { ++facts->unrepresentable; mark_partial(facts, "unrepresentable_path"); continue; }
        const bool suid = (status.st_mode & (S_ISUID | S_ISGID)) != 0;
        const bool weird = suid && (under(path, "/tmp") || under(path, "/dev/shm") || under(path, "/var/tmp") || under(path, "/home"));
        const bool unowned = !lookup_user(status.st_uid, users) || !lookup_group(status.st_gid, groups);
        const bool large = static_cast<std::uint64_t>(status.st_size < 0 ? 0 : status.st_size) > 200ULL * 1024ULL * 1024ULL;
        const bool recent = static_cast<std::uint64_t>(status.st_mtime > 0 ? status.st_mtime : 0) >= recent_cutoff;
        const bool persistence = persistence_path(path);
        if (suid) { outputs->suid.stream() << path << '\n'; ++facts->suid; }
        if (weird) { outputs->weird_suid.stream() << path << '\n'; ++facts->weird_suid; }
        if (unowned) { outputs->unowned.stream() << path << '\n'; ++facts->unowned; }
        if (large) { outputs->large.stream() << path << '\n'; ++facts->large; }
        if (recent) { outputs->recent.stream() << path << '\t' << status.st_mtime << '\n'; ++facts->recent; }
        if (persistence) { outputs->persistence.stream() << path << '\n'; ++facts->persistence; }
        if (!outputs->suid.stream() || !outputs->weird_suid.stream() || !outputs->unowned.stream() ||
            !outputs->large.stream() || !outputs->recent.stream() || !outputs->persistence.stream()) {
            mark_partial(facts, "output_write_failed");
            break;
        }
    }
    if (errno != 0) mark_partial(facts, "directory_read_failed");
    ::closedir(handle);
    return !facts->partial;
}

} // namespace

int run_filesystem_facts(const Arguments& args) {
    std::string error;
    if (!required_arguments(args, {"--root", "--suid-output", "--weird-suid-output", "--unowned-output", "--large-output",
                                   "--recent-output", "--persistence-output", "--coverage-jsonl"}, &error)) {
        std::cerr << error << '\n';
        return 2;
    }
    const std::string root = absolute_lexical_path(argument(args, "--root"));
    struct stat root_status{};
    if (::lstat(root.c_str(), &root_status) != 0 || !S_ISDIR(root_status.st_mode) || S_ISLNK(root_status.st_mode)) {
        std::cerr << "root must be a non-symlink directory\n";
        return 2;
    }
    const auto timeout = std::chrono::seconds(uint_argument(args, "--timeout-seconds", 900, 1, 86400));
    const unsigned max_depth = static_cast<unsigned>(uint_argument(args, "--max-depth", 64, 0, 64));
    const std::uint64_t max_files = uint_argument(args, "--max-files", MAX_FILES, 1, MAX_FILES);
    const std::uint64_t recent_seconds = uint_argument(args, "--recent-seconds", 7ULL * 86400ULL, 0, 10ULL * 365ULL * 86400ULL);
    const auto now = static_cast<std::uint64_t>(std::time(nullptr));
    const std::uint64_t recent_cutoff = now > recent_seconds ? now - recent_seconds : 0;
    Outputs outputs(args);
    if (!outputs.good()) { std::cerr << "cannot create filesystem facts output\n"; return 2; }
    Facts facts;
    std::unordered_map<unsigned long, bool> users;
    std::unordered_map<unsigned long, bool> groups;
    visit_directory(root, root, 0, max_depth, root_status.st_dev, Clock::now() + timeout, max_files, recent_cutoff,
                    &outputs, &facts, &users, &groups);
    outputs.coverage.stream() << Json{{"record_type", "summary"}, {"root", root}, {"files", facts.files},
        {"directories", facts.directories}, {"visited", facts.visited}, {"stat_calls", facts.stat_calls},
        {"suid", facts.suid}, {"weird_suid", facts.weird_suid}, {"unowned", facts.unowned}, {"large", facts.large},
        {"recent", facts.recent}, {"persistence", facts.persistence}, {"symlink_skipped", facts.symlink_skipped},
        {"permission_denied", facts.permission_denied}, {"disappeared", facts.disappeared},
        {"unrepresentable", facts.unrepresentable}, {"partial", facts.partial}, {"reason", facts.reason}}.dump() << '\n';
    if (!outputs.coverage.stream() || !outputs.commit()) return 3;
    std::cout << Json{{"status", facts.partial ? "PARTIAL" : "SUCCESS"}, {"root", root}, {"files", facts.files},
                      {"directories", facts.directories}, {"suid", facts.suid}, {"unowned", facts.unowned},
                      {"large", facts.large}, {"recent", facts.recent}, {"persistence", facts.persistence},
                      {"partial", facts.partial}, {"reason", facts.reason}}.dump() << '\n';
    return 0;
}

} // namespace secscope
