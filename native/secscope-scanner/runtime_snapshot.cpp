#include "runtime_snapshot.hpp"

#include "native_io.hpp"
#include "socket_snapshot.hpp"
#include "types.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <glob.h>
#include <iostream>
#include <map>
#include <limits.h>
#include <memory>
#include <nlohmann/json.hpp>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>
#include <unistd.h>

namespace secscope {
namespace {

using Json = nlohmann::json;
constexpr std::size_t MAX_FIELD_BYTES = 8192;
constexpr std::size_t MAX_FDS_PER_PROCESS = 4096;
constexpr std::size_t MAX_MAPS_PER_PROCESS = 4096;
constexpr std::size_t MAX_PACKAGE_ENTRIES = 2000000;

struct MapInfo {
    std::string address;
    std::string permissions;
    std::string path;
    std::string rss_kb;
    std::string vmflags;
    std::string map_files_target;
    bool suspicious = false;
};

struct ProcessInfo {
    std::int64_t pid = 0;
    std::int64_t ppid = 0;
    std::uint64_t start_ticks = 0;
    std::string comm;
    std::string uid;
    std::string euid;
    std::string loginuid;
    std::string tty;
    std::string exe;
    std::string cap_eff;
    std::string namespaces;
    std::string cgroup;
    std::string container_runtime = "none";
    std::string container_id;
    std::string pod_uid;
    std::string k8s_namespace;
    std::string host_namespace_suspicious = "no";
    std::string ancestors;
    std::string argv;
    std::string package = "unowned";
    std::string package_verify = "NOT_CHECKED";
    std::vector<std::pair<std::string, std::string>> fds;
    std::vector<MapInfo> maps;
    bool fd_truncated = false;
    bool maps_truncated = false;
};

struct SnapshotCounters {
    std::size_t processes = 0;
    std::size_t process_skipped = 0;
    std::size_t transient_processes = 0;
    std::size_t fd_count = 0;
    std::size_t maps = 0;
    std::size_t memory_records = 0;
    std::size_t namespace_gaps = 0;
    std::size_t fd_gaps = 0;
    std::size_t maps_gaps = 0;
    bool partial = false;
    std::string partial_reason;
};

struct ProcessResult {
    ProcessInfo process;
    SnapshotCounters counters;
    bool valid = false;
};

void mark_partial(SnapshotCounters* counters, const char* reason) {
    if (!counters) return;
    counters->partial = true;
    if (counters->partial_reason.empty() && reason) counters->partial_reason = reason;
}

void merge_counters(SnapshotCounters* destination, const SnapshotCounters& source) {
    if (!destination) return;
    destination->processes += source.processes;
    destination->process_skipped += source.process_skipped;
    destination->transient_processes += source.transient_processes;
    destination->fd_count += source.fd_count;
    destination->maps += source.maps;
    destination->memory_records += source.memory_records;
    destination->namespace_gaps += source.namespace_gaps;
    destination->fd_gaps += source.fd_gaps;
    destination->maps_gaps += source.maps_gaps;
    if (source.partial) mark_partial(destination, source.partial_reason.c_str());
}

std::string bounded_read(const std::string& path, std::size_t limit) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    std::string value;
    value.resize(limit);
    input.read(value.data(), static_cast<std::streamsize>(value.size()));
    value.resize(static_cast<std::size_t>(input.gcount()));
    return value;
}

std::string bounded_field(std::string value) {
    if (value.size() > MAX_FIELD_BYTES) value.resize(MAX_FIELD_BYTES);
    for (char& item : value) {
        if (item == '\0' || item == '\t' || item == '\r' || item == '\n') item = ' ';
    }
    return value;
}

std::string read_link(const std::string& path) {
    char buffer[PATH_MAX + 1]{};
    const ssize_t length = ::readlink(path.c_str(), buffer, sizeof(buffer) - 1);
    return length <= 0 ? std::string{} : std::string(buffer, static_cast<std::size_t>(length));
}

std::string status_field(const std::string& status, const std::string& key, std::size_t token = 0) {
    std::istringstream input(status);
    std::string line;
    while (std::getline(input, line)) {
        if (line.rfind(key, 0) != 0) continue;
        std::istringstream fields(line.substr(key.size()));
        std::string value;
        for (std::size_t index = 0; index <= token; ++index) {
            if (!(fields >> value)) return {};
        }
        return value;
    }
    return {};
}

std::uint64_t stat_start_ticks(const std::string& stat) {
    const auto close = stat.rfind(')');
    if (close == std::string::npos || close + 2 >= stat.size()) return 0;
    std::istringstream fields(stat.substr(close + 2));
    std::string value;
    // The first token after the comm is field 3 (state); field 22 is token 20.
    for (int index = 0; index < 20; ++index) {
        if (!(fields >> value)) return 0;
    }
    char* end = nullptr;
    const auto result = std::strtoull(value.c_str(), &end, 10);
    return end && *end == '\0' ? result : 0;
}

std::int64_t stat_ppid(const std::string& stat) {
    const auto close = stat.rfind(')');
    if (close == std::string::npos || close + 2 >= stat.size()) return 0;
    std::istringstream fields(stat.substr(close + 2));
    std::string state;
    std::string ppid;
    if (!(fields >> state >> ppid)) return 0;
    char* end = nullptr;
    const auto result = std::strtoll(ppid.c_str(), &end, 10);
    return end && *end == '\0' ? result : 0;
}

std::string normalize_cmdline(std::string value) {
    for (char& item : value) {
        if (item == '\0' || item == '\t' || item == '\r' || item == '\n') item = ' ';
    }
    while (!value.empty() && value.back() == ' ') value.pop_back();
    return bounded_field(std::move(value));
}

std::string namespace_value(const std::string& link) {
    const auto open = link.find('[');
    const auto close = link.find(']', open == std::string::npos ? 0 : open + 1);
    if (open == std::string::npos || close == std::string::npos) return bounded_field(link);
    return link.substr(open + 1, close - open - 1);
}

std::string namespace_summary(const std::string& base, std::size_t* gaps) {
    static const char* names[] = {"mnt", "pid", "net", "user", "uts", "ipc", "cgroup"};
    std::string result;
    for (const char* name : names) {
        const std::string value = read_link(base + "/ns/" + name);
        if (value.empty() && gaps) ++(*gaps);
        if (!result.empty()) result.push_back(',');
        result += name;
        result.push_back('=');
        result += namespace_value(value);
    }
    return result;
}

std::string container_runtime(const std::string& cgroup) {
    if (cgroup.find("libpod") != std::string::npos || cgroup.find("podman") != std::string::npos) return "podman";
    if (cgroup.find("cri-o") != std::string::npos || cgroup.find("crio") != std::string::npos) return "cri-o";
    if (cgroup.find("containerd") != std::string::npos || cgroup.find("cri-containerd") != std::string::npos) return "containerd";
    if (cgroup.find("docker") != std::string::npos) return "docker";
    if (cgroup.find("lxc") != std::string::npos) return "lxc";
    if (::access("/.dockerenv", F_OK) == 0) return "docker";
    if (::access("/run/.containerenv", F_OK) == 0) return "container";
    return "none";
}

std::string container_id(const std::string& cgroup) {
    static const std::regex full("[0-9a-fA-F]{64}");
    std::smatch match;
    if (std::regex_search(cgroup, match, full)) return match.str();
    static const std::regex pref("(?:docker-|cri-containerd-|crio-|libpod-)([0-9a-fA-F]{12,64})");
    if (std::regex_search(cgroup, match, pref) && match.size() > 1) return match[1].str();
    return {};
}

std::string pod_uid(const std::string& cgroup) {
    static const std::regex pattern("pod([0-9a-fA-F][0-9a-fA-F_-]{20,})");
    std::smatch match;
    if (!std::regex_search(cgroup, match, pattern) || match.size() < 2) return {};
    std::string value = match[1].str();
    std::replace(value.begin(), value.end(), '_', '-');
    return value;
}

std::string k8s_namespace(const std::string& base, const std::string& argv) {
    const std::string environment = bounded_read(base + "/environ", 128 * 1024);
    std::size_t start = 0;
    while (start <= environment.size()) {
        const auto end = environment.find('\0', start);
        const std::string item = environment.substr(start, end == std::string::npos ? end : end - start);
        for (const char* key : {"POD_NAMESPACE=", "KUBERNETES_NAMESPACE="}) {
            if (item.rfind(key, 0) == 0 && item.size() > std::char_traits<char>::length(key)) return bounded_field(item.substr(std::char_traits<char>::length(key)));
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    std::string value = bounded_read(base + "/root/var/run/secrets/kubernetes.io/serviceaccount/namespace", 253);
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r')) value.pop_back();
    if (!value.empty()) return bounded_field(std::move(value));
    static const std::regex flag("(?:^|[[:space:]])--namespace(?:=|[[:space:]]+)([^[:space:]]+)");
    std::smatch match;
    return std::regex_search(argv, match, flag) && match.size() > 1 ? bounded_field(match[1].str()) : std::string{};
}

std::string host_namespace_status(const std::string& base, const std::string& runtime) {
    if (runtime == "none") return "no";
    if (::access("/.dockerenv", F_OK) == 0 || ::access("/run/.containerenv", F_OK) == 0) return "unknown";
    std::string overlap;
    for (const char* name : {"mnt", "pid", "net", "user"}) {
        const std::string current = read_link(base + "/ns/" + name);
        const std::string init = read_link(std::string("/proc/1/ns/") + name);
        if (!current.empty() && current == init) {
            if (!overlap.empty()) overlap.push_back(',');
            overlap += name;
        }
    }
    return overlap.empty() ? "no" : "yes:" + overlap;
}

std::string ancestors(const ProcessInfo& start, const std::string& boot_id) {
    std::string result;
    std::int64_t current = start.ppid;
    for (int depth = 0; depth < 5 && current > 1; ++depth) {
        const std::string base = "/proc/" + std::to_string(current);
        const std::string status = bounded_read(base + "/status", 8192);
        if (status.empty()) break;
        const std::string comm = status_field(status, "Name:");
        const std::string exe = read_link(base + "/exe");
        if (!result.empty()) result += " <- ";
        result += std::to_string(current) + ":" + comm + ":" + (exe.empty() ? "unknown" : exe);
        const std::string stat = bounded_read(base + "/stat", 4096);
        current = stat_ppid(stat);
    }
    (void)boot_id;
    return bounded_field(std::move(result));
}

class PackageIndex {
public:
    PackageIndex() { load_dpkg(); if (!available_) load_rpm(); }

    std::string owner(const std::string& path) const {
        const auto found = owners_.find(path);
        return found == owners_.end() ? "unowned" : found->second;
    }

    bool available() const { return available_; }
    bool partial() const { return partial_; }

private:
    std::unordered_map<std::string, std::string> owners_;
    bool available_ = false;
    bool partial_ = false;

    void add(const std::string& package, const std::string& path) {
        if (owners_.size() >= MAX_PACKAGE_ENTRIES) { partial_ = true; return; }
        if (package.size() > MAX_FIELD_BYTES || path.size() > MAX_FIELD_BYTES) { partial_ = true; return; }
        if (path.empty() || path[0] != '/' || path.find_first_of("\t\r\n") != std::string::npos) return;
        owners_.emplace(path, package + ": " + path);
    }

    void load_dpkg() {
        glob_t matches{};
        if (::glob("/var/lib/dpkg/info/*.list", GLOB_NOSORT, nullptr, &matches) != 0) return;
        for (std::size_t index = 0; index < matches.gl_pathc; ++index) {
            const std::string list = matches.gl_pathv[index];
            const auto slash = list.rfind('/');
            const auto suffix = list.rfind(".list");
            if (slash == std::string::npos || suffix == std::string::npos || suffix <= slash + 1) continue;
            const std::string package = list.substr(slash + 1, suffix - slash - 1);
            std::ifstream input(list);
            if (!input) continue;
            available_ = true;
            std::string path;
            while (std::getline(input, path)) {
                if (path.size() > MAX_FIELD_BYTES) { partial_ = true; continue; }
                add(package, path);
                if (owners_.size() >= MAX_PACKAGE_ENTRIES) break;
            }
            if (owners_.size() >= MAX_PACKAGE_ENTRIES) break;
        }
        ::globfree(&matches);
    }

    void load_rpm() {
        int pipe_fds[2] = {-1, -1};
        if (::pipe(pipe_fds) != 0) return;
        const pid_t child = ::fork();
        if (child < 0) {
            ::close(pipe_fds[0]);
            ::close(pipe_fds[1]);
            return;
        }
        if (child == 0) {
            ::close(pipe_fds[0]);
            if (::dup2(pipe_fds[1], STDOUT_FILENO) < 0) _exit(126);
            ::close(pipe_fds[1]);
            const int dev_null = ::open("/dev/null", O_WRONLY | O_CLOEXEC);
            if (dev_null >= 0) {
                ::dup2(dev_null, STDERR_FILENO);
                ::close(dev_null);
            }
            ::execlp("rpm", "rpm", "-qa", "--qf", "%{NAME}\\t%{FILENAMES}\\n", static_cast<char*>(nullptr));
            _exit(127);
        }
        ::close(pipe_fds[1]);
        FILE* pipe = ::fdopen(pipe_fds[0], "r");
        if (!pipe) {
            ::close(pipe_fds[0]);
            int ignored = 0;
            while (::waitpid(child, &ignored, 0) < 0 && errno == EINTR) {}
            return;
        }
        char buffer[16384];
        while (std::fgets(buffer, sizeof(buffer), pipe)) {
            std::string line(buffer);
            while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
            const auto tab = line.find('\t');
            if (tab == std::string::npos) continue;
            const std::string package = line.substr(0, tab);
            std::string path = line.substr(tab + 1);
            const auto extra_tab = path.find('\t');
            if (extra_tab != std::string::npos) path.resize(extra_tab);
            add(package, path);
            available_ = true;
            if (owners_.size() >= MAX_PACKAGE_ENTRIES) break;
        }
        std::fclose(pipe);
        int status = 0;
        while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {}
        if (available_ && (!WIFEXITED(status) || WEXITSTATUS(status) != 0)) partial_ = true;
    }
};

bool parse_pid(const char* name, std::int64_t* pid) {
    if (!name || !pid || !*name) return false;
    char* end = nullptr;
    errno = 0;
    const long value = std::strtol(name, &end, 10);
    if (errno != 0 || !end || *end != '\0' || value <= 0) return false;
    *pid = value;
    return true;
}

std::vector<std::int64_t> proc_pids(std::size_t max, bool* partial) {
    std::vector<std::int64_t> result;
    DIR* proc = ::opendir("/proc");
    if (!proc) { if (partial) *partial = true; return result; }
    while (dirent* entry = ::readdir(proc)) {
        std::int64_t pid = 0;
        if (entry->d_type != DT_DIR || !parse_pid(entry->d_name, &pid)) continue;
        if (result.size() >= max) { if (partial) *partial = true; break; }
        result.push_back(pid);
    }
    ::closedir(proc);
    std::sort(result.begin(), result.end());
    return result;
}

void collect_fds(ProcessInfo* process, SnapshotCounters* counters) {
    if (!process || !counters) return;
    const std::string fd_dir = "/proc/" + std::to_string(process->pid) + "/fd";
    DIR* directory = ::opendir(fd_dir.c_str());
    if (!directory) { ++counters->fd_gaps; mark_partial(counters, "fd_visibility_gap"); return; }
    while (dirent* entry = ::readdir(directory)) {
        if (entry->d_name[0] == '.') continue;
        if (process->fds.size() >= MAX_FDS_PER_PROCESS) { process->fd_truncated = true; mark_partial(counters, "fd_budget"); break; }
        const std::string target = read_link(fd_dir + "/" + entry->d_name);
        if (target.empty()) continue;
        process->fds.emplace_back(entry->d_name, bounded_field(target));
        ++counters->fd_count;
    }
    ::closedir(directory);
}

bool map_header(const std::string& line, MapInfo* map) {
    if (!map) return false;
    std::istringstream fields(line);
    std::string offset;
    std::string device;
    std::string inode;
    if (!(fields >> map->address >> map->permissions >> offset >> device >> inode)) return false;
    std::getline(fields, map->path);
    while (!map->path.empty() && map->path.front() == ' ') map->path.erase(map->path.begin());
    map->path = bounded_field(std::move(map->path));
    return map->address.find('-') != std::string::npos && map->permissions.size() >= 4;
}

bool suspicious_map(const MapInfo& map) {
    return map.permissions.find('x') != std::string::npos &&
           (map.path.find("memfd:") != std::string::npos || map.path.find("(deleted)") != std::string::npos ||
            map.path.empty() || map.permissions.find('w') != std::string::npos ||
            map.path.rfind("/tmp/", 0) == 0 || map.path.rfind("/var/tmp/", 0) == 0 ||
            map.path.rfind("/dev/shm/", 0) == 0);
}

void collect_maps(ProcessInfo* process, SnapshotCounters* counters, std::size_t max_maps) {
    if (!process || !counters) return;
    std::ifstream input("/proc/" + std::to_string(process->pid) + "/smaps");
    if (!input) { ++counters->maps_gaps; mark_partial(counters, "maps_visibility_gap"); return; }
    MapInfo current;
    bool have_current = false;
    auto flush = [&]() {
        if (!have_current || current.permissions.find('x') == std::string::npos) { current = MapInfo{}; have_current = false; return; }
        if (process->maps.size() >= MAX_MAPS_PER_PROCESS || counters->maps >= max_maps) {
            process->maps_truncated = true;
            mark_partial(counters, "maps_budget");
            current = MapInfo{};
            have_current = false;
            return;
        }
        current.suspicious = suspicious_map(current);
        if (current.suspicious) {
            current.map_files_target = read_link("/proc/" + std::to_string(process->pid) + "/map_files/" + current.address);
            ++counters->memory_records;
        }
        process->maps.push_back(current);
        ++counters->maps;
        current = MapInfo{};
        have_current = false;
    };
    std::string line;
    while (std::getline(input, line)) {
        MapInfo next;
        if (map_header(line, &next)) {
            flush();
            if (process->maps_truncated) break;
            current = std::move(next);
            have_current = true;
        } else if (have_current && line.rfind("Rss:", 0) == 0) {
            current.rss_kb = status_field(line, "Rss:");
        } else if (have_current && line.rfind("VmFlags:", 0) == 0) {
            current.vmflags = bounded_field(line.substr(8));
            while (!current.vmflags.empty() && current.vmflags.front() == ' ') current.vmflags.erase(current.vmflags.begin());
        }
    }
    flush();
}

bool collect_process_info(std::int64_t pid, const std::string& boot_id, const PackageIndex& packages,
                          ProcessInfo* process, SnapshotCounters* counters, std::size_t max_maps) {
    if (!process || !counters) return false;
    process->pid = pid;
    const std::string base = "/proc/" + std::to_string(pid);
    const std::string status = bounded_read(base + "/status", 16384);
    const std::string stat = bounded_read(base + "/stat", 8192);
    if (status.empty() || stat.empty()) return false;
    process->comm = bounded_field(status_field(status, "Name:"));
    process->ppid = stat_ppid(stat);
    process->start_ticks = stat_start_ticks(stat);
    if (process->start_ticks == 0) return false;
    process->uid = bounded_field(status_field(status, "Uid:", 0));
    process->euid = bounded_field(status_field(status, "Uid:", 1));
    process->cap_eff = bounded_field(status_field(status, "CapEff:"));
    process->loginuid = bounded_field(bounded_read(base + "/loginuid", 128));
    if (process->loginuid.empty()) process->loginuid = "unknown";
    process->tty = read_link(base + "/fd/0");
    if (process->tty.empty()) process->tty = "none";
    process->exe = bounded_field(read_link(base + "/exe"));
    process->argv = normalize_cmdline(bounded_read(base + "/cmdline", MAX_FIELD_BYTES));
    process->cgroup = bounded_field(bounded_read(base + "/cgroup", MAX_FIELD_BYTES));
    process->container_runtime = container_runtime(process->cgroup);
    process->container_id = container_id(process->cgroup);
    process->pod_uid = pod_uid(process->cgroup);
    process->k8s_namespace = k8s_namespace(base, process->argv);
    process->host_namespace_suspicious = host_namespace_status(base, process->container_runtime);
    process->namespaces = namespace_summary(base, &counters->namespace_gaps);
    process->package = packages.owner(process->exe);
    process->ancestors = ancestors(*process, boot_id);
    collect_fds(process, counters);
    collect_maps(process, counters, max_maps);
    return true;
}

std::string socket_state(const std::string& value) {
    static const std::map<std::string, std::string> states{
        {"01", "ESTAB"}, {"02", "SYN-SENT"}, {"03", "SYN-RECV"}, {"04", "FIN-WAIT-1"},
        {"05", "FIN-WAIT-2"}, {"06", "TIME-WAIT"}, {"07", "CLOSE"}, {"08", "CLOSE-WAIT"},
        {"09", "LAST-ACK"}, {"0A", "LISTEN"}, {"0B", "CLOSING"}, {"0C", "NEW-SYN-RECV"}
    };
    const auto found = states.find(value);
    return found == states.end() ? value : found->second;
}

std::string socket_line(const SocketRecord& socket) {
    std::string comm = "unknown";
    if (socket.pid > 0) {
        comm = bounded_read("/proc/" + std::to_string(socket.pid) + "/comm", 256);
        while (!comm.empty() && (comm.back() == '\n' || comm.back() == '\r')) comm.pop_back();
        if (comm.empty()) comm = "unknown";
    }
    std::ostringstream output;
    output << socket.protocol << ' ' << socket_state(socket.state)
           << " 0 0 " << socket.local_address << ' ' << socket.remote_address;
    if (socket.pid > 0) output << " users:((\"" << clean_cell(comm) << "\",pid=" << socket.pid << ",fd=0))";
    return output.str();
}

Json map_json(const MapInfo& map) {
    return Json{{"address", map.address}, {"permissions", map.permissions}, {"path", map.path},
                {"rss_kb", map.rss_kb}, {"vmflags", map.vmflags}, {"map_files_target", map.map_files_target},
                {"suspicious", map.suspicious}};
}

Json process_json(const ProcessInfo& process) {
    Json value{{"pid", process.pid}, {"ppid", process.ppid}, {"start_ticks", process.start_ticks},
               {"comm", process.comm}, {"uid", process.uid}, {"euid", process.euid},
               {"loginuid", process.loginuid}, {"tty", process.tty}, {"exe", process.exe},
               {"package", process.package}, {"cap_eff", process.cap_eff}, {"namespaces", process.namespaces},
               {"container_runtime", process.container_runtime}, {"container_id", process.container_id},
               {"pod_uid", process.pod_uid}, {"k8s_namespace", process.k8s_namespace},
               {"cgroup", process.cgroup}, {"host_namespace_suspicious", process.host_namespace_suspicious},
               {"ancestors_5", process.ancestors}, {"argv", process.argv},
               {"fd_truncated", process.fd_truncated}, {"maps_truncated", process.maps_truncated}};
    value["fds"] = Json::array();
    for (const auto& fd : process.fds) value["fds"].push_back(Json{{"fd", fd.first}, {"target", fd.second}});
    value["maps"] = Json::array();
    for (const auto& map : process.maps) value["maps"].push_back(map_json(map));
    return value;
}

void write_process_tsv(std::ostream& output, const ProcessInfo& process, const std::string& boot_id) {
    const std::string instance = "process:" + boot_id + ":" + std::to_string(process.pid) + ":" + std::to_string(process.start_ticks) + ":" + process.exe;
    output << clean_cell(instance) << '\t' << clean_cell(boot_id) << '\t' << process.pid << '\t' << process.start_ticks << '\t'
           << process.ppid << '\t' << clean_cell(process.comm) << '\t' << clean_cell(process.uid) << '\t' << clean_cell(process.euid) << '\t'
           << clean_cell(process.loginuid) << '\t' << clean_cell(process.tty) << '\t' << clean_cell(process.exe) << '\t'
           << clean_cell(process.package) << '\t' << process.package_verify << '\t' << clean_cell(process.cap_eff) << '\t'
           << clean_cell(process.namespaces) << '\t' << clean_cell(process.container_id) << '\t' << clean_cell(process.ancestors) << '\t'
           << clean_cell(process.argv) << '\t' << clean_cell(process.container_runtime) << '\t' << clean_cell(process.pod_uid) << '\t'
           << clean_cell(process.k8s_namespace) << '\t' << clean_cell(process.cgroup) << '\t' << clean_cell(process.namespaces) << '\t'
           << clean_cell(process.host_namespace_suspicious) << '\n';
}

void write_container_tsv(std::ostream& output, const ProcessInfo& process, const std::string& boot_id) {
    if (process.container_runtime == "none" && process.container_id.empty() && process.pod_uid.empty()) return;
    const std::string instance = "process:" + boot_id + ":" + std::to_string(process.pid) + ":" + std::to_string(process.start_ticks) + ":" + process.exe;
    output << process.pid << '\t' << clean_cell(instance) << '\t' << clean_cell(process.container_runtime) << '\t'
           << clean_cell(process.container_id) << '\t' << clean_cell(process.pod_uid) << '\t' << clean_cell(process.k8s_namespace) << '\t'
           << clean_cell(process.cgroup) << '\t' << clean_cell(process.namespaces) << '\t' << clean_cell(process.host_namespace_suspicious) << '\t'
           << clean_cell(process.exe) << '\t' << clean_cell(process.argv) << '\n';
}

void write_memory_tsv(std::ostream& output, const ProcessInfo& process, const std::string& boot_id,
                      const std::string& network) {
    const std::string instance = "process:" + boot_id + ":" + std::to_string(process.pid) + ":" + std::to_string(process.start_ticks) + ":" + process.exe;
    std::string counter = "none";
    if (process.comm == "java" || process.comm == "node" || process.comm == "dotnet" || process.comm == "postgres" ||
        process.comm == "mysqld" || process.comm == "mongod" || process.comm == "redis-server" || process.comm.rfind("php-fpm", 0) == 0) {
        counter = "known_jit_or_runtime";
    }
    for (const auto& map : process.maps) {
        if (!map.suspicious) continue;
        const std::string kind = map.path.find("memfd:") != std::string::npos ? "MEMFD" :
            (map.path.find("(deleted)") != std::string::npos ? "DELETED" :
             (map.path.empty() ? "ANONYMOUS_EXECUTABLE" : "EXECUTABLE_MAPPING"));
        output << clean_cell(instance) << '\t' << process.pid << '\t' << clean_cell(process.comm) << '\t' << clean_cell(process.exe) << '\t'
               << clean_cell(map.address) << '\t' << clean_cell(map.permissions) << '\t' << clean_cell(map.path) << '\t' << kind << '\t'
               << clean_cell(map.rss_kb) << '\t' << clean_cell(map.vmflags) << '\t' << clean_cell(map.map_files_target.empty() ? "UNAVAILABLE_OR_ANONYMOUS" : map.map_files_target)
               << '\t' << counter << '\t' << clean_cell(network) << '\n';
    }
}

std::string boot_id() {
    std::string value = bounded_read("/proc/sys/kernel/random/boot_id", 128);
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r')) value.pop_back();
    return value.empty() ? "unknown" : bounded_field(std::move(value));
}

bool ensure_parent(const std::string& path) {
    if (path.empty()) return true;
    std::error_code error;
    const auto parent = std::filesystem::path(path).parent_path();
    if (!parent.empty()) std::filesystem::create_directories(parent, error);
    return !error;
}

bool valid_phase(const std::string& phase) {
    return phase == "initial" || phase == "periodic" || phase == "final";
}

std::size_t runtime_worker_count(std::size_t process_count) {
    if (process_count == 0) return 0;
    const unsigned hardware = std::max(1u, std::thread::hardware_concurrency());
    std::size_t workers = std::min<std::size_t>(process_count, std::min<unsigned>(hardware, 8u));
    const char* requested = std::getenv("SECSCOPE_NATIVE_RUNTIME_WORKERS");
    if (requested && *requested) {
        char* end = nullptr;
        errno = 0;
        const unsigned long parsed = std::strtoul(requested, &end, 10);
        if (errno == 0 && end != requested && *end == '\0' && parsed > 0) {
            workers = std::min(workers, static_cast<std::size_t>(parsed));
        }
    }
    return std::max<std::size_t>(workers, 1);
}

int run_one_snapshot(const Arguments& args, AtomicOutput* raw, AtomicOutput* process_output,
                    AtomicOutput* container_output, AtomicOutput* memory_output, AtomicOutput* socket_text_output,
                    AtomicOutput* socket_tsv_output, std::size_t snapshot_index, const std::string& phase,
                    std::size_t max_processes, std::size_t max_sockets, std::size_t max_maps,
                    bool* partial_output) {
    if (!raw) return 2;
    (void)args;
    SnapshotCounters counters;
    bool pid_partial = false;
    const auto pids = proc_pids(max_processes, &pid_partial);
    counters.partial = pid_partial;
    if (pid_partial) counters.partial_reason = "process_budget";
    const std::string boot = boot_id();
    PackageIndex packages;
    if (packages.partial()) mark_partial(&counters, "package_index_budget");

    std::vector<SocketRecord> sockets;
    Counters socket_counters;
    if (!collect_socket_snapshot(&sockets, &socket_counters, max_sockets)) {
        mark_partial(&counters, "socket_snapshot_failed");
    }
    if (socket_counters.partial) mark_partial(&counters, socket_counters.partial_reason.empty() ? "socket_snapshot_partial" : socket_counters.partial_reason.c_str());
    std::map<std::int64_t, std::string> socket_lines;
    std::map<std::int64_t, std::size_t> socket_lines_count;
    if (snapshot_index == 0 && socket_tsv_output) socket_tsv_output->stream() << "protocol\tlocal\tremote\tstate\tinode\tpid\n";
    for (const auto& socket : sockets) {
        if (socket.pid > 0 && socket_lines_count[socket.pid] < 8) {
            const std::string line = socket_line(socket);
            socket_lines[socket.pid] += socket_lines[socket.pid].empty() ? line : "\n" + line;
            ++socket_lines_count[socket.pid];
        }
        if (socket_text_output) socket_text_output->stream() << socket_line(socket) << '\n';
        if (socket_tsv_output) socket_tsv_output->stream() << socket.protocol << '\t' << clean_cell(socket.local_address) << '\t'
            << clean_cell(socket.remote_address) << '\t' << clean_cell(socket_state(socket.state)) << '\t' << socket.inode << '\t' << socket.pid << '\n';
        raw->stream() << Json{{"record_type", "socket"}, {"snapshot_index", snapshot_index}, {"phase", phase},
                              {"protocol", socket.protocol}, {"local", socket.local_address}, {"remote", socket.remote_address},
                              {"state", socket_state(socket.state)}, {"inode", socket.inode}, {"pid", socket.pid}}.dump() << '\n';
    }

    raw->stream() << Json{{"record_type", "snapshot"}, {"snapshot_index", snapshot_index}, {"phase", phase},
                          {"timestamp_epoch", static_cast<std::int64_t>(std::time(nullptr))}, {"boot_id", boot},
                          {"process_limit", max_processes}, {"socket_limit", max_sockets}, {"map_limit", max_maps}}.dump() << '\n';
    if (snapshot_index == 0 && process_output) {
        process_output->stream() << "process_instance_id\tboot_id\tpid\tstarttime\tppid\tcomm\tuid\teuid\tloginuid\ttty\texe\tpackage\tpackage_verify\tcap_eff\tnamespaces\tcontainer_id\tancestors_5\targv\tcontainer_runtime\tpod_uid\tk8s_namespace\tcgroup_path\tnamespace_inode_summary\thost_namespace_suspicious\n";
    }
    if (snapshot_index == 0 && container_output) {
        container_output->stream() << "pid\tprocess_instance_id\tcontainer_runtime\tcontainer_id\tpod_uid\tk8s_namespace\tcgroup_path\tnamespace_inode_summary\thost_namespace_suspicious\texe\targv\n";
    }
    if (snapshot_index == 0 && memory_output) {
        memory_output->stream() << "process_instance_id\tpid\tcomm\texe\taddress\tpermissions\tpath\tmapping_kind\trss_kb\tvmflags\tmap_files_target\tcounter_evidence\tnetwork\n";
    }
    std::vector<ProcessResult> process_results(pids.size());
    std::atomic<std::size_t> next_pid{0};
    const std::size_t worker_count = runtime_worker_count(pids.size());
    std::vector<std::thread> workers;
    workers.reserve(worker_count);
    for (std::size_t worker = 0; worker < worker_count; ++worker) {
        workers.emplace_back([&]() {
            for (;;) {
                const std::size_t index = next_pid.fetch_add(1, std::memory_order_relaxed);
                if (index >= pids.size()) return;
                ProcessResult& result = process_results[index];
                result.valid = collect_process_info(pids[index], boot, packages, &result.process, &result.counters, max_maps);
                if (result.valid) ++result.counters.processes;
                else if (::access(("/proc/" + std::to_string(pids[index])).c_str(), F_OK) != 0) ++result.counters.transient_processes;
                else ++result.counters.process_skipped;
            }
        });
    }
    for (auto& worker : workers) worker.join();

    // Workers only fill independent slots. Merge and emit in sorted PID order so
    // concurrency cannot change evidence ordering or downstream hashes.
    for (const auto& result : process_results) {
        merge_counters(&counters, result.counters);
        if (!result.valid) continue;
        const ProcessInfo& process = result.process;
        if (process_output) write_process_tsv(process_output->stream(), process, boot);
        if (container_output) write_container_tsv(container_output->stream(), process, boot);
        const auto network = socket_lines.find(process.pid);
        if (memory_output) write_memory_tsv(memory_output->stream(), process, boot, network == socket_lines.end() ? "" : network->second);
        Json process_record = process_json(process);
        process_record["record_type"] = "process";
        process_record["snapshot_index"] = snapshot_index;
        process_record["phase"] = phase;
        process_record["process_instance_id"] = "process:" + boot + ":" + std::to_string(process.pid) + ":" + std::to_string(process.start_ticks) + ":" + process.exe;
        raw->stream() << process_record.dump() << '\n';
    }
    if (counters.process_skipped > 0) mark_partial(&counters, "process_visibility_gap");
    if (counters.namespace_gaps > 0) mark_partial(&counters, "namespace_visibility_gap");
    if (counters.fd_gaps > 0) mark_partial(&counters, "fd_visibility_gap");
    if (counters.maps_gaps > 0) mark_partial(&counters, "maps_visibility_gap");
    raw->stream() << Json{{"record_type", "summary"}, {"snapshot_index", snapshot_index}, {"phase", phase},
                          {"processes", counters.processes}, {"process_skipped", counters.process_skipped},
                          {"transient_processes", counters.transient_processes}, {"socket_transient_processes", socket_counters.disappeared},
                          {"fds", counters.fd_count},
                          {"maps", counters.maps}, {"memory_records", counters.memory_records}, {"namespace_gaps", counters.namespace_gaps},
                          {"fd_gaps", counters.fd_gaps}, {"maps_gaps", counters.maps_gaps}, {"partial", counters.partial},
                          {"reason", counters.partial_reason}}.dump() << '\n';
    if (!raw->stream() || (process_output && !process_output->stream()) || (container_output && !container_output->stream()) ||
        (memory_output && !memory_output->stream()) || (socket_text_output && !socket_text_output->stream()) ||
        (socket_tsv_output && !socket_tsv_output->stream())) return 2;
    if (partial_output) *partial_output = counters.partial;
    return 0;
}

}

int run_runtime_snapshot(const Arguments& args) {
    std::string error;
    if (!required_arguments(args, {"--output"}, &error)) { std::cerr << error << '\n'; return 2; }
    const std::string output_path = argument(args, "--output");
    const std::string phase = argument(args, "--phase", "initial");
    if (!valid_phase(phase) || output_path.size() > 4096) { std::cerr << "invalid runtime snapshot phase or output\n"; return 2; }
    const std::size_t snapshots = static_cast<std::size_t>(uint_argument(args, "--snapshots", 1, 1, 64));
    const std::size_t interval = static_cast<std::size_t>(uint_argument(args, "--interval-seconds", 0, 0, 86400));
    const std::size_t max_processes = static_cast<std::size_t>(uint_argument(args, "--max-processes", 32768, 1, 32768));
    const std::size_t max_sockets = static_cast<std::size_t>(uint_argument(args, "--max-sockets", 65536, 1, 262144));
    const std::size_t max_maps = static_cast<std::size_t>(uint_argument(args, "--max-maps", 65536, 1, 262144));
    const std::string process_path = argument(args, "--process-tsv");
    const std::string container_path = argument(args, "--container-tsv");
    const std::string memory_path = argument(args, "--memory-tsv");
    const std::string socket_text_path = argument(args, "--socket-text");
    const std::string socket_tsv_path = argument(args, "--socket-tsv");
    if (snapshots > 1 && (!process_path.empty() || !container_path.empty() || !memory_path.empty() || !socket_text_path.empty() || !socket_tsv_path.empty())) {
        std::cerr << "TSV outputs require --snapshots 1\n";
        return 2;
    }
    for (const auto& path : {output_path, process_path, container_path, memory_path, socket_text_path, socket_tsv_path}) {
        if (!path.empty() && !ensure_parent(path)) { std::cerr << "cannot create runtime output parent\n"; return 2; }
    }
    AtomicOutput raw(output_path);
    std::unique_ptr<AtomicOutput> process_output;
    std::unique_ptr<AtomicOutput> container_output;
    std::unique_ptr<AtomicOutput> memory_output;
    std::unique_ptr<AtomicOutput> socket_text_output;
    std::unique_ptr<AtomicOutput> socket_tsv_output;
    if (!raw.good()) return 2;
    if (!process_path.empty()) process_output = std::make_unique<AtomicOutput>(process_path);
    if (!container_path.empty()) container_output = std::make_unique<AtomicOutput>(container_path);
    if (!memory_path.empty()) memory_output = std::make_unique<AtomicOutput>(memory_path);
    if (!socket_text_path.empty()) socket_text_output = std::make_unique<AtomicOutput>(socket_text_path);
    if (!socket_tsv_path.empty()) socket_tsv_output = std::make_unique<AtomicOutput>(socket_tsv_path);
    if ((process_output && !process_output->good()) || (container_output && !container_output->good()) ||
        (memory_output && !memory_output->good()) || (socket_text_output && !socket_text_output->good()) ||
        (socket_tsv_output && !socket_tsv_output->good())) return 2;
    bool partial = false;
    for (std::size_t index = 0; index < snapshots; ++index) {
        bool snapshot_partial = false;
        if (run_one_snapshot(args, &raw, process_output.get(), container_output.get(), memory_output.get(),
                             socket_text_output.get(), socket_tsv_output.get(), index, phase,
                             max_processes, max_sockets, max_maps, &snapshot_partial) != 0) return 3;
        partial = partial || snapshot_partial;
        if (index + 1 < snapshots && interval > 0) std::this_thread::sleep_for(std::chrono::seconds(interval));
    }
    if (!raw.commit() || (process_output && !process_output->commit()) || (container_output && !container_output->commit()) ||
        (memory_output && !memory_output->commit()) || (socket_text_output && !socket_text_output->commit()) ||
        (socket_tsv_output && !socket_tsv_output->commit())) return 4;
    std::cout << Json{{"status", partial ? "PARTIAL" : "SUCCESS"}, {"phase", phase}, {"snapshots", snapshots},
                      {"partial", partial},
                      {"collector", "native"}, {"process_output", process_path}, {"memory_output", memory_path},
                      {"socket_output", socket_text_path}}.dump() << '\n';
    return 0;
}

}
