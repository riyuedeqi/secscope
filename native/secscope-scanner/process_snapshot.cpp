#include "process_snapshot.hpp"

#include "hashing.hpp"
#include <algorithm>
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <cstdlib>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/sha.h>

namespace secscope {
namespace {
constexpr std::size_t MAX_MAPS_PER_PROCESS = 4096;
constexpr std::size_t MAX_MAPS_TOTAL = 65536;
std::string read_file(const std::string& path, std::size_t limit) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    std::string value;
    value.resize(limit);
    input.read(value.data(), static_cast<std::streamsize>(value.size()));
    value.resize(static_cast<std::size_t>(input.gcount()));
    return value;
}
std::string json_safe(const std::string& input) {
    std::ostringstream out;
    for (unsigned char c : input) {
        switch (c) { case '\\': out << "\\\\"; break; case '"': out << "\\\""; break;
        case '\n': out << "\\n"; break; case '\r': out << "\\r"; break; case '\t': out << "\\t"; break;
        default: if (c < 0x20) out << "\\u00" << std::hex << static_cast<unsigned>(c); else out << static_cast<char>(c); }
    }
    return out.str();
}
}

bool collect_process_snapshot(std::vector<ProcessRecord>* records, Counters* counters, std::size_t max_processes) {
    if (!records || !counters) return false;
    records->clear();
    DIR* proc = ::opendir("/proc");
    if (!proc) return false;
    std::size_t total_maps = 0;
    while (dirent* entry = ::readdir(proc)) {
        if (entry->d_type != DT_DIR) continue;
        char* end = nullptr;
        long pid = std::strtol(entry->d_name, &end, 10);
        if (!end || *end != '\0' || pid <= 0) continue;
        if (records->size() >= max_processes) { counters->partial = true; counters->partial_reason = "max_processes"; break; }
        ++counters->proc_pid_visits;
        ProcessRecord item; item.pid = pid;
        const std::string base = std::string("/proc/") + entry->d_name;
        char exe_buf[4096]; ssize_t exe_len = ::readlink((base + "/exe").c_str(), exe_buf, sizeof(exe_buf) - 1);
        if (exe_len > 0) { exe_buf[exe_len] = '\0'; item.exe.assign(exe_buf, static_cast<std::size_t>(exe_len)); }
        std::string comm = read_file(base + "/comm", 512); while (!comm.empty() && (comm.back() == '\n' || comm.back() == '\r')) comm.pop_back(); item.comm = comm;
        std::string status = read_file(base + "/status", 8192);
        std::istringstream lines(status); std::string line;
        while (std::getline(lines, line)) {
            if (line.rfind("State:", 0) == 0) item.state = line.substr(6);
            else if (line.rfind("PPid:", 0) == 0) item.ppid = std::strtoll(line.c_str() + 5, nullptr, 10);
        }
        std::string stat = read_file(base + "/stat", 4096); auto close = stat.rfind(')');
        if (close != std::string::npos) { std::istringstream tail(stat.substr(close + 2)); std::string token; for (int i = 0; i < 20 && tail >> token; ++i) if (i == 19) item.start_ticks = std::strtoull(token.c_str(), nullptr, 10); }
        std::string cmdline = read_file(base + "/cmdline", 8192);
        if (!cmdline.empty()) { unsigned char digest[32]{}; static const char hex[] = "0123456789abcdef"; SHA256(reinterpret_cast<const unsigned char*>(cmdline.data()), cmdline.size(), digest); item.cmdline_hash.reserve(64); for (unsigned char c : digest) { item.cmdline_hash.push_back(hex[c >> 4]); item.cmdline_hash.push_back(hex[c & 15]); } }
        std::ifstream maps(base + "/maps");
        while (std::getline(maps, line)) {
            if (item.executable_maps.size() >= MAX_MAPS_PER_PROCESS || total_maps >= MAX_MAPS_TOTAL) { counters->partial = true; counters->partial_reason = "maps_budget"; break; }
            ++counters->proc_maps_visits;
            std::istringstream fields(line); std::string address, perms, offset, dev, inode, path;
            if (fields >> address >> perms >> offset >> dev >> inode && std::getline(fields, path) && perms.find('x') != std::string::npos) {
                while (!path.empty() && path.front() == ' ') path.erase(path.begin());
                if (!path.empty() && path.front() == '/' && path.find(" (deleted)") == std::string::npos) { item.executable_maps.push_back(path); ++total_maps; }
            }
        }
        records->push_back(std::move(item));
    }
    ::closedir(proc);
    std::sort(records->begin(), records->end(), [](const ProcessRecord& a, const ProcessRecord& b) { return a.pid < b.pid; });
    return true;
}

bool write_process_snapshot(const std::string& path, const std::vector<ProcessRecord>& records) {
    const std::string temp = path + ".tmp"; std::ofstream out(temp, std::ios::binary | std::ios::trunc); if (!out) return false;
    out << "{\"schema_version\":1,\"processes\":[";
    for (std::size_t i = 0; i < records.size(); ++i) { const auto& p = records[i]; if (i) out << ','; out << "{\"pid\":" << p.pid << ",\"ppid\":" << p.ppid << ",\"start_ticks\":" << p.start_ticks << ",\"comm\":\"" << json_safe(p.comm) << "\",\"exe\":\"" << json_safe(p.exe) << "\",\"cmdline_hash\":\"" << p.cmdline_hash << "\",\"state\":\"" << json_safe(p.state) << "\",\"maps\":["; for (std::size_t j = 0; j < p.executable_maps.size(); ++j) { if (j) out << ','; out << '\"' << json_safe(p.executable_maps[j]) << '\"'; } out << "]}"; }
    out << "]}\n"; out.close(); return out && ::rename(temp.c_str(), path.c_str()) == 0;
}
}
