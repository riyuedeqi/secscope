#include "socket_snapshot.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <dirent.h>
#include <fstream>
#include <iomanip>
#include <map>
#include <sstream>
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>

namespace secscope {
namespace {
constexpr std::size_t MAX_SOCKET_OWNERS = 262144;

void mark_partial(Counters* counters, const char* reason) {
    if (!counters) return;
    counters->partial = true;
    if (counters->partial_reason.empty() && reason) counters->partial_reason = reason;
}

bool parse_unsigned(const std::string& value, int base, std::uint64_t* result) {
    if (!result || value.empty()) return false;
    errno = 0;
    char* end = nullptr;
    const unsigned long long parsed = std::strtoull(value.c_str(), &end, base);
    if (errno != 0 || !end || end == value.c_str() || *end != '\0') return false;
    *result = static_cast<std::uint64_t>(parsed);
    return true;
}

bool hex_byte(const std::string& value, std::size_t offset, unsigned char* result) {
    if (!result || offset + 2 > value.size()) return false;
    const auto digit = [](char item) -> int {
        if (item >= '0' && item <= '9') return item - '0';
        if (item >= 'a' && item <= 'f') return item - 'a' + 10;
        if (item >= 'A' && item <= 'F') return item - 'A' + 10;
        return -1;
    };
    const int high = digit(value[offset]);
    const int low = digit(value[offset + 1]);
    if (high < 0 || low < 0) return false;
    *result = static_cast<unsigned char>((high << 4) | low);
    return true;
}

bool normalize_address(const std::string& value, std::string* normalized) {
    if (!normalized) return false;
    const auto colon = value.find(':');
    if (colon == std::string::npos) { *normalized = value; return true; }
    const std::string hex = value.substr(0, colon);
    const std::string port = value.substr(colon + 1);
    std::uint64_t ip = 0;
    std::uint64_t port_number = 0;
    if (!parse_unsigned(port, 16, &port_number) || port_number > 0xffffULL) return false;
    if (hex.size() == 32) {
        unsigned char bytes[16]{};
        for (unsigned word = 0; word < 4; ++word) {
            for (unsigned byte = 0; byte < 4; ++byte) {
                if (!hex_byte(hex, static_cast<std::size_t>(word * 8U + (3U - byte) * 2U), &bytes[word * 4U + byte])) return false;
            }
        }
        char text[INET6_ADDRSTRLEN]{};
        if (!::inet_ntop(AF_INET6, bytes, text, sizeof(text))) return false;
        *normalized = std::string("[") + text + "]:" + std::to_string(port_number);
        return true;
    }
    if (hex.size() != 8 || !parse_unsigned(hex, 16, &ip) || ip > 0xffffffffULL) return false;
    std::ostringstream output;
    for (unsigned index = 0; index < 4; ++index) {
        if (index != 0) output << '.';
        output << ((ip >> (index * 8U)) & 0xffU);
    }
    output << ':' << port_number;
    *normalized = output.str();
    return true;
}

bool parse_pid(const char* value, std::int64_t* pid) {
    if (!value || !pid || !*value) return false;
    errno = 0;
    char* end = nullptr;
    const long long parsed = std::strtoll(value, &end, 10);
    if (errno != 0 || !end || end == value || *end != '\0' || parsed <= 0) return false;
    *pid = static_cast<std::int64_t>(parsed);
    return true;
}

void collect_inode_pids(std::map<std::uint64_t, std::int64_t>* owners, Counters* counters, std::size_t max_pids) {
    if (!owners || !counters) return;
    DIR* proc = ::opendir("/proc");
    if (!proc) { mark_partial(counters, "process_owner_index_unavailable"); return; }
    std::size_t seen = 0;
    while (dirent* p = ::readdir(proc)) {
        if (p->d_type != DT_DIR) continue;
        if (seen >= max_pids) { mark_partial(counters, "process_owner_index_budget"); break; }
        std::int64_t pid = 0;
        if (!parse_pid(p->d_name, &pid)) continue;
        ++seen;
        const std::string fd_dir = std::string("/proc/") + p->d_name + "/fd";
        DIR* fds = ::opendir(fd_dir.c_str());
        if (!fds) {
            const int open_error = errno;
            if (open_error == ENOENT || ::access((std::string("/proc/") + p->d_name).c_str(), F_OK) != 0) {
                ++counters->disappeared;
            } else {
                mark_partial(counters, "socket_owner_visibility_gap");
            }
            continue;
        }
        while (dirent* f = ::readdir(fds)) {
            if (owners->size() >= MAX_SOCKET_OWNERS) { mark_partial(counters, "socket_owner_index_budget"); break; }
            if (f->d_name[0] == '.') continue;
            const std::string link = fd_dir + "/" + f->d_name;
            char buffer[256]{};
            const ssize_t length = ::readlink(link.c_str(), buffer, sizeof(buffer) - 1);
            if (length <= 8) continue;
            buffer[length] = '\0';
            const std::string target(buffer, static_cast<std::size_t>(length));
            if (target.rfind("socket:[", 0) != 0 || target.back() != ']') continue;
            std::uint64_t inode = 0;
            if (target.size() <= 9 || !parse_unsigned(target.substr(8, target.size() - 9), 10, &inode) || inode == 0) {
                mark_partial(counters, "malformed_socket_owner");
                continue;
            }
            (*owners)[inode] = pid;
        }
        ::closedir(fds);
    }
    ::closedir(proc);
}
}

bool collect_socket_snapshot(std::vector<SocketRecord>* records, Counters* counters, std::size_t max_sockets) {
    if (!records || !counters) return false;
    records->clear();
    std::map<std::uint64_t, std::int64_t> owners;
    collect_inode_pids(&owners, counters, 32768);
    const char* files[] = {"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"};
    const char* names[] = {"tcp", "tcp6", "udp", "udp6"};
    bool readable_file = false;
    for (int file_index = 0; file_index < 4; ++file_index) {
        std::ifstream input(files[file_index]);
        if (!input) { mark_partial(counters, "socket_proc_file_unavailable"); continue; }
        readable_file = true;
        std::string line;
        std::getline(input, line);
        while (std::getline(input, line)) {
            if (records->size() >= max_sockets) { mark_partial(counters, "max_sockets"); break; }
            std::istringstream fields(line); std::string sl, local, remote, state, txrx, tr, retr, uid, timeout, inode;
            if (!(fields >> sl >> local >> remote >> state >> txrx >> tr >> retr >> uid >> timeout >> inode)) { mark_partial(counters, "malformed_socket_record"); continue; }
            SocketRecord socket;
            socket.protocol = names[file_index];
            if (!normalize_address(local, &socket.local_address) || !normalize_address(remote, &socket.remote_address) ||
                !parse_unsigned(inode, 10, &socket.inode)) {
                mark_partial(counters, "malformed_socket_record");
                continue;
            }
            socket.state = state;
            const auto it = owners.find(socket.inode);
            if (it != owners.end()) socket.pid = it->second;
            records->push_back(std::move(socket));
            ++counters->socket_snapshots;
        }
    }
    return readable_file;
}

bool write_socket_snapshot(const std::string& path, const std::vector<SocketRecord>& records) {
    const std::string temp = path + ".tmp"; std::ofstream out(temp, std::ios::trunc); if (!out) return false; out << "protocol\tlocal\tremote\tstate\tinode\tpid\n";
    for (const auto& s : records) out << s.protocol << '\t' << s.local_address << '\t' << s.remote_address << '\t' << s.state << '\t' << s.inode << '\t' << s.pid << '\n';
    out.close(); return out && ::rename(temp.c_str(), path.c_str()) == 0;
}
}
