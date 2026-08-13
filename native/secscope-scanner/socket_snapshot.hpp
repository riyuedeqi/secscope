#ifndef SECSCOPE_SOCKET_SNAPSHOT_HPP
#define SECSCOPE_SOCKET_SNAPSHOT_HPP
#include "types.hpp"
namespace secscope {
bool collect_socket_snapshot(std::vector<SocketRecord>* records, Counters* counters,
                             std::size_t max_sockets = 65536);
bool write_socket_snapshot(const std::string& path, const std::vector<SocketRecord>& records);
}
#endif
