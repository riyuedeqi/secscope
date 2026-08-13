#include "protocol.hpp"
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
int main(int argc, char** argv) {
    if (argc < 2) return 2;
    std::string path = "/run/secscope-cache/cache.sock";
    if (std::string(argv[1]) == "--socket") {
        if (argc < 4 || std::string(argv[2]).empty()) return 2;
        path = argv[2];
        argv += 2;
        argc -= 2;
    }
    if (argc < 2 || std::string(argv[1]).empty()) return 2;
    std::string request = argv[1];
    if (request.empty()) return 2;
    int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 2;
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (path.size() >= sizeof(address.sun_path)) { ::close(fd); return 2; }
    std::strncpy(address.sun_path, path.c_str(), sizeof(address.sun_path) - 1);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) { ::close(fd); return 3; }
    if (request.front() != '{') request = "{\"schema_version\":1,\"command\":\"" + request + "\"}";
    bool ok = secscope_cache::write_frame(fd, request);
    std::string response;
    ok = ok && secscope_cache::read_frame(fd, &response);
    ::close(fd);
    if (!ok) return 4;
    std::cout << response << '\n';
    return 0;
}
