#include "protocol.hpp"
#include "storage.hpp"
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>

namespace { volatile std::sig_atomic_t stop = 0; volatile std::sig_atomic_t listen_fd = -1; void on_signal(int) { stop = 1; if (listen_fd >= 0) { ::close(static_cast<int>(listen_fd)); listen_fd = -1; } } }
int main(int argc, char** argv) {
    std::string socket_path = "/run/secscope-cache/cache.sock";
    std::string storage_path = "/var/lib/secscope/cache.snapshot";
    for (int index = 1; index < argc; ++index) {
        if (std::string(argv[index]) == "--socket" && index + 1 < argc) socket_path = argv[++index];
        else if (std::string(argv[index]) == "--storage" && index + 1 < argc) storage_path = argv[++index];
    }
    std::filesystem::path dir(socket_path);
    dir.remove_filename();
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec || ::chmod(dir.c_str(), 0700) != 0) return 2;
    ::unlink(socket_path.c_str());
    int server = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server < 0) return 2;
    const auto cleanup_socket = [&]() {
        ::close(server);
        listen_fd = -1;
        ::unlink(socket_path.c_str());
    };
    listen_fd = server;
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (socket_path.size() >= sizeof(address.sun_path)) {
        cleanup_socket();
        return 2;
    }
    std::strncpy(address.sun_path, socket_path.c_str(), sizeof(address.sun_path) - 1);
    if (::bind(server, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
        ::chmod(socket_path.c_str(), 0600) != 0 || ::listen(server, 16) != 0) {
        cleanup_socket();
        return 2;
    }
    secscope_cache::Storage storage(storage_path);
    storage.load();
    std::signal(SIGTERM, on_signal);
    std::signal(SIGINT, on_signal);
    while (!stop) {
        int client = ::accept4(server, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) {
            if (errno == EINTR) continue;
            break;
        }
        timeval timeout{5, 0};
        ::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        ::setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        ucred peer{};
        socklen_t peer_len = sizeof(peer);
        if (::getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) != 0 || peer.uid != ::getuid()) {
            secscope_cache::write_frame(client, secscope_cache::json_response("DENIED"));
            ::close(client);
            continue;
        }
        std::string request;
        if (secscope_cache::read_frame(client, &request)) {
            const auto command = secscope_cache::request_command(request);
            const auto key = secscope_cache::request_value(request, "key");
            const auto value = secscope_cache::request_value(request, "value");
            std::string response;
            if (command == "ping" || command == "health") response = secscope_cache::json_response("OK", command == "health" ? "healthy" : "pong");
            else if (command == "reset") { storage.reset(); response = secscope_cache::json_response("OK", "reset"); }
            else if (command == "get_cached_hash") { std::string cached; response = storage.get(key, &cached) ? secscope_cache::json_response("HIT", cached) : secscope_cache::json_response("MISS"); }
            else if (command == "update_hash") response = storage.put(key, value) ? secscope_cache::json_response("OK") : secscope_cache::json_response("FAILED", "storage");
            else if (command == "commit_baseline" || command == "checkpoint" || command == "file_snapshot" || command == "file_delta" || command == "process_snapshot") response = secscope_cache::json_response("OK", "accepted");
            else response = secscope_cache::json_response("INVALID", "unknown_command");
            secscope_cache::write_frame(client, response);
        }
        ::close(client);
    }
    if (listen_fd >= 0) ::close(server);
    listen_fd = -1;
    ::unlink(socket_path.c_str());
    return 0;
}
