#include "protocol.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <nlohmann/json.hpp>
#include <sys/socket.h>
#include <unistd.h>
namespace secscope_cache {
bool read_frame(int fd, std::string* payload) {
    if (!payload) return false;
    std::uint32_t length = 0;
    std::size_t got = 0;
    while (got < sizeof(length)) {
        const ssize_t count = ::recv(fd, reinterpret_cast<char*>(&length) + got, sizeof(length) - got, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        got += static_cast<std::size_t>(count);
    }
    length = ntohl(length);
    if (length == 0 || length > MAX_FRAME) return false;
    payload->assign(length, '\0');
    got = 0;
    while (got < length) {
        const ssize_t count = ::recv(fd, payload->data() + got, length - got, 0);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        got += static_cast<std::size_t>(count);
    }
    return true;
}

bool write_frame(int fd, const std::string& payload) {
    if (payload.empty() || payload.size() > MAX_FRAME) return false;
    const std::uint32_t length = htonl(static_cast<std::uint32_t>(payload.size()));
    const char* header = reinterpret_cast<const char*>(&length);
    std::size_t sent = 0;
    while (sent < sizeof(length)) {
        const ssize_t count = ::send(fd, header + sent, sizeof(length) - sent, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        sent += static_cast<std::size_t>(count);
    }
    sent = 0;
    while (sent < payload.size()) {
        const ssize_t count = ::send(fd, payload.data() + sent, payload.size() - sent, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return false;
        sent += static_cast<std::size_t>(count);
    }
    return true;
}

std::string request_value(const std::string& text, const char* key) {
    if (!key || text.size() > MAX_FRAME) return {};
    try {
        const auto object = nlohmann::json::parse(text);
        if (!object.is_object()) return {};
        const auto found = object.find(key);
        return found != object.end() && found->is_string() ? found->get<std::string>() : std::string{};
    } catch (...) {
        return {};
    }
}

std::string request_command(const std::string& json) { return request_value(json, "command"); }
std::string json_response(const std::string& status, const std::string& detail) {
    const std::string safe_status = nlohmann::json(status).dump();
    const std::string safe_detail = nlohmann::json(detail.substr(0, 65536)).dump();
    return "{\"schema_version\":1,\"protocol_version\":1,\"status\":" + safe_status + ",\"detail\":" + safe_detail + "}";
}
}
