#ifndef SECSCOPE_CACHE_PROTOCOL_HPP
#define SECSCOPE_CACHE_PROTOCOL_HPP
#include <cstddef>
#include <cstdint>
#include <string>
namespace secscope_cache {
constexpr unsigned PROTOCOL_VERSION = 1;
constexpr std::size_t MAX_FRAME = 1024 * 1024;
bool read_frame(int fd, std::string* payload);
bool write_frame(int fd, const std::string& payload);
std::string request_command(const std::string& json);
std::string request_value(const std::string& json, const char* key);
std::string json_response(const std::string& status, const std::string& detail = {});
}
#endif
