#include "native_io.hpp"

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <sys/stat.h>
#include <unistd.h>

namespace secscope {

Arguments parse_arguments(int argc, char** argv) {
    Arguments result;
    for (int index = 0; index < argc; ++index) {
        std::string name = argv[index];
        if (name.rfind("--", 0) != 0) continue;
        std::string value = "true";
        if (index + 1 < argc && std::string(argv[index + 1]).rfind("--", 0) != 0) {
            value = argv[++index];
        }
        result[name].push_back(value);
    }
    return result;
}

std::string argument(const Arguments& args, const std::string& name,
                     const std::string& fallback) {
    const auto found = args.find(name);
    return found == args.end() || found->second.empty() ? fallback : found->second.back();
}

std::vector<std::string> arguments(const Arguments& args, const std::string& name) {
    const auto found = args.find(name);
    return found == args.end() ? std::vector<std::string>{} : found->second;
}

std::uint64_t uint_argument(const Arguments& args, const std::string& name,
                            std::uint64_t fallback, std::uint64_t minimum,
                            std::uint64_t maximum) {
    const std::string raw = argument(args, name);
    if (raw.empty() || raw[0] == '-') return fallback;
    errno = 0;
    char* end = nullptr;
    const unsigned long long parsed = std::strtoull(raw.c_str(), &end, 10);
    if (errno != 0 || end == raw.c_str() || *end != '\0') return fallback;
    return std::max(minimum, std::min(maximum, static_cast<std::uint64_t>(parsed)));
}

double double_argument(const Arguments& args, const std::string& name,
                       double fallback, double minimum, double maximum) {
    const std::string raw = argument(args, name);
    if (raw.empty()) return fallback;
    errno = 0;
    char* end = nullptr;
    const double parsed = std::strtod(raw.c_str(), &end);
    if (errno != 0 || end == raw.c_str() || *end != '\0' || !std::isfinite(parsed)) return fallback;
    return std::max(minimum, std::min(maximum, parsed));
}

bool required_arguments(const Arguments& args,
                        const std::vector<std::string>& names,
                        std::string* error) {
    for (const auto& name : names) {
        if (argument(args, name).empty()) {
            if (error) *error = name + " is required";
            return false;
        }
    }
    return true;
}

std::string trim_line(std::string line) {
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
    return line;
}

std::string clean_cell(const std::string& value) {
    std::string result = value;
    for (char& item : result) {
        if (item == '\t' || item == '\r' || item == '\n' || item == '\0' || item == '\x1f') item = ' ';
    }
    return result;
}

std::string absolute_lexical_path(const std::string& path) {
    std::error_code error;
    const auto absolute = std::filesystem::absolute(path, error);
    return error ? path : absolute.lexically_normal().string();
}

AtomicOutput::AtomicOutput(const std::string& path)
    : path_(path), temporary_(path + ".tmp." + std::to_string(::getpid())),
      stream_(temporary_, std::ios::binary | std::ios::trunc) {
    if (stream_) ::chmod(temporary_.c_str(), 0600);
}

AtomicOutput::~AtomicOutput() {
    if (!committed_) {
        stream_.close();
        ::unlink(temporary_.c_str());
    }
}

bool AtomicOutput::good() const { return static_cast<bool>(stream_); }
std::ofstream& AtomicOutput::stream() { return stream_; }

bool AtomicOutput::commit() {
    if (committed_) return true;
    stream_.flush();
    if (!stream_) return false;
    stream_.close();
    if (::rename(temporary_.c_str(), path_.c_str()) != 0) return false;
    ::chmod(path_.c_str(), 0600);
    committed_ = true;
    return true;
}

}
