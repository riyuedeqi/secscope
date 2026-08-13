#include "storage.hpp"
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace secscope_cache {
namespace {
constexpr std::size_t MAX_SNAPSHOT_BYTES = 128ULL * 1024ULL * 1024ULL;
constexpr std::size_t MAX_VALUE_BYTES = 32768;
constexpr std::size_t MAX_LINE_BYTES = 160ULL * 1024ULL;

std::string hex(const std::string& value) {
    static const char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(value.size() * 2);
    for (unsigned char byte : value) {
        result += digits[byte >> 4];
        result += digits[byte & 15];
    }
    return result;
}

bool unhex(const std::string& value, std::string* result) {
    if (!result || value.size() % 2 != 0) return false;
    result->clear();
    result->reserve(value.size() / 2);
    const auto digit = [](char item) -> int {
        if (item >= '0' && item <= '9') return item - '0';
        if (item >= 'a' && item <= 'f') return item - 'a' + 10;
        if (item >= 'A' && item <= 'F') return item - 'A' + 10;
        return -1;
    };
    for (std::size_t index = 0; index < value.size(); index += 2) {
        const int high = digit(value[index]);
        const int low = digit(value[index + 1]);
        if (high < 0 || low < 0) { result->clear(); return false; }
        result->push_back(static_cast<char>((high << 4) | low));
    }
    return true;
}

void isolate_corrupt(const std::string& path) {
    const std::string corrupt = path + ".corrupt";
    ::rename(path.c_str(), corrupt.c_str());
}
}

Storage::Storage(std::string path, std::size_t capacity)
    : path_(std::move(path)), capacity_(capacity == 0 ? 1 : capacity) {}

bool Storage::load() {
    values_.clear();
    std::ifstream input(path_, std::ios::binary);
    if (!input) return true;
    input.seekg(0, std::ios::end);
    const auto size = input.tellg();
    if (size < 0 || static_cast<std::uint64_t>(size) > MAX_SNAPSHOT_BYTES) {
        isolate_corrupt(path_);
        return false;
    }
    input.seekg(0, std::ios::beg);
    std::string header;
    if (!std::getline(input, header) || header != "SECSCOPE-CACHE 1") {
        isolate_corrupt(path_);
        return false;
    }
    std::string line;
    while (std::getline(input, line)) {
        if (line.size() > MAX_LINE_BYTES) {
            values_.clear();
            isolate_corrupt(path_);
            return false;
        }
        const auto tab = line.find('\t');
        if (tab == std::string::npos) {
            values_.clear();
            isolate_corrupt(path_);
            return false;
        }
        std::string key;
        std::string value;
        if (!unhex(line.substr(0, tab), &key) || !unhex(line.substr(tab + 1), &value) || key.empty() || key.size() > 4096 || value.size() > MAX_VALUE_BYTES) {
            values_.clear();
            isolate_corrupt(path_);
            return false;
        }
        if (values_.find(key) == values_.end() && values_.size() >= capacity_) {
            values_.clear();
            isolate_corrupt(path_);
            return false;
        }
        values_[std::move(key)] = std::move(value);
    }
    if (input.bad()) {
        values_.clear();
        isolate_corrupt(path_);
        return false;
    }
    return true;
}

bool Storage::persist() {
    const std::string temporary = path_ + ".tmp";
    std::ofstream output(temporary, std::ios::trunc);
    if (!output) return false;
    output << "SECSCOPE-CACHE 1\n";
    for (const auto& entry : values_) output << hex(entry.first) << '\t' << hex(entry.second) << '\n';
    output.flush();
    if (!output) { output.close(); ::unlink(temporary.c_str()); return false; }
    output.close();
    if (::rename(temporary.c_str(), path_.c_str()) != 0) { ::unlink(temporary.c_str()); return false; }
    ::chmod(path_.c_str(), 0600);
    return true;
}

bool Storage::get(const std::string& key, std::string* value) const {
    const auto iterator = values_.find(key);
    if (iterator == values_.end()) return false;
    if (value) *value = iterator->second;
    return true;
}

bool Storage::put(const std::string& key, const std::string& value) {
    if (key.empty() || key.size() > 4096 || value.size() > MAX_VALUE_BYTES) return false;
    const auto existing = values_.find(key);
    const bool had_existing = existing != values_.end();
    std::string old_value;
    if (had_existing) old_value = existing->second;
    std::string evicted_key;
    std::string evicted_value;
    if (values_.size() >= capacity_ && !had_existing) {
        auto evicted = values_.begin();
        evicted_key = evicted->first;
        evicted_value = evicted->second;
        values_.erase(evicted);
    }
    values_[key] = value;
    if (persist()) return true;
    if (had_existing) values_[key] = std::move(old_value);
    else values_.erase(key);
    if (!evicted_key.empty()) values_[std::move(evicted_key)] = std::move(evicted_value);
    return false;
}

void Storage::reset() {
    values_.clear();
    persist();
}
}
