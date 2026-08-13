#ifndef SECSCOPE_CACHE_STORAGE_HPP
#define SECSCOPE_CACHE_STORAGE_HPP
#include <cstddef>
#include <string>
#include <unordered_map>
namespace secscope_cache {
class Storage {
public:
    explicit Storage(std::string path, std::size_t capacity = 2048);
    bool load();
    bool persist();
    bool get(const std::string& key, std::string* value) const;
    bool put(const std::string& key, const std::string& value);
    void reset();
    std::size_t size() const { return values_.size(); }
private:
    std::string path_;
    std::size_t capacity_;
    std::unordered_map<std::string, std::string> values_;
};
}
#endif
