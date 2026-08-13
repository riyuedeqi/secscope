#include "hashing.hpp"

#include <cerrno>
#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>
#include <array>
#include <iomanip>
#include <memory>
#include <sstream>
#include <vector>

namespace secscope {
namespace {
class ScopedFd {
public:
    explicit ScopedFd(int fd) : fd_(fd) {}
    ~ScopedFd() { if (fd_ >= 0) ::close(fd_); }
    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;
    int get() const { return fd_; }
private:
    int fd_;
};

std::string hex_digest(const unsigned char* data, unsigned length) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (unsigned i = 0; i < length; ++i) output << std::setw(2) << static_cast<unsigned>(data[i]);
    return output.str();
}
bool digest_file(int fd, EVP_MD_CTX* md5, EVP_MD_CTX* sha, std::uint64_t expected_size) {
    std::vector<unsigned char> buffer(1024 * 1024);
    std::uint64_t total = 0;
    while (true) {
        ssize_t count = ::read(fd, buffer.data(), buffer.size());
        if (count < 0) { if (errno == EINTR) continue; return false; }
        if (count == 0) break;
        total += static_cast<std::uint64_t>(count);
        if (total > expected_size) return false;
        if (EVP_DigestUpdate(md5, buffer.data(), static_cast<std::size_t>(count)) != 1 ||
            EVP_DigestUpdate(sha, buffer.data(), static_cast<std::size_t>(count)) != 1) return false;
    }
    return total == expected_size;
}
}

bool hash_file(const std::string& path, std::uint64_t max_bytes, InventoryRecord* record, Counters* counters) {
    if (!record) return false;
    struct stat before{}, after{};
    ScopedFd fd(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (fd.get() < 0 || ::fstat(fd.get(), &before) != 0) {
        if (counters) ++counters->hash_failed;
        record->status = errno == ENOENT ? "DELETED" : "UNREADABLE";
        record->error = errno == EACCES ? "permission_denied" : "open_or_stat_failed";
        return false;
    }
    if (!S_ISREG(before.st_mode) || before.st_size < 0 || static_cast<std::uint64_t>(before.st_size) > max_bytes) {
        record->status = !S_ISREG(before.st_mode) ? "SPECIAL_FILE_SKIPPED" : "TOO_LARGE";
        record->error = !S_ISREG(before.st_mode) ? "not_regular_file" : "hash_size_limit";
        if (counters) ++counters->skipped;
        return false;
    }
    using DigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    DigestContext md5(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    DigestContext sha(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    bool ok = md5 && sha && EVP_DigestInit_ex(md5.get(), EVP_md5(), nullptr) == 1 &&
              EVP_DigestInit_ex(sha.get(), EVP_sha256(), nullptr) == 1 &&
              digest_file(fd.get(), md5.get(), sha.get(), static_cast<std::uint64_t>(before.st_size));
    unsigned char md5_out[EVP_MAX_MD_SIZE]{}, sha_out[EVP_MAX_MD_SIZE]{};
    unsigned md5_len = 0, sha_len = 0;
    if (ok) ok = EVP_DigestFinal_ex(md5.get(), md5_out, &md5_len) == 1 && EVP_DigestFinal_ex(sha.get(), sha_out, &sha_len) == 1;
    if (::fstat(fd.get(), &after) != 0) ok = false;
    if (ok && (before.st_dev != after.st_dev || before.st_ino != after.st_ino || before.st_size != after.st_size ||
               before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec ||
               before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)) {
        ok = false;
        record->status = "CHANGED_DURING_HASH";
        record->error = "metadata_changed";
    }
    if (ok) {
        record->md5 = hex_digest(md5_out, md5_len);
        record->sha256 = hex_digest(sha_out, sha_len);
        record->status = "SUCCESS";
        if (counters) ++counters->hash_computed;
    } else if (counters) {
        ++counters->hash_failed;
    }
    return ok;
}
}
