#ifndef SECSCOPE_CHECKPOINT_HPP
#define SECSCOPE_CHECKPOINT_HPP
#include "types.hpp"
namespace secscope {
struct Checkpoint { unsigned schema_version = 1; std::string profile; std::string input_fingerprint; std::size_t completed = 0; std::size_t total = 0; std::string status = "SUCCESS"; std::string reason; };
bool save_checkpoint(const std::string& path, const Checkpoint& checkpoint);
bool load_checkpoint(const std::string& path, Checkpoint* checkpoint);
}
#endif
