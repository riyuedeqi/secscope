#pragma once

#include <string>

namespace secscope {

constexpr const char* NATIVE_HASH_ANALYZER_VERSION = "native-hash-files-v2";

int run_native_helper(const std::string& command, int argc, char** argv);
bool is_native_helper_command(const std::string& command);

}
