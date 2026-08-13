#pragma once

#include <chrono>
#include <cstdint>
#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace secscope {

using Arguments = std::map<std::string, std::vector<std::string>>;

Arguments parse_arguments(int argc, char** argv);
std::string argument(const Arguments& args, const std::string& name,
                     const std::string& fallback = {});
std::vector<std::string> arguments(const Arguments& args, const std::string& name);
std::uint64_t uint_argument(const Arguments& args, const std::string& name,
                            std::uint64_t fallback, std::uint64_t minimum,
                            std::uint64_t maximum);
double double_argument(const Arguments& args, const std::string& name,
                       double fallback, double minimum, double maximum);
bool required_arguments(const Arguments& args,
                        const std::vector<std::string>& names,
                        std::string* error);
std::string trim_line(std::string line);
std::string clean_cell(const std::string& value);
std::string absolute_lexical_path(const std::string& path);

class AtomicOutput {
public:
    explicit AtomicOutput(const std::string& path);
    ~AtomicOutput();
    AtomicOutput(const AtomicOutput&) = delete;
    AtomicOutput& operator=(const AtomicOutput&) = delete;

    bool good() const;
    std::ofstream& stream();
    bool commit();

private:
    std::string path_;
    std::string temporary_;
    std::ofstream stream_;
    bool committed_ = false;
};

}
