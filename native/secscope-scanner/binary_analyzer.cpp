#include "binary_analyzer.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <cerrno>
#include <fcntl.h>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <regex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_set>
#include <vector>

namespace secscope {
namespace {

using Json = nlohmann::json;
using Bytes = std::vector<unsigned char>;
constexpr const char* VERSION = "1.0.0";
constexpr std::size_t MAX_STRINGS = 512;
constexpr std::size_t MAX_TABLE_ITEMS = 256;
constexpr std::size_t MAX_SECTIONS = 96;

std::string safe_json_dump(const Json& value) {
    return value.dump(-1, ' ', false, Json::error_handler_t::replace);
}

const std::vector<std::set<std::string>> INJECTION = {
    {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
    {"OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "NtCreateThreadEx"},
    {"OpenProcess", "WriteProcessMemory", "QueueUserAPC"},
    {"NtOpenProcess", "NtWriteVirtualMemory", "RtlCreateUserThread"}};
const std::vector<std::set<std::string>> MEMORY_LOADER = {
    {"VirtualAlloc", "VirtualProtect", "CreateThread"},
    {"NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx"},
    {"memfd_create", "mmap", "mprotect"}};
const std::vector<std::set<std::string>> DYNAMIC_RESOLVER = {
    {"LoadLibraryA", "GetProcAddress"}, {"LoadLibraryW", "GetProcAddress"},
    {"LdrLoadDll", "LdrGetProcedureAddress"}, {"dlopen", "dlsym"}};
const std::vector<std::set<std::string>> LINUX_INJECTION = {
    {"ptrace", "process_vm_writev"}, {"ptrace", "/proc/", "/mem"}};
const std::set<std::string> NETWORK_APIS = {
    "socket", "connect", "WSAStartup", "InternetOpenA", "InternetOpenW",
    "WinHttpOpen", "curl_easy_init", "getaddrinfo"};
const std::set<std::string> CRYPTO_MARKERS = {
    "AES", "RC4", "CryptDecrypt", "BCryptDecrypt", "ChaCha20", "XOR"};
const std::set<std::string> EXEC_MARKERS = {
    "CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW",
    "WinExec", "system", "execve", "popen", "powershell"};

template <typename T>
bool read_number(const Bytes& data, std::size_t offset, T* value, bool little = true) {
    if (!value || offset > data.size() || sizeof(T) > data.size() - offset) return false;
    T result{};
    for (std::size_t index = 0; index < sizeof(T); ++index) {
        const std::size_t shift = little ? index : sizeof(T) - index - 1;
        result |= static_cast<T>(data[offset + index]) << (shift * 8U);
    }
    *value = result;
    return true;
}

std::string hex_value(std::uint64_t value) {
    std::ostringstream output;
    output << "0x" << std::hex << std::nouppercase << value;
    return output.str();
}

std::string ascii_string(const Bytes& data, std::size_t offset, std::size_t limit = 512) {
    if (offset >= data.size()) return {};
    const std::size_t end = std::min(data.size(), offset + limit);
    std::size_t current = offset;
    while (current < end && data[current] != 0) ++current;
    static constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(current - offset);
    for (std::size_t index = offset; index < current; ++index) {
        const unsigned char value = data[index];
        if (value >= 0x20 && value <= 0x7e) {
            result.push_back(static_cast<char>(value));
        } else {
            result += "\\x";
            result.push_back(digits[value >> 4U]);
            result.push_back(digits[value & 0x0fU]);
        }
    }
    return result;
}

double entropy(const Bytes& data, std::size_t offset, std::size_t length) {
    if (offset >= data.size() || length == 0) return 0.0;
    const std::size_t end = std::min(data.size(), offset + length);
    if (end <= offset) return 0.0;
    std::array<std::size_t, 256> counts{};
    for (std::size_t index = offset; index < end; ++index) ++counts[data[index]];
    const double total = static_cast<double>(end - offset);
    double result = 0.0;
    for (const auto count : counts) {
        if (count == 0) continue;
        const double probability = static_cast<double>(count) / total;
        result -= probability * std::log2(probability);
    }
    return std::round(result * 10000.0) / 10000.0;
}

std::vector<std::string> ascii_runs(const Bytes& data) {
    std::vector<std::string> result;
    std::size_t start = 0;
    while (start < data.size() && result.size() < MAX_STRINGS) {
        while (start < data.size() && (data[start] < 0x20 || data[start] > 0x7e)) ++start;
        const std::size_t begin = start;
        while (start < data.size() && data[start] >= 0x20 && data[start] <= 0x7e) ++start;
        if (start - begin >= 5) result.emplace_back(data.begin() + static_cast<std::ptrdiff_t>(begin), data.begin() + static_cast<std::ptrdiff_t>(start));
    }
    return result;
}

std::vector<std::string> wide_runs(const Bytes& data) {
    std::vector<std::string> result;
    std::size_t index = 0;
    while (index + 1 < data.size() && result.size() < MAX_STRINGS) {
        const std::size_t begin = index;
        std::string value;
        while (index + 1 < data.size() && data[index] >= 0x20 && data[index] <= 0x7e && data[index + 1] == 0) {
            value.push_back(static_cast<char>(data[index])); index += 2;
        }
        if (value.size() >= 5) result.push_back(std::move(value));
        index = std::max(index, begin + 1);
    }
    return result;
}

std::vector<std::string> unique_values(const std::vector<std::string>& source) {
    std::vector<std::string> result;
    std::unordered_set<std::string> seen;
    for (const auto& value : source) {
        const std::string clipped = value.substr(0, 2048);
        if (seen.insert(clipped).second) result.push_back(clipped);
    }
    return result;
}

Json extract_strings(const Bytes& data) {
    std::vector<std::string> values = ascii_runs(data);
    const auto wide = wide_runs(data);
    values.insert(values.end(), wide.begin(), wide.end());
    values = unique_values(values);
    std::string joined;
    for (const auto& value : values) joined += value + "\n";
    const std::regex url_re(R"(https?://[^\s"'<>]{4,256})", std::regex::icase | std::regex::optimize);
    const std::regex ip_re(R"((?:[0-9]{1,3}\.){3}[0-9]{1,3})", std::regex::optimize);
    const std::regex domain_re(R"(\b(?:[a-z0-9-]{1,63}\.)+(?:com|net|org|io|cn|ru|top|xyz|info|biz|cc|me|co)\b)", std::regex::icase | std::regex::optimize);
    const std::regex config_re(R"((mutex|campaign|sleep|beacon|server|host|port|password|install|persistence|user-agent))", std::regex::icase | std::regex::optimize);
    const std::regex encoded_re(R"(^[A-Za-z0-9+/=_-]+$)", std::regex::optimize);
    auto matches = [&](const std::regex& pattern, std::size_t limit) {
        std::vector<std::string> output;
        for (std::sregex_iterator iterator(joined.begin(), joined.end(), pattern), end; iterator != end && output.size() < limit; ++iterator) output.push_back(iterator->str());
        std::sort(output.begin(), output.end()); output.erase(std::unique(output.begin(), output.end()), output.end());
        return output;
    };
    std::vector<std::string> config;
    std::vector<std::string> encoded;
    for (const auto& value : values) {
        if (std::regex_search(value, config_re) && config.size() < 64) config.push_back(value);
        if (value.size() >= 40 && std::regex_match(value, encoded_re) && encoded.size() < 32) encoded.push_back(value);
    }
    return Json{{"ascii_unicode_sample", Json(std::vector<std::string>(values.begin(), values.begin() + static_cast<std::ptrdiff_t>(std::min<std::size_t>(128, values.size()))))},
                {"urls", matches(url_re, 64)}, {"ips", matches(ip_re, 64)}, {"domains", matches(domain_re, 64)},
                {"config_strings", config}, {"encoded_candidates", encoded}};
}

std::set<std::string> marker_set(const std::vector<std::string>& imports, const Json& strings) {
    std::set<std::string> result(imports.begin(), imports.end());
    std::string haystack;
    if (strings.contains("ascii_unicode_sample")) for (const auto& value : strings["ascii_unicode_sample"]) haystack += value.get<std::string>() + "\n";
    std::set<std::string> markers;
    for (const auto& group : INJECTION) markers.insert(group.begin(), group.end());
    for (const auto& group : MEMORY_LOADER) markers.insert(group.begin(), group.end());
    for (const auto& group : DYNAMIC_RESOLVER) markers.insert(group.begin(), group.end());
    for (const auto& group : LINUX_INJECTION) markers.insert(group.begin(), group.end());
    markers.insert(NETWORK_APIS.begin(), NETWORK_APIS.end()); markers.insert(CRYPTO_MARKERS.begin(), CRYPTO_MARKERS.end()); markers.insert(EXEC_MARKERS.begin(), EXEC_MARKERS.end());
    markers.insert({"memcpy", "RtlMoveMemory", "SW_HIDE", "CREATE_NO_WINDOW", "DownloadString", "Invoke-WebRequest", "/proc/", "/mem", "Sleep"});
    std::string lower_haystack = haystack;
    std::transform(lower_haystack.begin(), lower_haystack.end(), lower_haystack.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    for (const auto& marker : markers) {
        std::string lower_marker = marker;
        std::transform(lower_marker.begin(), lower_marker.end(), lower_marker.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower_haystack.find(lower_marker) != std::string::npos) result.insert(marker);
    }
    return result;
}

Json api_combinations(const std::vector<std::string>& imports, const Json& strings) {
    const auto markers = marker_set(imports, strings);
    Json combinations = Json::array();
    auto sorted_hit = [&](const std::set<std::string>& required) {
        std::vector<std::string> hit;
        for (const auto& value : required) if (markers.count(value)) hit.push_back(value);
        return hit;
    };
    for (const auto& required : INJECTION) { const auto hit = sorted_hit(required); if (hit.size() == required.size()) { combinations.push_back({{"name", "process_injection"}, {"apis", hit}, {"risk", 35}}); break; } }
    for (const auto& required : LINUX_INJECTION) { const auto hit = sorted_hit(required); if (hit.size() == required.size()) { combinations.push_back({{"name", "process_injection"}, {"apis", hit}, {"risk", 35}}); break; } }
    for (const auto& required : MEMORY_LOADER) { const auto hit = sorted_hit(required); if (hit.size() == required.size()) { combinations.push_back({{"name", "memory_loader"}, {"apis", hit}, {"risk", 25}}); break; } }
    for (const auto& required : DYNAMIC_RESOLVER) { const auto hit = sorted_hit(required); if (hit.size() == required.size()) { combinations.push_back({{"name", "dynamic_api_resolution"}, {"apis", hit}, {"risk", 12}}); break; } }
    auto intersection = [&](const std::set<std::string>& required) { return sorted_hit(required); };
    const auto network = intersection(NETWORK_APIS), crypto = intersection(CRYPTO_MARKERS);
    const std::set<std::string> loop_set{"Sleep", "sleep", "beacon"};
    const auto loop = intersection(loop_set);
    if (!network.empty() && !crypto.empty() && !loop.empty()) { auto apis = network; apis.insert(apis.end(), crypto.begin(), crypto.end()); apis.insert(apis.end(), loop.begin(), loop.end()); combinations.push_back({{"name", "encrypted_periodic_client"}, {"apis", apis}, {"risk", 20}}); }
    const auto hidden = intersection({"SW_HIDE", "CREATE_NO_WINDOW"}), execute = intersection(EXEC_MARKERS);
    if (!hidden.empty() && !execute.empty() && !network.empty()) { auto apis = hidden; apis.insert(apis.end(), execute.begin(), execute.end()); apis.insert(apis.end(), network.begin(), network.end()); combinations.push_back({{"name", "hidden_network_process"}, {"apis", apis}, {"risk", 20}}); }
    const auto download = intersection({"DownloadString", "Invoke-WebRequest"});
    if (!download.empty() && markers.count("powershell") && !execute.empty()) { auto apis = download; apis.insert(apis.end(), execute.begin(), execute.end()); apis.push_back("powershell"); combinations.push_back({{"name", "script_download_execute"}, {"apis", apis}, {"risk", 25}}); }
    return combinations;
}

struct Section {
    std::string name;
    std::uint64_t virtual_size = 0;
    std::uint64_t virtual_address = 0;
    std::uint64_t raw_size = 0;
    std::uint64_t raw_offset = 0;
    std::uint64_t characteristics = 0;
    double entropy_value = 0.0;
    bool executable = false;
    bool writable = false;
};

std::optional<std::size_t> rva_to_offset(std::uint64_t rva, const std::vector<Section>& sections, std::uint64_t header_size) {
    if (rva < header_size && rva <= std::numeric_limits<std::size_t>::max()) return static_cast<std::size_t>(rva);
    for (const auto& section : sections) {
        const std::uint64_t span = std::max(section.virtual_size, section.raw_size);
        if (rva < section.virtual_address || span > std::numeric_limits<std::uint64_t>::max() - section.virtual_address) continue;
        const std::uint64_t end = section.virtual_address + span;
        if (rva >= end) continue;
        const std::uint64_t delta = rva - section.virtual_address;
        if (section.raw_offset > std::numeric_limits<std::uint64_t>::max() - delta) continue;
        const std::uint64_t offset = section.raw_offset + delta;
        if (offset > std::numeric_limits<std::size_t>::max()) continue;
        return static_cast<std::size_t>(offset);
    }
    return std::nullopt;
}

Json section_json(const Section& section) {
    return Json{{"name", section.name}, {"virtual_size", section.virtual_size}, {"virtual_address", section.virtual_address},
                {"raw_size", section.raw_size}, {"raw_offset", section.raw_offset}, {"characteristics", hex_value(section.characteristics)},
                {"entropy", section.entropy_value}, {"executable", section.executable}, {"writable", section.writable}};
}

Json parse_pe(const Bytes& data) {
    Json result{{"format", "PE"}, {"sections", Json::array()}, {"imports", Json::array()}, {"exports", Json::array()}, {"resources", Json::object()}, {"certificate_table", Json{{"present", false}}}, {"parse_status", "PARTIAL"}, {"parse_errors", Json::array()}};
    std::uint32_t peoff = 0; std::uint16_t section_count_raw = 0, optional_size = 0;
    if (!read_number(data, 0x3c, &peoff) || peoff < 0x40 || peoff > data.size() ||
        data.size() - peoff < 24 || std::memcmp(data.data() + peoff, "PE\0\0", 4) != 0) {
        result["parse_errors"].push_back("invalid PE signature/offset");
        return result;
    }
    std::uint16_t machine = 0; std::uint32_t stamp = 0;
    if (!read_number(data, peoff + 4, &machine) || !read_number(data, peoff + 6, &section_count_raw) || !read_number(data, peoff + 8, &stamp) || !read_number(data, peoff + 20, &optional_size)) { result["parse_errors"].push_back("truncated PE header"); return result; }
    const std::size_t opt = peoff + 24; std::uint16_t magic = 0;
    if (!read_number(data, opt, &magic) || (magic != 0x10b && magic != 0x20b)) { result["parse_errors"].push_back("unsupported optional header"); return result; }
    const bool is64 = magic == 0x20b; std::uint32_t entry = 0, header_size = 0;
    if (!read_number(data, opt + 16, &entry) || !read_number(data, opt + 60, &header_size)) { result["parse_errors"].push_back("truncated optional header"); return result; }
    const std::size_t section_count = std::min<std::size_t>(section_count_raw, MAX_SECTIONS);
    result["machine"] = hex_value(machine); result["is_64bit"] = is64; result["compile_time_epoch"] = stamp; result["entry_point_rva"] = entry; result["section_count"] = section_count;
    if (stamp != 0) { std::time_t raw = static_cast<std::time_t>(stamp); std::tm utc{}; if (::gmtime_r(&raw, &utc)) { std::ostringstream time; time << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ"); result["compile_time"] = time.str(); } }
    std::vector<std::pair<std::uint32_t, std::uint32_t>> directories(16, {0, 0});
    const std::size_t dd = opt + (is64 ? 112 : 96);
    for (std::size_t index = 0; index < directories.size(); ++index) { if (dd + index * 8 + 8 <= opt + optional_size) { read_number(data, dd + index * 8, &directories[index].first); read_number(data, dd + index * 8 + 4, &directories[index].second); } }
    std::vector<Section> sections; std::uint64_t max_raw_end = header_size; const std::size_t section_offset = opt + optional_size;
    for (std::size_t index = 0; index < section_count; ++index) {
        if (section_offset > data.size() || index > (data.size() - section_offset) / 40) {
            result["parse_errors"].push_back("truncated_section_table");
            break;
        }
        const std::size_t offset = section_offset + index * 40;
        Section section;
        section.name = ascii_string(data, offset, 8);
        read_number(data, offset + 8, &section.virtual_size);
        read_number(data, offset + 12, &section.virtual_address);
        read_number(data, offset + 16, &section.raw_size);
        read_number(data, offset + 20, &section.raw_offset);
        read_number(data, offset + 36, &section.characteristics);
        section.executable = (section.characteristics & 0x20000000U) != 0;
        section.writable = (section.characteristics & 0x80000000U) != 0;
        if (section.raw_offset < data.size()) {
            const auto sample_size = std::min<std::uint64_t>(
                section.raw_size, std::min<std::uint64_t>(8U * 1024U * 1024U, data.size() - section.raw_offset));
            section.entropy_value = entropy(data, static_cast<std::size_t>(section.raw_offset),
                                            static_cast<std::size_t>(sample_size));
        }
        const std::uint64_t raw_end = section.raw_offset > std::numeric_limits<std::uint64_t>::max() - section.raw_size
                                          ? std::numeric_limits<std::uint64_t>::max()
                                          : section.raw_offset + section.raw_size;
        max_raw_end = std::max(max_raw_end, std::min<std::uint64_t>(data.size(), raw_end));
        sections.push_back(section);
        result["sections"].push_back(section_json(section));
    }
    result["overlay_size"] = data.size() > max_raw_end ? data.size() - max_raw_end : 0;
    auto parse_c_string = [&](std::optional<std::size_t> offset) { return offset ? ascii_string(data, *offset) : std::string{}; };
    const auto parse_imports = [&]() {
        Json imports = Json::array(); const auto [rva, size] = directories[1]; const auto base = rva_to_offset(rva, sections, header_size); if (!base || size == 0) return imports;
        for (std::size_t index = 0; index < MAX_TABLE_ITEMS; ++index) { const std::size_t offset = *base + index * 20; if (offset + 20 > data.size()) break; std::uint32_t original = 0, name_rva = 0, first = 0; read_number(data, offset, &original); read_number(data, offset + 12, &name_rva); read_number(data, offset + 16, &first); if (!(original || name_rva || first)) break; const std::string module = parse_c_string(rva_to_offset(name_rva, sections, header_size)); const std::uint64_t thunk_rva = original ? original : first; const auto thunk = rva_to_offset(thunk_rva, sections, header_size); const std::size_t width = is64 ? 8 : 4; const std::uint64_t ordinal_mask = is64 ? (1ULL << 63U) : (1ULL << 31U); for (std::size_t ti = 0; ti < 128 && thunk && imports.size() < MAX_TABLE_ITEMS; ++ti) { const std::size_t toff = *thunk + ti * width; if (toff + width > data.size()) break; std::uint64_t value = 0; if (is64) read_number(data, toff, &value); else { std::uint32_t low = 0; read_number(data, toff, &low); value = low; } if (value == 0) break; std::string name; if ((value & ordinal_mask) != 0) name = "ordinal:" + std::to_string(value & 0xffffU); else { const auto name_offset = rva_to_offset(value, sections, header_size); if (name_offset && *name_offset + 2 <= data.size()) name = ascii_string(data, *name_offset + 2); } imports.push_back((module + "!" + name).substr(0, 512)); } }
        return imports;
    };
    result["imports"] = parse_imports();
    const auto [exp_rva, exp_size] = directories[0]; if (const auto offset = rva_to_offset(exp_rva, sections, header_size); offset && exp_size && *offset + 40 <= data.size()) { std::uint32_t count = 0, names_rva = 0; read_number(data, *offset + 24, &count); read_number(data, *offset + 32, &names_rva); if (const auto names = rva_to_offset(names_rva, sections, header_size)) for (std::size_t index = 0; index < std::min<std::uint32_t>(count, MAX_TABLE_ITEMS) && *names + index * 4 + 4 <= data.size(); ++index) { std::uint32_t name_rva = 0; read_number(data, *names + index * 4, &name_rva); if (const auto name_offset = rva_to_offset(name_rva, sections, header_size)) result["exports"].push_back(ascii_string(data, *name_offset)); } }
    const auto [resource_rva, resource_size] = directories[2]; const auto [security_offset, security_size] = directories[4]; result["resources"] = Json{{"present", resource_rva != 0 && resource_size != 0}, {"rva", resource_rva}, {"size", resource_size}}; result["certificate_table"] = Json{{"present", security_offset != 0 && security_size != 0 && static_cast<std::uint64_t>(security_offset) + security_size <= data.size()}, {"offset", security_offset}, {"size", security_size}};
    result["parse_status"] = result["parse_errors"].empty() ? "SUCCESS" : "PARTIAL";
    return result;
}

Json parse_elf(const Bytes& data) {
    Json result{{"format", "ELF"}, {"sections", Json::array()}, {"imports", Json::array()}, {"exports", Json::array()}, {"resources", Json::object()}, {"certificate_table", Json{{"present", false}}}, {"parse_status", "PARTIAL"}, {"parse_errors", Json::array()}};
    if (data.size() < 6) { result["parse_errors"].push_back("truncated ELF header"); return result; }
    const unsigned char elf_class = data[4], encoding = data[5]; if ((elf_class != 1 && elf_class != 2) || (encoding != 1 && encoding != 2)) { result["parse_errors"].push_back("unsupported ELF class/encoding"); return result; }
    const bool is64 = elf_class == 2, little = encoding == 1; std::uint64_t entry = 0, section_offset = 0; std::uint16_t section_size = 0, section_count_raw = 0, section_name_index = 0;
    if (data.size() < (is64 ? 64U : 52U)) { result["parse_errors"].push_back("truncated ELF header"); return result; }
    if (is64) { read_number(data, 24, &entry, little); read_number(data, 40, &section_offset, little); read_number(data, 58, &section_size, little); read_number(data, 60, &section_count_raw, little); read_number(data, 62, &section_name_index, little); }
    else { std::uint32_t entry32 = 0, offset32 = 0; read_number(data, 24, &entry32, little); read_number(data, 32, &offset32, little); entry = entry32; section_offset = offset32; read_number(data, 46, &section_size, little); read_number(data, 48, &section_count_raw, little); read_number(data, 50, &section_name_index, little); }
    struct Header { std::uint32_t name = 0, type = 0; std::uint64_t flags = 0, offset = 0, size = 0, link = 0, entry_size = 0; };
    std::size_t section_count = std::min<std::size_t>(section_count_raw, MAX_SECTIONS); std::vector<Header> headers;
    if (section_size < (is64 ? 64U : 40U) || section_offset > data.size()) {
        result["parse_errors"].push_back("invalid_section_table");
        return result;
    }
    const std::size_t available_sections = (data.size() - static_cast<std::size_t>(section_offset)) / section_size;
    if (section_count > available_sections) section_count = available_sections;
    for (std::size_t index = 0; index < section_count; ++index) { const std::uint64_t raw = section_offset + index * section_size; if (raw > data.size() || section_size > data.size() - raw) break; Header header; read_number(data, raw, &header.name, little); read_number(data, raw + 4, &header.type, little); if (is64) { read_number(data, raw + 8, &header.flags, little); read_number(data, raw + 24, &header.offset, little); read_number(data, raw + 32, &header.size, little); read_number(data, raw + 40, &header.link, little); read_number(data, raw + 56, &header.entry_size, little); } else { std::uint32_t flags = 0, offset = 0, size = 0, link = 0, entry_size = 0; read_number(data, raw + 8, &flags, little); read_number(data, raw + 16, &offset, little); read_number(data, raw + 20, &size, little); read_number(data, raw + 24, &link, little); read_number(data, raw + 36, &entry_size, little); header.flags = flags; header.offset = offset; header.size = size; header.link = link; header.entry_size = entry_size; } headers.push_back(header); }
    for (auto& header : headers) {
        if (header.offset > data.size()) header.size = 0;
        else header.size = std::min<std::uint64_t>(header.size, data.size() - header.offset);
    }
    if (is64) {
        for (std::size_t index = 0; index < headers.size(); ++index) {
            const std::uint64_t raw = section_offset + index * section_size;
            std::uint32_t link = 0;
            if (read_number(data, static_cast<std::size_t>(raw) + 40, &link, little)) {
                headers[index].link = link;
            }
        }
    }
    Bytes names; if (section_name_index < headers.size()) { const auto& header = headers[section_name_index]; if (header.offset < data.size()) names.assign(data.begin() + static_cast<std::ptrdiff_t>(header.offset), data.begin() + static_cast<std::ptrdiff_t>(std::min<std::uint64_t>(data.size(), header.offset + header.size))); }
    auto name_at = [&](const Bytes& source, std::uint64_t offset) { return offset < source.size() ? ascii_string(source, static_cast<std::size_t>(offset), 256) : std::string{}; };
    for (const auto& header : headers) { const std::string name = name_at(names, header.name); Json section{{"name", name}, {"type", header.type}, {"raw_offset", header.offset}, {"raw_size", header.size}, {"flags", hex_value(header.flags)}, {"entropy", header.offset < data.size() ? entropy(data, static_cast<std::size_t>(header.offset), static_cast<std::size_t>(std::min<std::uint64_t>(header.size, 8U * 1024U * 1024U))) : 0.0}, {"executable", (header.flags & 4U) != 0}, {"writable", (header.flags & 1U) != 0}}; result["sections"].push_back(section); }
    std::vector<std::string> imported, exported;
    for (const auto& header : headers) { if ((header.type != 2 && header.type != 11) || header.link >= headers.size()) continue; const auto& string_header = headers[header.link]; Bytes string_data; if (string_header.offset < data.size()) string_data.assign(data.begin() + static_cast<std::ptrdiff_t>(string_header.offset), data.begin() + static_cast<std::ptrdiff_t>(std::min<std::uint64_t>(data.size(), string_header.offset + string_header.size))); const std::uint64_t entry_size = header.entry_size ? header.entry_size : (is64 ? 24 : 16); if (entry_size < (is64 ? 24 : 16) || header.offset >= data.size()) continue; const std::uint64_t count = std::min<std::uint64_t>(MAX_TABLE_ITEMS * 4, header.size / entry_size); for (std::uint64_t index = 0; index < count; ++index) { const std::uint64_t offset = header.offset + index * entry_size; if (offset + entry_size > data.size()) break; std::uint32_t name_index = 0; read_number(data, static_cast<std::size_t>(offset), &name_index, little); const unsigned char info = data[static_cast<std::size_t>(offset + (is64 ? 4 : 12))]; std::uint16_t shndx = 0; read_number(data, static_cast<std::size_t>(offset + (is64 ? 6 : 14)), &shndx, little); const std::string name = name_at(string_data, name_index); if (name.empty() || (info >> 4U) == 0) continue; if (shndx == 0 && imported.size() < MAX_TABLE_ITEMS) imported.push_back(name); else if (shndx != 0 && exported.size() < MAX_TABLE_ITEMS) exported.push_back(name); } }
    std::sort(imported.begin(), imported.end()); imported.erase(std::unique(imported.begin(), imported.end()), imported.end()); std::sort(exported.begin(), exported.end()); exported.erase(std::unique(exported.begin(), exported.end()), exported.end()); result["imports"] = std::vector<std::string>(imported.begin(), imported.begin() + static_cast<std::ptrdiff_t>(std::min<std::size_t>(MAX_TABLE_ITEMS, imported.size()))); result["exports"] = std::vector<std::string>(exported.begin(), exported.begin() + static_cast<std::ptrdiff_t>(std::min<std::size_t>(MAX_TABLE_ITEMS, exported.size())));
    std::uint16_t machine = 0; read_number(data, 18, &machine, little); result["is_64bit"] = is64; result["machine"] = hex_value(machine); result["entry_point"] = entry; result["section_count"] = result["sections"].size(); result["signature_status"] = "NOT_APPLICABLE_PACKAGE_TRUST_REQUIRED"; result["parse_status"] = "SUCCESS";
    return result;
}

std::vector<std::string> path_anomalies(const std::string& path) {
    std::string lower_path = path; std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); }); std::replace(lower_path.begin(), lower_path.end(), '/', '\\'); std::vector<std::string> values; const std::regex temporary(R"((\\temp\\|\\tmp\\|\\appdata\\|\\downloads\\|\\users\\public\\|/tmp/|/var/tmp/|/dev/shm/))", std::regex::icase); if (std::regex_search(lower_path, temporary)) values.push_back("user_or_temporary_execution_location"); const std::string base = lower_path.substr(lower_path.find_last_of("\\/") + 1); const std::set<std::string> system_names{"svchost.exe", "services.exe", "lsass.exe", "winlogon.exe", "explorer.exe"}; if (system_names.count(base) && lower_path.find("\\windows\\system32\\") == std::string::npos) values.push_back("system_name_outside_system_directory"); return values;
}

std::string digest_hex(EVP_MD_CTX* context, const EVP_MD* algorithm, const Bytes& data, unsigned char* raw, unsigned* length) {
    if (!context || !algorithm || EVP_DigestInit_ex(context, algorithm, nullptr) != 1 || EVP_DigestUpdate(context, data.data(), data.size()) != 1 || EVP_DigestFinal_ex(context, raw, length) != 1) return {};
    std::ostringstream output; output << std::hex << std::setfill('0'); for (unsigned index = 0; index < *length; ++index) output << std::setw(2) << static_cast<unsigned>(raw[index]); return output.str();
}

[[maybe_unused]] bool read_and_hash_legacy(const std::string& path, std::uint64_t max_bytes, Bytes* captured, std::string* sha, std::string* md5, struct stat* before, struct stat* after) {
    if (::lstat(path.c_str(), before) != 0 || !S_ISREG(before->st_mode) || S_ISLNK(before->st_mode)) return false;
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW); if (fd < 0) return false;
    EVP_MD_CTX* sha_context = EVP_MD_CTX_new(); EVP_MD_CTX* md5_context = EVP_MD_CTX_new(); if (!sha_context || !md5_context) { if (sha_context) EVP_MD_CTX_free(sha_context); if (md5_context) EVP_MD_CTX_free(md5_context); ::close(fd); return false; }
    if (EVP_DigestInit_ex(sha_context, EVP_sha256(), nullptr) != 1 || EVP_DigestInit_ex(md5_context, EVP_md5(), nullptr) != 1) { EVP_MD_CTX_free(sha_context); EVP_MD_CTX_free(md5_context); ::close(fd); return false; }
    captured->clear(); captured->reserve(static_cast<std::size_t>(std::min<std::uint64_t>(max_bytes, 64U * 1024U * 1024U))); std::array<unsigned char, 1024 * 1024> buffer{}; std::uint64_t total = 0;
    while (true) { const ssize_t count = ::read(fd, buffer.data(), buffer.size()); if (count == 0) break; if (count < 0) { if (errno == EINTR) continue; EVP_MD_CTX_free(sha_context); EVP_MD_CTX_free(md5_context); ::close(fd); return false; } EVP_DigestUpdate(sha_context, buffer.data(), static_cast<std::size_t>(count)); EVP_DigestUpdate(md5_context, buffer.data(), static_cast<std::size_t>(count)); const std::uint64_t room = max_bytes > total ? max_bytes - total : 0; if (room > 0) captured->insert(captured->end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(std::min<std::uint64_t>(room, static_cast<std::uint64_t>(count)))); total += static_cast<std::uint64_t>(count); }
    ::close(fd); unsigned char sha_raw[EVP_MAX_MD_SIZE]{}, md5_raw[EVP_MAX_MD_SIZE]{}; unsigned sha_len = 0, md5_len = 0; if (EVP_DigestFinal_ex(sha_context, sha_raw, &sha_len) != 1 || EVP_DigestFinal_ex(md5_context, md5_raw, &md5_len) != 1) { EVP_MD_CTX_free(sha_context); EVP_MD_CTX_free(md5_context); return false; } EVP_MD_CTX_free(sha_context); EVP_MD_CTX_free(md5_context); auto format = [](const unsigned char* raw, unsigned length) { std::ostringstream output; output << std::hex << std::setfill('0'); for (unsigned index = 0; index < length; ++index) output << std::setw(2) << static_cast<unsigned>(raw[index]); return output.str(); }; *sha = format(sha_raw, sha_len); *md5 = format(md5_raw, md5_len); if (::lstat(path.c_str(), after) != 0) return false; return before->st_dev == after->st_dev && before->st_ino == after->st_ino && before->st_size == after->st_size && before->st_mtime == after->st_mtime;
}

bool same_binary_file_version(const struct stat& left, const struct stat& right) {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
           left.st_size == right.st_size &&
           left.st_mtim.tv_sec == right.st_mtim.tv_sec &&
           left.st_mtim.tv_nsec == right.st_mtim.tv_nsec;
}

bool read_and_hash(const std::string& path, std::uint64_t max_bytes, Bytes* captured, std::string* sha, std::string* md5, struct stat* before, struct stat* after) {
    if (!captured || !sha || !md5 || !before || !after || ::lstat(path.c_str(), before) != 0 ||
        !S_ISREG(before->st_mode) || S_ISLNK(before->st_mode)) return false;
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat opened{};
    if (::fstat(fd, &opened) != 0 || !same_binary_file_version(*before, opened)) {
        ::close(fd);
        return false;
    }
    EVP_MD_CTX* sha_context = EVP_MD_CTX_new();
    EVP_MD_CTX* md5_context = EVP_MD_CTX_new();
    if (!sha_context || !md5_context) {
        if (sha_context) EVP_MD_CTX_free(sha_context);
        if (md5_context) EVP_MD_CTX_free(md5_context);
        ::close(fd);
        return false;
    }
    const bool initialized = EVP_DigestInit_ex(sha_context, EVP_sha256(), nullptr) == 1 &&
                             EVP_DigestInit_ex(md5_context, EVP_md5(), nullptr) == 1;
    if (!initialized) {
        EVP_MD_CTX_free(sha_context);
        EVP_MD_CTX_free(md5_context);
        ::close(fd);
        return false;
    }
    captured->clear();
    captured->reserve(static_cast<std::size_t>(std::min<std::uint64_t>(max_bytes, 64U * 1024U * 1024U)));
    std::array<unsigned char, 1024 * 1024> buffer{};
    std::uint64_t total = 0;
    bool failed = false;
    while (true) {
        const ssize_t count = ::read(fd, buffer.data(), buffer.size());
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            failed = true;
            break;
        }
        const std::size_t bytes = static_cast<std::size_t>(count);
        if (EVP_DigestUpdate(sha_context, buffer.data(), bytes) != 1 ||
            EVP_DigestUpdate(md5_context, buffer.data(), bytes) != 1) {
            failed = true;
            break;
        }
        const std::uint64_t room = max_bytes > total ? max_bytes - total : 0;
        if (room != 0) {
            const std::size_t copy_count = static_cast<std::size_t>(
                std::min<std::uint64_t>(room, static_cast<std::uint64_t>(bytes)));
            captured->insert(captured->end(), buffer.begin(),
                             buffer.begin() + static_cast<std::ptrdiff_t>(copy_count));
        }
        total += static_cast<std::uint64_t>(bytes);
    }
    struct stat after_fd{};
    const bool fd_ok = ::fstat(fd, &after_fd) == 0;
    const bool path_ok = ::lstat(path.c_str(), after) == 0;
    ::close(fd);
    unsigned char sha_raw[EVP_MAX_MD_SIZE]{};
    unsigned char md5_raw[EVP_MAX_MD_SIZE]{};
    unsigned sha_len = 0;
    unsigned md5_len = 0;
    const bool finalized = !failed && fd_ok && path_ok &&
                           EVP_DigestFinal_ex(sha_context, sha_raw, &sha_len) == 1 &&
                           EVP_DigestFinal_ex(md5_context, md5_raw, &md5_len) == 1;
    EVP_MD_CTX_free(sha_context);
    EVP_MD_CTX_free(md5_context);
    if (!finalized || !same_binary_file_version(*before, after_fd) ||
        !same_binary_file_version(*before, *after)) return false;
    auto format = [](const unsigned char* raw, unsigned length) {
        std::ostringstream output;
        output << std::hex << std::setfill('0');
        for (unsigned index = 0; index < length; ++index) output << std::setw(2) << static_cast<unsigned>(raw[index]);
        return output.str();
    };
    *sha = format(sha_raw, sha_len);
    *md5 = format(md5_raw, md5_len);
    return true;
}

Json analyze_path(const std::string& path, std::uint64_t max_bytes) {
    struct stat before{}, after{}; Bytes data; std::string sha, md5; if (!read_and_hash(path, max_bytes, &data, &sha, &md5, &before, &after)) return Json{{"file_path", path}, {"parse_status", "ERROR"}, {"error", "TOCTOU_CHANGED"}, {"verdict", "UNKNOWN"}};
    Json parsed; if (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z') parsed = parse_pe(data); else if (data.size() >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') parsed = parse_elf(data); else return Json();
    Json strings = extract_strings(data); std::vector<std::string> imports; for (const auto& value : parsed["imports"]) { const std::string item = value.get<std::string>(); imports.push_back(item.substr(item.find_last_of('!') + 1)); } const Json combos = api_combinations(imports, strings); std::vector<std::string> anomalies = path_anomalies(path); for (const auto& section : parsed["sections"]) if (section.value("raw_size", 0ULL) >= 512 && section.value("entropy", 0.0) >= 7.2) { anomalies.push_back("high_entropy_sections"); break; } if (parsed.value("overlay_size", 0ULL) >= 4096) anomalies.push_back("overlay_data"); const std::regex packer(R"((upx|aspack|themida|vmp|packed))", std::regex::icase); for (const auto& section : parsed["sections"]) if (std::regex_search(section.value("name", ""), packer)) { anomalies.push_back("packer_section_name"); break; }
    if (parsed.value("format", "") == "PE" && parsed.value("entry_point_rva", 0U) != 0) { bool in_exec = false; for (const auto& section : parsed["sections"]) if (section.value("executable", false)) { const std::uint64_t start = section.value("virtual_address", 0ULL); const std::uint64_t end = start + std::max(section.value("virtual_size", 0ULL), section.value("raw_size", 0ULL)); if (parsed["entry_point_rva"].get<std::uint64_t>() >= start && parsed["entry_point_rva"].get<std::uint64_t>() < end) in_exec = true; } if (!in_exec) anomalies.push_back("entry_point_outside_executable_section"); }
    const std::uint64_t stamp = parsed.value("compile_time_epoch", 0ULL); const auto now = static_cast<std::uint64_t>(std::time(nullptr)); if (stamp != 0 && (stamp > now + 86400 || stamp < 315532800)) anomalies.push_back("implausible_compile_time"); std::sort(anomalies.begin(), anomalies.end()); anomalies.erase(std::unique(anomalies.begin(), anomalies.end()), anomalies.end()); int score = 0; for (const auto& combo : combos) score += combo.value("risk", 0); score = std::min(100, score + std::min(20, 4 * static_cast<int>(anomalies.size()))); if (combos.empty()) score = std::min(score, 24);
    std::ostringstream mode; mode << "0o" << std::oct << (before.st_mode & 07777); parsed["detector"] = "SecScope.BinaryAnalyzer"; parsed["detector_version"] = VERSION; parsed["file_path"] = absolute_lexical_path(path); parsed["file_hash"] = sha; parsed["sha256"] = sha; parsed["md5"] = md5; parsed["file_size"] = before.st_size; parsed["bytes_parsed"] = data.size(); parsed["mode"] = mode.str(); parsed["created_time"] = before.st_ctime; parsed["modified_time"] = before.st_mtime; parsed["accessed_time"] = before.st_atime; parsed["device"] = before.st_dev; parsed["inode"] = before.st_ino; parsed["signature_status"] = parsed.value("signature_status", parsed.value("certificate_table", Json()).value("present", false) ? "PRESENT_UNVERIFIED" : "NOT_PRESENT"); parsed["publisher"] = ""; parsed["product_name"] = ""; parsed["company_name"] = ""; parsed["version_info"] = ""; parsed["strings"] = strings; parsed["api_combinations"] = combos; parsed["structural_anomalies"] = anomalies; parsed["risk_score"] = score; parsed["finding_type"] = score ? "SECURITY_ANOMALY" : "OBSERVATION"; parsed["malware_family"] = "UNDETERMINED"; parsed["verdict"] = "NOT_CLASSIFIED_AS_MALWARE"; parsed["evidence_domains"] = Json::array({"FILE"}); parsed["visibility_gaps"] = Json::array({"signature publisher and package trust require platform enrichment"}); return parsed;
}

}

int run_binary_analyzer(const Arguments& args) {
    std::string error; if (!required_arguments(args, {"--input-list", "--output-jsonl"}, &error)) { std::cerr << error << '\n'; return 2; }
    std::ifstream input(argument(args, "--input-list")); AtomicOutput output(argument(args, "--output-jsonl")); const std::string projection_path = argument(args, "--projection-tsv"); std::unique_ptr<AtomicOutput> projection; if (!projection_path.empty()) projection = std::make_unique<AtomicOutput>(projection_path); if (!input || !output.good() || (projection && !projection->good())) { std::cerr << "cannot open binary analyzer input/output\n"; return 2; }
    const std::size_t max_files = static_cast<std::size_t>(uint_argument(args, "--max-files", 800, 1, 10000)); const std::uint64_t max_bytes = uint_argument(args, "--max-bytes", 32U * 1024U * 1024U, 4096, 256U * 1024U * 1024U); const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(uint_argument(args, "--timeout-seconds", 120, 1, 3600)); std::size_t scanned = 0, skipped = 0, errors = 0; if (projection) projection->stream() << "file_path\tformat\tsha256\tmd5\tsignature_status\trisk_score\tapi_combinations\tstructural_anomalies\n";
    std::string line; while (std::getline(input, line) && scanned < max_files && std::chrono::steady_clock::now() < deadline) { line = trim_line(std::move(line)); if (line.empty()) continue; Json result = analyze_path(line, max_bytes); if (result.empty()) { ++skipped; continue; } if (result.value("parse_status", "") == "ERROR") ++errors; output.stream() << safe_json_dump(result) << '\n'; if (projection && result.contains("file_path")) { auto list_cell = [](const Json& value) { std::string result; if (value.is_array()) { for (std::size_t index = 0; index < value.size(); ++index) { if (index) result += ','; result += value[index].is_object() ? value[index].value("name", "") : value[index].get<std::string>(); } } else result = value.is_string() ? value.get<std::string>() : safe_json_dump(value); return clean_cell(result); }; projection->stream() << clean_cell(result.value("file_path", "")) << '\t' << clean_cell(result.value("format", "")) << '\t' << clean_cell(result.value("sha256", "")) << '\t' << clean_cell(result.value("md5", "")) << '\t' << clean_cell(result.value("signature_status", "")) << '\t' << result.value("risk_score", 0) << '\t' << list_cell(result.value("api_combinations", Json::array())) << '\t' << list_cell(result.value("structural_anomalies", Json::array())) << '\n'; } ++scanned; }
    const bool limited = scanned >= max_files || std::chrono::steady_clock::now() >= deadline; const Json summary{{"summary", true}, {"status", limited || errors ? "PARTIAL" : "SUCCESS"}, {"scanned", scanned}, {"skipped_non_binary", skipped}, {"errors", errors}, {"max_files", max_files}, {"timed_out", std::chrono::steady_clock::now() >= deadline}}; output.stream() << safe_json_dump(summary) << '\n'; const Json status{{"status", limited || errors ? "PARTIAL" : "SUCCESS"}, {"scanned", scanned}, {"errors", errors}}; std::cout << safe_json_dump(status) << '\n'; if (!output.commit() || (projection && !projection->commit())) return 2; return 0;
}

}
