#include "static_analyzer.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <limits>
#include <map>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_set>
#include <vector>
#include <zlib.h>

#include <archive.h>
#include <archive_entry.h>

namespace secscope {
namespace {

using Json = nlohmann::json;
using Bytes = std::vector<unsigned char>;
constexpr const char* VERSION = "1.0";
constexpr std::size_t TEXT_LIMIT = 2U * 1024U * 1024U;
constexpr std::size_t LONG_LINE_LIMIT = 32768;

struct PatternGroup { const char* name; std::vector<const char*> patterns; };
const std::vector<PatternGroup> CAPABILITY_PATTERNS = {
    {"external_input", {R"(\$_(?:GET|POST|COOKIE|REQUEST|FILES|SERVER))", R"(php://input)", R"(Request\.(?:Form|QueryString|Cookies|InputStream))", R"(getParameter\s*\()", R"(getInputStream\s*\()", R"(HttpServletRequest)", R"(req\.(?:body|query|params|headers))", R"(request\.(?:args|form|data|json|cookies))", R"(sys\.stdin)"}},
    {"decode_transform", {R"(base64_(?:decode|url_decode))", R"(FromBase64String)", R"(Base64\.(?:getDecoder|getUrlDecoder))", R"(atob\s*\()", R"(gzinflate|gzuncompress|gzdecode|DeflateStream|GZipStream)", R"(str_rot13)", R"(urldecode|decodeURIComponent)", R"((?:xor|\^)\s*(?:0x[0-9a-f]+|\d+))", R"(chr\s*\()", R"(String\.fromCharCode)", R"(bytes\.fromhex)"}},
    {"dynamic_code", {R"(\beval\s*\()", R"(\bassert\s*\()", R"(create_function\s*\()", R"(call_user_func(?:_array)?\s*\()", R"(ClassLoader.{0,80}defineClass)", R"(MethodHandles(?:\.Lookup)?.{0,80}defineClass)", R"(Unsafe.{0,80}defineClass)", R"(Instrumentation.{0,80}(?:redefineClasses|retransformClasses))", R"(Assembly\.Load\s*\()", R"(Reflection\.Emit)", R"(DynamicMethod\s*\()", R"(new\s+Function\s*\()", R"(\bvm\.(?:runIn|runInNewContext|compileFunction))", R"(\bexec\s*\()", R"(\bcompile\s*\()"}},
    {"command_execution", {R"(\b(?:system|exec|shell_exec|passthru|proc_open|popen)\s*\()", R"(Runtime\.getRuntime\s*\(\)\.exec)", R"(new\s+ProcessBuilder)", R"(Process\.Start\s*\()", R"(System\.Diagnostics\.Process)", R"(child_process\.(?:exec|execFile|spawn|fork))", R"(subprocess\.(?:Popen|run|call|check_output))", R"(os\.system\s*\()", R"(powershell(?:\.exe)?\s+-)"}},
    {"dynamic_load", {R"(\b(?:include|include_once|require|require_once)\s*\(?\s*\$)", R"(Class\.forName\s*\()", R"(Method\.invoke\s*\()", R"(Assembly\.LoadFrom|AssemblyLoadContext)", R"(require\s*\(\s*[^'\"])", R"(importlib\.|__import__\s*\()", R"(require\.cache)", R"(sys\.modules\s*\[)"}},
    {"web_registration", {R"(addServlet\s*\()", R"(addFilter\s*\()", R"(addListener\s*\()", R"(addMappingForUrlPatterns)", R"(StandardContext)", R"(\bValve\b|addValve\s*\()", R"(HandlerMapping|HandlerInterceptor|adaptedInterceptors)", R"(ServerEndpointConfig|addEndpoint\s*\()", R"(RegisterModule|IHttpModule|IHttpHandler|HttpApplication)", R"(buildProviders|preloadEnabled)"}},
    {"reflection", {R"(Reflection(?:Method|Function))", R"(Class\.forName)", R"(Method\.invoke)", R"(getDeclaredMethod)", R"(setAccessible\s*\()", R"(System\.Reflection)", R"(Activator\.CreateInstance)", R"(getattr\s*\()", R"(globals\s*\()"}},
    {"file_write", {R"(file_put_contents\s*\()", R"(fwrite\s*\()", R"(Files\.write)", R"(FileOutputStream)", R"(WriteAllBytes|WriteAllText)", R"(fs\.(?:writeFile|appendFile|createWriteStream))", R"(open\s*\([^\n]{0,120}['\"](?:w|a|x)b?['\"])"}},
    {"network", {R"(fsockopen|stream_socket_client|curl_exec)", R"(java\.net\.(?:Socket|URL|HttpURLConnection))", R"(HttpClient)", R"(System\.Net\.(?:Sockets|WebClient|HttpClient))", R"(net\.(?:connect|createConnection)|http\.request)", R"(socket\.socket|requests\.(?:get|post))"}},
    {"deserialization", {R"(unserialize\s*\()", R"(ObjectInputStream)", R"(BinaryFormatter|LosFormatter|ObjectStateFormatter|NetDataContractSerializer)", R"(pickle\.loads?\s*\()", R"(yaml\.load\s*\()"}},
    {"encrypted_protocol", {R"(openssl_decrypt|sodium_crypto|mcrypt_decrypt)", R"(Cipher\.getInstance)", R"(AesManaged|AesCryptoServiceProvider)", R"(createDecipheriv|crypto\.subtle\.decrypt)", R"(Fernet\s*\()"}},
    {"jmx_rmi", {R"(MBeanServer|registerMBean)", R"(javax\.management)", R"(LocateRegistry|UnicastRemoteObject|java\.rmi)"}},
    {"viewstate", {R"(__VIEWSTATE)", R"(ViewState)", R"(MachineKey|machineKey)", R"(enableViewStateMac\s*=\s*['\"]?false)"}}
};
const std::vector<PatternGroup> COUNTER_PATTERNS = {
    {"generated_class_framework", {R"(CGLIB|EnhancerByCGLIB|ByteBuddy|net\.bytebuddy|\$\$Lambda\$|jdk\.internal\.reflect)"}},
    {"test_or_mock", {R"((^|[/\\])(test|tests|fixture|fixtures|mock|mocks)([/\\]|$))", R"(@Test\b|pytest|unittest)"}},
    {"framework_bootstrap", {R"(SpringApplication\.run)", R"(Laravel|WordPress|ThinkPHP)", R"(Microsoft\.AspNetCore)"}}
};

std::string sha256(const Bytes& data) {
    EVP_MD_CTX* context = EVP_MD_CTX_new(); if (!context) return {};
    std::array<unsigned char, EVP_MAX_MD_SIZE> raw{}; unsigned length = 0;
    const bool ok = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1 && EVP_DigestUpdate(context, data.data(), data.size()) == 1 && EVP_DigestFinal_ex(context, raw.data(), &length) == 1;
    EVP_MD_CTX_free(context); if (!ok) return {};
    std::ostringstream output; output << std::hex << std::setfill('0'); for (unsigned index = 0; index < length; ++index) output << std::setw(2) << static_cast<unsigned>(raw[index]); return output.str();
}

std::string lower(std::string value) { std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); }); return value; }

std::string detect_encoding(const Bytes& data) { if (data.size() >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf) return "utf-8-sig"; if (data.size() >= 2 && data[0] == 0xff && data[1] == 0xfe) return "utf-16-le"; if (data.size() >= 2 && data[0] == 0xfe && data[1] == 0xff) return "utf-16-be"; return "utf-8"; }

std::string text_from_bytes(const Bytes& data, std::string* encoding) {
    *encoding = detect_encoding(data); std::string result;
    if (*encoding == "utf-16-le" || *encoding == "utf-16-be") {
        const bool little = *encoding == "utf-16-le"; const std::size_t start = 2; result.reserve((data.size() - start) / 2);
        for (std::size_t index = start; index + 1 < data.size(); index += 2) { const std::uint16_t value = little ? static_cast<std::uint16_t>(data[index] | (data[index + 1] << 8U)) : static_cast<std::uint16_t>((data[index] << 8U) | data[index + 1]); if (value < 0x80) result.push_back(static_cast<char>(value)); else if (value < 0x800) { result.push_back(static_cast<char>(0xc0 | (value >> 6U))); result.push_back(static_cast<char>(0x80 | (value & 0x3fU))); } else { result.push_back(static_cast<char>(0xe0 | (value >> 12U))); result.push_back(static_cast<char>(0x80 | ((value >> 6U) & 0x3fU))); result.push_back(static_cast<char>(0x80 | (value & 0x3fU))); } }
    } else { const std::size_t start = *encoding == "utf-8-sig" ? 3 : 0; result.assign(data.begin() + static_cast<std::ptrdiff_t>(std::min(start, data.size())), data.end()); }
    std::string bounded; std::size_t lines = 0, line_start = 0;
    while (line_start <= result.size() && lines < 50000 && bounded.size() < TEXT_LIMIT) { const auto end = result.find('\n', line_start); const std::size_t line_end = end == std::string::npos ? result.size() : end; const std::size_t length = std::min<std::size_t>(LONG_LINE_LIMIT, line_end - line_start); bounded.append(result, line_start, length); bounded.push_back('\n'); ++lines; if (end == std::string::npos) break; line_start = end + 1; }
    if (bounded.size() > TEXT_LIMIT) bounded.resize(TEXT_LIMIT);
    return bounded;
}

Bytes base64_decode(const std::string& value) {
    static const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (value.empty() || value.size() % 4 != 0) return {};
    std::size_t padding = 0;
    while (padding < value.size() && value[value.size() - 1 - padding] == '=') ++padding;
    if (padding > 2 || (padding > 0 && value.size() <= padding)) return {};
    for (std::size_t index = 0; index + padding < value.size(); ++index) {
        if (alphabet.find(value[index]) == std::string::npos) return {};
    }
    for (std::size_t index = value.size() - padding; index < value.size(); ++index) {
        if (value[index] != '=') return {};
    }
    Bytes result;
    result.reserve((value.size() / 4) * 3 - padding);
    for (std::size_t index = 0; index < value.size(); index += 4) {
        const auto first = alphabet.find(value[index]);
        const auto second = alphabet.find(value[index + 1]);
        if (first == std::string::npos || second == std::string::npos) return {};
        const bool third_padding = value[index + 2] == '=';
        const bool fourth_padding = value[index + 3] == '=';
        if (third_padding && !fourth_padding) return {};
        if ((third_padding || fourth_padding) && index + 4 != value.size()) return {};
        const auto third = third_padding ? 0U : alphabet.find(value[index + 2]);
        const auto fourth = fourth_padding ? 0U : alphabet.find(value[index + 3]);
        if (third == std::string::npos || fourth == std::string::npos) return {};
        result.push_back(static_cast<unsigned char>((first << 2U) | (second >> 4U)));
        if (!third_padding) result.push_back(static_cast<unsigned char>((second << 4U) | (third >> 2U)));
        if (!fourth_padding) result.push_back(static_cast<unsigned char>((third << 6U) | fourth));
    }
    return result;
}

Bytes hex_decode(const std::string& value) { if (value.size() % 2 != 0) return {}; Bytes result; result.reserve(value.size() / 2); auto digit = [](char c) -> int { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; if (c >= 'A' && c <= 'F') return c - 'A' + 10; return -1; }; for (std::size_t index = 0; index < value.size(); index += 2) { const int high = digit(value[index]), low = digit(value[index + 1]); if (high < 0 || low < 0) return {}; result.push_back(static_cast<unsigned char>((high << 4) | low)); } return result; }

Bytes inflate_bytes(const Bytes& input, int window_bits, std::size_t limit) {
    z_stream stream{}; if (inflateInit2(&stream, window_bits) != Z_OK) return {}; stream.next_in = const_cast<Bytef*>(input.data()); stream.avail_in = static_cast<uInt>(std::min<std::size_t>(input.size(), std::numeric_limits<uInt>::max())); Bytes result; std::array<unsigned char, 64 * 1024> buffer{}; int status = Z_OK;
    while (status == Z_OK && result.size() <= limit) { stream.next_out = buffer.data(); stream.avail_out = buffer.size(); status = inflate(&stream, Z_NO_FLUSH); const std::size_t produced = buffer.size() - stream.avail_out; if (result.size() + produced > limit) { inflateEnd(&stream); return {}; } result.insert(result.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(produced)); if (stream.avail_in == 0 && status == Z_OK) break; }
    inflateEnd(&stream); return status == Z_STREAM_END ? result : Bytes{};
}

std::string url_decode(const std::string& value, Bytes* bytes) { Bytes result; for (std::size_t index = 0; index < value.size(); ++index) { if (value[index] == '%' && index + 2 < value.size()) { auto digit = [](char c) -> int { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; if (c >= 'A' && c <= 'F') return c - 'A' + 10; return -1; }; const int high = digit(value[index + 1]), low = digit(value[index + 2]); if (high >= 0 && low >= 0) { result.push_back(static_cast<unsigned char>((high << 4) | low)); index += 2; continue; } } result.push_back(static_cast<unsigned char>(value[index])); } *bytes = std::move(result); return std::string(bytes->begin(), bytes->end()); }

std::string rot13(std::string value) { for (char& c : value) { if (c >= 'a' && c <= 'z') c = static_cast<char>('a' + (c - 'a' + 13) % 26); else if (c >= 'A' && c <= 'Z') c = static_cast<char>('A' + (c - 'A' + 13) % 26); } return value; }

[[maybe_unused]] std::vector<std::pair<std::string, std::string>> decode_layers_legacy(const std::string& text, unsigned max_depth, std::size_t max_decoded_bytes, double ratio_limit) {
    std::vector<std::pair<std::string, std::string>> layers{{"normalized_text", text}}; std::unordered_set<std::string> seen{sha256(Bytes(text.begin(), text.end()))}; std::size_t total = text.size(); const std::regex base64_re(R"(([A-Za-z0-9+/]{40,}={0,2}))", std::regex::optimize); const std::regex hex_re(R"(((?:[0-9a-f]{2}){24,}))", std::regex::icase | std::regex::optimize);
    for (unsigned depth = 0; depth < max_depth; ++depth) { std::vector<std::pair<std::string, Bytes>> produced; const std::size_t start = layers.size() > 8 ? layers.size() - 8 : 0; for (std::size_t layer = start; layer < layers.size(); ++layer) { const std::string& value = layers[layer].second; for (std::sregex_iterator iterator(value.begin(), value.end(), base64_re), end; iterator != end; ++iterator) { Bytes decoded = base64_decode((*iterator)[1].str()); if (!decoded.empty() && decoded.size() <= max_decoded_bytes) produced.emplace_back("base64(depth=" + std::to_string(depth + 1) + ")", std::move(decoded)); } for (std::sregex_iterator iterator(value.begin(), value.end(), hex_re), end; iterator != end; ++iterator) { Bytes decoded = hex_decode((*iterator)[1].str()); if (!decoded.empty() && decoded.size() <= max_decoded_bytes) produced.emplace_back("hex(depth=" + std::to_string(depth + 1) + ")", std::move(decoded)); } if (value.find('%') != std::string::npos) { Bytes decoded; url_decode(value.substr(0, max_decoded_bytes), &decoded); if (decoded != Bytes(value.begin(), value.begin() + static_cast<std::ptrdiff_t>(std::min(value.size(), max_decoded_bytes)))) produced.emplace_back("url(depth=" + std::to_string(depth + 1) + ")", std::move(decoded)); } if (lower(value).find("str_rot13") != std::string::npos) { const std::string decoded = rot13(value.substr(0, max_decoded_bytes)); produced.emplace_back("rot13(depth=" + std::to_string(depth + 1) + ")", Bytes(decoded.begin(), decoded.end())); } }
        std::size_t added = 0; for (auto& item : produced) { std::vector<std::pair<std::string, Bytes>> candidates; candidates.push_back(std::move(item)); if (candidates.back().second.size() >= 2 && candidates.back().second[0] == 0x1f && candidates.back().second[1] == 0x8b) { Bytes decoded = inflate_bytes(candidates.back().second, 16 + MAX_WBITS, max_decoded_bytes); if (!decoded.empty()) candidates.emplace_back("gzip(depth=" + std::to_string(depth + 1) + ")", std::move(decoded)); } else { Bytes decoded = inflate_bytes(candidates.back().second, MAX_WBITS, max_decoded_bytes); if (!decoded.empty()) candidates.emplace_back("deflate(depth=" + std::to_string(depth + 1) + ")", std::move(decoded)); decoded = inflate_bytes(candidates.front().second, -MAX_WBITS, max_decoded_bytes); if (!decoded.empty()) candidates.emplace_back("deflate(depth=" + std::to_string(depth + 1) + ")", std::move(decoded)); } for (auto& candidate : candidates) { if (candidate.second.empty() || candidate.second.size() > max_decoded_bytes || total + candidate.second.size() > max_decoded_bytes) continue; if (candidate.first.rfind("gzip(", 0) == 0 || candidate.first.rfind("deflate(", 0) == 0) if (candidate.first.size() > 0 && produced.size() > 0 && candidate.second.size() > static_cast<std::size_t>(ratio_limit * std::max<std::size_t>(1, candidate.second.size()))) continue; const std::string digest = sha256(candidate.second); if (!seen.insert(digest).second) continue; std::string encoding; const std::string decoded = text_from_bytes(candidate.second, &encoding); layers.emplace_back(candidate.first, decoded); total += candidate.second.size(); ++added; } } if (added == 0) break; }
    return layers;
}

std::string fold_literals(std::string value) {
    const std::regex concatenation(
        R"((['"])([^'"\r\n]{1,120})\1\s*(?:\.|\+)\s*(['"])([^'"\r\n]{1,120})\3)",
        std::regex::ECMAScript | std::regex::optimize);
    for (unsigned pass = 0; pass < 3; ++pass) {
        const std::string folded = std::regex_replace(value, concatenation, "$1$2$4$3");
        if (folded == value) break;
        value = folded;
    }
    return value;
}

std::vector<std::pair<std::string, std::string>> decode_layers(const std::string& text, unsigned max_depth, std::size_t max_decoded_bytes, double ratio_limit) {
    struct Candidate {
        std::string label;
        Bytes bytes;
        bool decompressed = false;
        std::size_t compressed_size = 0;
    };
    std::vector<std::pair<std::string, std::string>> layers{{"normalized_text", text}};
    std::unordered_set<std::string> seen{sha256(Bytes(text.begin(), text.end()))};
    std::size_t total = text.size();
    const std::regex base64_re(R"(([A-Za-z0-9+/]{40,}={0,2}))", std::regex::ECMAScript | std::regex::optimize);
    const std::regex hex_re(R"(((?:[0-9a-f]{2}){24,}))", std::regex::ECMAScript | std::regex::icase | std::regex::optimize);
    const auto base64_boundary = [](const std::string& value, const std::smatch& match) {
        const auto position = match.position(1);
        if (position < 0) return false;
        const std::size_t begin = static_cast<std::size_t>(position);
        const std::size_t end = begin + match.length(1);
        const auto member = [](unsigned char c) { return std::isalnum(c) != 0 || c == '+' || c == '/' || c == '='; };
        return (begin == 0 || !member(static_cast<unsigned char>(value[begin - 1]))) &&
               (end >= value.size() || !member(static_cast<unsigned char>(value[end])));
    };
    const auto hex_boundary = [](const std::string& value, const std::smatch& match) {
        const auto position = match.position(1);
        if (position < 0) return false;
        const std::size_t begin = static_cast<std::size_t>(position);
        const std::size_t end = begin + match.length(1);
        const auto member = [](unsigned char c) { return std::isxdigit(c) != 0; };
        return (begin == 0 || !member(static_cast<unsigned char>(value[begin - 1]))) &&
               (end >= value.size() || !member(static_cast<unsigned char>(value[end])));
    };
    for (unsigned depth = 0; depth < max_depth; ++depth) {
        std::vector<Candidate> produced;
        const std::size_t start = layers.size() > 8 ? layers.size() - 8 : 0;
        for (std::size_t layer = start; layer < layers.size(); ++layer) {
            const std::string& value = layers[layer].second;
            std::size_t base64_matches = 0;
            for (std::sregex_iterator iterator(value.begin(), value.end(), base64_re), end;
                 iterator != end && base64_matches < 8; ++iterator, ++base64_matches) {
                if (!base64_boundary(value, *iterator)) continue;
                Bytes decoded = base64_decode((*iterator)[1].str());
                if (!decoded.empty() && decoded.size() <= max_decoded_bytes) {
                    produced.push_back({"base64(depth=" + std::to_string(depth + 1) + ")", std::move(decoded), false, 0});
                }
            }
            std::size_t hex_matches = 0;
            for (std::sregex_iterator iterator(value.begin(), value.end(), hex_re), end;
                 iterator != end && hex_matches < 4; ++iterator, ++hex_matches) {
                if (!hex_boundary(value, *iterator)) continue;
                Bytes decoded = hex_decode((*iterator)[1].str());
                if (!decoded.empty() && decoded.size() <= max_decoded_bytes) {
                    produced.push_back({"hex(depth=" + std::to_string(depth + 1) + ")", std::move(decoded), false, 0});
                }
            }
            if (value.find('%') != std::string::npos) {
                const std::string prefix = value.substr(0, std::min(value.size(), max_decoded_bytes));
                Bytes decoded;
                url_decode(prefix, &decoded);
                if (decoded != Bytes(prefix.begin(), prefix.end()) && decoded.size() <= max_decoded_bytes) {
                    produced.push_back({"url(depth=" + std::to_string(depth + 1) + ")", std::move(decoded), false, 0});
                }
            }
            if (lower(value).find("str_rot13") != std::string::npos) {
                const std::string decoded = rot13(value.substr(0, std::min(value.size(), max_decoded_bytes)));
                if (!decoded.empty()) produced.push_back({"rot13(depth=" + std::to_string(depth + 1) + ")", Bytes(decoded.begin(), decoded.end()), false, 0});
            }
        }
        std::size_t added = 0;
        for (auto& item : produced) {
            std::vector<Candidate> candidates;
            candidates.push_back(std::move(item));
            const Bytes& compressed = candidates.front().bytes;
            if (compressed.size() >= 2 && compressed[0] == 0x1f && compressed[1] == 0x8b) {
                Bytes decoded = inflate_bytes(compressed, 16 + MAX_WBITS, max_decoded_bytes);
                if (!decoded.empty()) candidates.push_back({"gzip(depth=" + std::to_string(depth + 1) + ")", std::move(decoded), true, compressed.size()});
            } else {
                Bytes decoded = inflate_bytes(compressed, MAX_WBITS, max_decoded_bytes);
                if (!decoded.empty()) candidates.push_back({"deflate(depth=" + std::to_string(depth + 1) + ")", std::move(decoded), true, compressed.size()});
                decoded = inflate_bytes(compressed, -MAX_WBITS, max_decoded_bytes);
                if (!decoded.empty()) candidates.push_back({"deflate(depth=" + std::to_string(depth + 1) + ")", std::move(decoded), true, compressed.size()});
            }
            for (auto& candidate : candidates) {
                if (candidate.bytes.empty() || candidate.bytes.size() > max_decoded_bytes ||
                    total > max_decoded_bytes || candidate.bytes.size() > max_decoded_bytes - total) continue;
                if (candidate.decompressed && candidate.compressed_size != 0 &&
                    static_cast<double>(candidate.bytes.size()) / static_cast<double>(candidate.compressed_size) > ratio_limit) continue;
                const std::string digest = sha256(candidate.bytes);
                if (!seen.insert(digest).second) continue;
                std::string encoding;
                const std::string decoded = text_from_bytes(candidate.bytes, &encoding);
                layers.emplace_back(candidate.label, decoded);
                total += candidate.bytes.size();
                ++added;
            }
        }
        if (added == 0) break;
    }
    return layers;
}

std::string language_for(const std::string& name, const std::string& text, const Bytes& data) { const std::string extension = lower(std::filesystem::path(name).extension().string()); static const std::map<std::string, std::string> languages{{".php", "php"}, {".phtml", "php"}, {".php5", "php"}, {".inc", "php"}, {".jsp", "java"}, {".jspx", "java"}, {".java", "java"}, {".class", "java-bytecode"}, {".jar", "java-archive"}, {".war", "java-archive"}, {".ear", "java-archive"}, {".aspx", "dotnet"}, {".ashx", "dotnet"}, {".asmx", "dotnet"}, {".asp", "asp"}, {".dll", "dotnet-pe"}, {".exe", "pe"}, {".nupkg", "dotnet-archive"}, {".js", "nodejs"}, {".mjs", "nodejs"}, {".cjs", "nodejs"}, {".py", "python"}, {".pyw", "python"}}; const auto found = languages.find(extension); if (found != languages.end()) return found->second; const std::string lower_text = lower(text); if (lower_text.find("<?php") != std::string::npos) return "php"; if (std::regex_search(text, std::regex(R"(<%@\s*(?:page|webhandler|webservice))", std::regex::icase))) return lower_text.find("language=\"java") != std::string::npos ? "java" : "dotnet"; if (data.size() >= 2 && data[0] == 'M' && data[1] == 'Z') return "pe"; if (data.size() >= 4 && data[0] == 0xca && data[1] == 0xfe && data[2] == 0xba && data[3] == 0xbe) return "java-bytecode"; return "unknown"; }

std::string snippet(const std::string& value) { std::string result; bool space = false; for (unsigned char c : value) { if (std::isspace(c)) { space = true; continue; } if (space && !result.empty()) result.push_back(' '); space = false; result.push_back(static_cast<char>(c)); if (result.size() >= 160) break; } return result; }

Json analyze_bytes(const std::string& name, const Bytes& data, const std::string& container, unsigned max_depth, std::size_t max_decoded_bytes, double ratio_limit) {
    const auto started = std::chrono::steady_clock::now(); std::string encoding; const std::string text = text_from_bytes(data, &encoding); const std::string folded = fold_literals(text); const auto layers = decode_layers(folded, max_depth, max_decoded_bytes, ratio_limit); std::string combined; for (const auto& layer : layers) combined += layer.second + "\n"; if (combined.size() > TEXT_LIMIT) combined.resize(TEXT_LIMIT); Json capabilities = Json::array(), evidence = Json::object();
    for (const auto& group : CAPABILITY_PATTERNS) { std::vector<std::string> snippets; for (const char* raw : group.patterns) { try { const std::regex pattern(raw, std::regex::icase | std::regex::optimize); std::smatch match; if (std::regex_search(combined, match, pattern)) { const std::string value = snippet(match.str()); if (std::find(snippets.begin(), snippets.end(), value) == snippets.end()) snippets.push_back(value); } } catch (const std::regex_error&) {} } if (!snippets.empty()) { capabilities.push_back(group.name); evidence[group.name] = snippets; } }
    std::vector<std::string> counter; const std::string counter_text = name + "\n" + combined.substr(0, std::min<std::size_t>(200000, combined.size())); for (const auto& group : COUNTER_PATTERNS) for (const char* raw : group.patterns) { try { if (std::regex_search(counter_text, std::regex(raw, std::regex::icase | std::regex::optimize))) { counter.push_back(group.name); break; } } catch (const std::regex_error&) {} }
    std::set<std::string> capability_set; for (const auto& value : capabilities) capability_set.insert(value.get<std::string>()); std::vector<std::string> causal; auto has = [&](const char* value) { return capability_set.count(value) != 0; }; if (has("external_input") && has("decode_transform")) causal.push_back("external_input->decode_transform"); if (has("decode_transform") && (has("dynamic_code") || has("command_execution"))) causal.push_back("decode_transform->dynamic_execution"); if (has("external_input") && (has("command_execution") || has("dynamic_code"))) causal.push_back("external_input->dangerous_capability"); if (has("web_registration") && (has("dynamic_code") || has("command_execution") || has("reflection"))) causal.push_back("web_registration->dynamic_capability"); if (has("command_execution") && (has("file_write") || has("network"))) causal.push_back("command_execution->post_execution_capability"); int score = static_cast<int>(capabilities.size()) + static_cast<int>(causal.size()) * 2; if (std::find(counter.begin(), counter.end(), "generated_class_framework") != counter.end()) score = std::max(0, score - 3); if (std::find(counter.begin(), counter.end(), "test_or_mock") != counter.end()) score = std::max(0, score - 2); const std::string classification = score >= 9 && causal.size() >= 2 ? "HIGH_RISK_STRUCTURE" : (score >= 5 || !causal.empty() ? "ANOMALY" : "OBSERVE"); const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count(); return Json{{"schema_version", 1}, {"detector", "secscope-bounded-static"}, {"detector_version", VERSION}, {"path", name}, {"container", container}, {"size", data.size()}, {"sha256", sha256(data)}, {"encoding", encoding}, {"language", language_for(name, text, data)}, {"classification", classification}, {"score", score}, {"capabilities", capabilities}, {"evidence", evidence}, {"causal_edges", causal}, {"deobfuscation_chain", [&]() { Json values = Json::array(); for (const auto& layer : layers) values.push_back(layer.first); return values; }()}, {"counter_evidence", counter}, {"visibility_gaps", Json::array()}, {"status", "SUCCESS"}, {"elapsed_ms", elapsed}};
}

bool safe_member_name(const std::string& name) { std::string normalized = name; std::replace(normalized.begin(), normalized.end(), '\\', '/'); if (normalized.empty() || normalized[0] == '/' || (normalized.size() >= 2 && std::isalpha(static_cast<unsigned char>(normalized[0])) && normalized[1] == ':')) return false; std::stringstream parts(normalized); std::string part; while (std::getline(parts, part, '/')) if (part == "..") return false; return true; }

[[maybe_unused]] std::vector<Json> analyze_archive_legacy(const std::string& path, std::size_t max_bytes, std::size_t max_members, std::size_t max_archive_bytes, double ratio_limit, unsigned max_depth, std::size_t max_decoded_bytes, std::chrono::steady_clock::time_point deadline) {
    std::vector<Json> results; struct archive* reader = archive_read_new(); if (!reader) return results; archive_read_support_filter_all(reader); archive_read_support_format_all(reader); if (archive_read_open_filename(reader, path.c_str(), 1024 * 1024) != ARCHIVE_OK) { archive_read_free(reader); return results; } std::size_t members = 0, expanded = 0; struct archive_entry* entry = nullptr; while (members < max_members && expanded < max_archive_bytes && std::chrono::steady_clock::now() < deadline && archive_read_next_header(reader, &entry) == ARCHIVE_OK) { const char* raw_name = archive_entry_pathname(entry); const std::string name = raw_name ? raw_name : ""; const la_int64_t declared = archive_entry_size(entry); if (!archive_entry_filetype(entry) || !safe_member_name(name) || declared > static_cast<la_int64_t>(max_bytes) || declared < 0 || expanded + static_cast<std::size_t>(declared) > max_archive_bytes) { archive_read_data_skip(reader); continue; } Bytes data; data.reserve(static_cast<std::size_t>(std::min<la_int64_t>(declared, static_cast<la_int64_t>(max_bytes)))); std::array<unsigned char, 64 * 1024> buffer{}; while (true) { const la_ssize_t count = archive_read_data(reader, buffer.data(), buffer.size()); if (count <= 0) break; if (data.size() + static_cast<std::size_t>(count) > max_bytes) { data.clear(); break; } data.insert(data.end(), buffer.begin(), buffer.begin() + count); } if (data.empty() && declared > 0) continue; if (declared > 0 && data.size() != static_cast<std::size_t>(declared)) continue; if (expanded + data.size() > max_archive_bytes) continue; if (declared > 0 && archive_entry_size_is_set(entry) && archive_entry_size(entry) > 0 && data.size() / static_cast<double>(std::max<la_int64_t>(1, archive_entry_size(entry))) > ratio_limit) continue; results.push_back(analyze_bytes(path + "!" + name, data, path, max_depth, max_decoded_bytes, ratio_limit)); expanded += data.size(); ++members; } archive_read_free(reader); return results;
}

std::vector<Json> analyze_archive(const std::string& path, std::size_t max_bytes, std::size_t max_members, std::size_t max_archive_bytes, double ratio_limit, unsigned max_depth, std::size_t max_decoded_bytes, std::chrono::steady_clock::time_point deadline) {
    std::vector<Json> results;
    struct stat archive_stat{};
    const bool have_archive_size = ::lstat(path.c_str(), &archive_stat) == 0 && archive_stat.st_size > 0;
    const std::size_t source_bytes = have_archive_size ? static_cast<std::size_t>(archive_stat.st_size) : 0;
    struct archive* reader = archive_read_new();
    if (!reader) return results;
    archive_read_support_filter_all(reader);
    archive_read_support_format_all(reader);
    if (archive_read_open_filename(reader, path.c_str(), 1024 * 1024) != ARCHIVE_OK) {
        archive_read_free(reader);
        return results;
    }
    std::size_t members = 0;
    std::size_t expanded = 0;
    struct archive_entry* entry = nullptr;
    while (members < max_members && expanded < max_archive_bytes &&
           std::chrono::steady_clock::now() < deadline &&
           archive_read_next_header(reader, &entry) == ARCHIVE_OK) {
        const char* raw_name = archive_entry_pathname(entry);
        const std::string name = raw_name ? raw_name : "";
        const la_int64_t declared = archive_entry_size(entry);
        const mode_t file_type = archive_entry_filetype(entry);
        if (file_type != AE_IFREG || !safe_member_name(name) || declared < 0 ||
            static_cast<std::uint64_t>(declared) > max_bytes ||
            static_cast<std::uint64_t>(declared) > max_archive_bytes - std::min(expanded, max_archive_bytes)) {
            archive_read_data_skip(reader);
            continue;
        }
        Bytes data;
        data.reserve(static_cast<std::size_t>(declared));
        std::array<unsigned char, 64 * 1024> buffer{};
        bool read_error = false;
        while (true) {
            const la_ssize_t count = archive_read_data(reader, buffer.data(), buffer.size());
            if (count == 0) break;
            if (count < 0) {
                read_error = true;
                break;
            }
            const std::size_t produced = static_cast<std::size_t>(count);
            if (produced > max_bytes - std::min(data.size(), max_bytes) ||
                produced > max_archive_bytes - std::min(expanded + data.size(), max_archive_bytes)) {
                read_error = true;
                break;
            }
            data.insert(data.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(produced));
        }
        if (read_error || data.size() != static_cast<std::size_t>(declared)) continue;
        if (data.size() > max_archive_bytes - expanded) continue;
        // libarchive exposes the unpacked member size but not a portable
        // compressed member size.  Bound the aggregate expansion against the
        // source archive size so highly compressed archives cannot bypass the
        // same expansion policy as embedded deflate/gzip data.
        if (source_bytes != 0 && ratio_limit > 0.0 &&
            static_cast<double>(expanded + data.size()) / static_cast<double>(source_bytes) > ratio_limit) continue;
        results.push_back(analyze_bytes(path + "!" + name, data, path, max_depth, max_decoded_bytes, ratio_limit));
        expanded += data.size();
        ++members;
    }
    archive_read_free(reader);
    return results;
}

struct BoundedRead {
    enum class Status { SUCCESS, SKIPPED, TOO_LARGE, CHANGED, ERROR };
    Status status = Status::ERROR;
    Bytes data;
    struct stat before{};
};

bool same_file_version(const struct stat& left, const struct stat& right) {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
           left.st_size == right.st_size &&
           left.st_mtim.tv_sec == right.st_mtim.tv_sec &&
           left.st_mtim.tv_nsec == right.st_mtim.tv_nsec;
}

BoundedRead read_bounded_checked(const std::string& path, std::size_t limit) {
    BoundedRead result;
    if (::lstat(path.c_str(), &result.before) != 0) return result;
    if (S_ISLNK(result.before.st_mode) || !S_ISREG(result.before.st_mode)) {
        result.status = BoundedRead::Status::SKIPPED;
        return result;
    }
    if (result.before.st_size < 0 || static_cast<std::uint64_t>(result.before.st_size) > limit) {
        result.status = BoundedRead::Status::TOO_LARGE;
        return result;
    }
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return result;
    struct stat opened{};
    if (::fstat(fd, &opened) != 0 || !same_file_version(result.before, opened)) {
        ::close(fd);
        result.status = BoundedRead::Status::CHANGED;
        return result;
    }
    std::array<unsigned char, 1024 * 1024> buffer{};
    bool too_large = false;
    bool read_error = false;
    while (true) {
        const ssize_t count = ::read(fd, buffer.data(), buffer.size());
        if (count == 0) break;
        if (count < 0) {
            if (errno == EINTR) continue;
            read_error = true;
            break;
        }
        const std::size_t produced = static_cast<std::size_t>(count);
        if (produced > limit - std::min(result.data.size(), limit)) {
            too_large = true;
            break;
        }
        result.data.insert(result.data.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(produced));
    }
    struct stat after_fd{}, after_path{};
    const bool fd_ok = ::fstat(fd, &after_fd) == 0;
    const bool path_ok = ::lstat(path.c_str(), &after_path) == 0;
    ::close(fd);
    if (read_error || !fd_ok || !path_ok) {
        result.status = BoundedRead::Status::ERROR;
        return result;
    }
    if (!same_file_version(result.before, after_fd) || !same_file_version(result.before, after_path)) {
        result.status = BoundedRead::Status::CHANGED;
        return result;
    }
    if (too_large) {
        result.data.clear();
        result.status = BoundedRead::Status::TOO_LARGE;
        return result;
    }
    result.status = BoundedRead::Status::SUCCESS;
    return result;
}

[[maybe_unused]] std::vector<unsigned char> read_bounded_legacy(const std::string& path, std::size_t limit, struct stat* before, struct stat* after) { if (::lstat(path.c_str(), before) != 0 || !S_ISREG(before->st_mode) || S_ISLNK(before->st_mode) || before->st_size > static_cast<off_t>(limit)) return {}; const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW); if (fd < 0) return {}; Bytes data; std::array<unsigned char, 1024 * 1024> buffer{}; while (data.size() <= limit) { const ssize_t count = ::read(fd, buffer.data(), buffer.size()); if (count == 0) break; if (count < 0) { if (errno == EINTR) continue; data.clear(); break; } if (data.size() + static_cast<std::size_t>(count) > limit) { data.clear(); break; } data.insert(data.end(), buffer.begin(), buffer.begin() + count); } ::close(fd); if (::lstat(path.c_str(), after) != 0 || before->st_dev != after->st_dev || before->st_ino != after->st_ino || before->st_size != after->st_size || before->st_mtime != after->st_mtime) return {}; return data; }

[[maybe_unused]] Bytes read_bounded(const std::string& path, std::size_t limit, struct stat* before, struct stat* after) {
    return read_bounded_legacy(path, limit, before, after);
}

}

[[maybe_unused]] int run_static_analyzer_legacy(const Arguments& args) {
    std::string error; if (!required_arguments(args, {"--input-list", "--output-jsonl"}, &error)) { std::cerr << error << '\n'; return 2; }
    std::ifstream input(argument(args, "--input-list")); AtomicOutput output(argument(args, "--output-jsonl")); const std::string projection_path = argument(args, "--projection-tsv"); std::unique_ptr<AtomicOutput> projection; if (!projection_path.empty()) projection = std::make_unique<AtomicOutput>(projection_path); if (!input || !output.good() || (projection && !projection->good())) { std::cerr << "cannot open static analyzer input/output\n"; return 2; }
    if (projection) projection->stream() << "path\tlanguage\tclassification\tscore\tsha256\tcapabilities\tcausal_edges\tcounter_evidence\n";
    const std::size_t max_files = static_cast<std::size_t>(uint_argument(args, "--max-files", 800, 1, 10000)); const std::size_t max_bytes = static_cast<std::size_t>(uint_argument(args, "--max-bytes", 4U * 1024U * 1024U, 1024, 64U * 1024U * 1024U)); const unsigned max_depth = static_cast<unsigned>(uint_argument(args, "--max-decode-depth", 3, 0, 5)); const std::size_t max_decoded_bytes = static_cast<std::size_t>(uint_argument(args, "--max-decoded-bytes", 4U * 1024U * 1024U, 1024, 64U * 1024U * 1024U)); const std::size_t max_members = static_cast<std::size_t>(uint_argument(args, "--max-archive-members", 200, 1, 10000)); const std::size_t max_archive_bytes = static_cast<std::size_t>(uint_argument(args, "--max-archive-bytes", 32U * 1024U * 1024U, 1024, 512U * 1024U * 1024U)); const double ratio = double_argument(args, "--max-compression-ratio", 50.0, 1.0, 10000.0); const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(uint_argument(args, "--timeout-seconds", 120, 1, 3600)); std::size_t count = 0; std::string line;
    auto write_projection = [&](const Json& result) {
        if (!projection || !result.contains("path")) return;
        auto list_cell = [](const Json& value) { std::string result; if (value.is_array()) { for (std::size_t index = 0; index < value.size(); ++index) { if (index) result += ','; result += value[index].is_string() ? value[index].get<std::string>() : value[index].dump(); } } else if (value.is_string()) result = value.get<std::string>(); else result = value.dump(); return clean_cell(result); };
        projection->stream() << clean_cell(result.value("path", "")) << '\t' << clean_cell(result.value("language", "")) << '\t' << clean_cell(result.value("classification", "")) << '\t' << result.value("score", 0) << '\t' << clean_cell(result.value("sha256", "")) << '\t' << list_cell(result.value("capabilities", Json::array())) << '\t' << list_cell(result.value("causal_edges", Json::array())) << '\t' << list_cell(result.value("counter_evidence", Json::array())) << '\n';
    };
    while (std::getline(input, line) && count < max_files && std::chrono::steady_clock::now() < deadline) { line = trim_line(std::move(line)); if (line.empty()) continue; struct stat before{}, after{}; const Bytes data = read_bounded(line, max_bytes, &before, &after); if (data.empty() && before.st_size != 0) { const Json failed = Json{{"detector", "secscope-bounded-static"}, {"detector_version", VERSION}, {"path", line}, {"status", "FAILED"}, {"error", "file_read_or_parse_failed"}, {"visibility_gaps", Json::array({"file_read_or_parse_failed"})}}; output.stream() << failed.dump() << '\n'; write_projection(failed); ++count; continue; } const Json primary = analyze_bytes(line, data, "", max_depth, max_decoded_bytes, ratio); output.stream() << primary.dump(-1, ' ', false) << '\n'; write_projection(primary); const std::string extension = lower(std::filesystem::path(line).extension().string()); const std::set<std::string> archive_extensions{".zip", ".jar", ".war", ".ear", ".nupkg", ".tar", ".tgz", ".gz"}; if (archive_extensions.count(extension) && std::chrono::steady_clock::now() < deadline) for (const auto& result : analyze_archive(line, max_bytes, max_members, max_archive_bytes, ratio, max_depth, max_decoded_bytes, deadline)) { output.stream() << result.dump(-1, ' ', false) << '\n'; write_projection(result); } ++count; }
    const bool timed_out = std::chrono::steady_clock::now() >= deadline; output.stream() << Json{{"status", timed_out ? "PARTIAL" : "SUCCESS"}, {"scanned_files", count}, {"timeout", timed_out}, {"detector_version", VERSION}}.dump() << '\n'; std::cout << Json{{"status", timed_out ? "PARTIAL" : "SUCCESS"}, {"scanned_files", count}, {"timeout", timed_out}, {"detector_version", VERSION}}.dump() << '\n'; if (!output.commit() || (projection && !projection->commit())) return 2; return 0;
}

int run_static_analyzer(const Arguments& args) {
    std::string error;
    if (!required_arguments(args, {"--input-list", "--output-jsonl"}, &error)) {
        std::cerr << error << '\n';
        return 2;
    }
    std::ifstream input(argument(args, "--input-list"));
    AtomicOutput output(argument(args, "--output-jsonl"));
    const std::string projection_path = argument(args, "--projection-tsv");
    std::unique_ptr<AtomicOutput> projection;
    if (!projection_path.empty()) projection = std::make_unique<AtomicOutput>(projection_path);
    if (!input || !output.good() || (projection && !projection->good())) {
        std::cerr << "cannot open static analyzer input/output\n";
        return 2;
    }
    if (projection) projection->stream() << "path\tlanguage\tclassification\tscore\tsha256\tcapabilities\tcausal_edges\tcounter_evidence\n";
    const std::size_t max_files = static_cast<std::size_t>(uint_argument(args, "--max-files", 800, 1, 10000));
    const std::size_t max_bytes = static_cast<std::size_t>(uint_argument(args, "--max-bytes", 4U * 1024U * 1024U, 1024, 64U * 1024U * 1024U));
    const unsigned max_depth = static_cast<unsigned>(uint_argument(args, "--max-decode-depth", 3, 0, 5));
    const std::size_t max_decoded_bytes = static_cast<std::size_t>(uint_argument(args, "--max-decoded-bytes", 4U * 1024U * 1024U, 1024, 64U * 1024U * 1024U));
    const std::size_t max_members = static_cast<std::size_t>(uint_argument(args, "--max-archive-members", 200, 1, 10000));
    const std::size_t max_archive_bytes = static_cast<std::size_t>(uint_argument(args, "--max-archive-bytes", 32U * 1024U * 1024U, 1024, 512U * 1024U * 1024U));
    const double ratio = double_argument(args, "--max-compression-ratio", 50.0, 1.0, 10000.0);
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(uint_argument(args, "--timeout-seconds", 120, 1, 3600));
    const std::set<std::string> archive_extensions{".zip", ".jar", ".war", ".ear", ".nupkg", ".tar", ".tgz", ".gz"};
    std::size_t count = 0;
    std::size_t failed_records = 0;
    std::size_t partial_records = 0;
    std::size_t skipped_records = 0;
    std::string line;
    auto write_projection = [&](const Json& result) {
        if (!projection || !result.contains("path")) return;
        auto list_cell = [](const Json& value) {
            std::string result;
            if (value.is_array()) {
                for (std::size_t index = 0; index < value.size(); ++index) {
                    if (index) result += ',';
                    result += value[index].is_string() ? value[index].get<std::string>() : value[index].dump();
                }
            } else if (value.is_string()) {
                result = value.get<std::string>();
            } else {
                result = value.dump();
            }
            return clean_cell(result);
        };
        projection->stream() << clean_cell(result.value("path", "")) << '\t'
                             << clean_cell(result.value("language", "")) << '\t'
                             << clean_cell(result.value("classification", "")) << '\t'
                             << result.value("score", 0) << '\t'
                             << clean_cell(result.value("sha256", "")) << '\t'
                             << list_cell(result.value("capabilities", Json::array())) << '\t'
                             << list_cell(result.value("causal_edges", Json::array())) << '\t'
                             << list_cell(result.value("counter_evidence", Json::array())) << '\n';
    };
    while (std::getline(input, line) && count < max_files &&
           std::chrono::steady_clock::now() < deadline) {
        line = trim_line(std::move(line));
        if (line.empty()) continue;
        const BoundedRead read = read_bounded_checked(line, max_bytes);
        if (read.status != BoundedRead::Status::SUCCESS) {
            Json failed{{"detector", "secscope-bounded-static"}, {"detector_version", VERSION},
                        {"path", line}, {"visibility_gaps", Json::array()}};
            if (read.status == BoundedRead::Status::SKIPPED) {
                failed["status"] = "SKIPPED";
                failed["error"] = S_ISLNK(read.before.st_mode) ? "not_regular_or_symlink" : "not_regular_or_symlink";
                ++skipped_records;
            } else if (read.status == BoundedRead::Status::TOO_LARGE) {
                failed["status"] = "SKIPPED";
                failed["error"] = "file_too_large";
                ++skipped_records;
            } else if (read.status == BoundedRead::Status::CHANGED) {
                failed["status"] = "PARTIAL";
                failed["error"] = "toctou_changed_during_read";
                failed["visibility_gaps"] = Json::array({"unstable_file"});
                ++partial_records;
            } else {
                failed["status"] = "FAILED";
                failed["error"] = "file_read_or_parse_failed";
                failed["visibility_gaps"] = Json::array({"file_read_or_parse_failed"});
                ++failed_records;
            }
            output.stream() << failed.dump() << '\n';
            write_projection(failed);
            ++count;
            continue;
        }
        Json primary = analyze_bytes(line, read.data, "", max_depth, max_decoded_bytes, ratio);
        primary["device"] = static_cast<std::uint64_t>(read.before.st_dev);
        primary["inode"] = static_cast<std::uint64_t>(read.before.st_ino);
        primary["mtime"] = static_cast<std::int64_t>(read.before.st_mtime);
        primary["ctime"] = static_cast<std::int64_t>(read.before.st_ctime);
        primary["hardlink_count"] = static_cast<std::uint64_t>(read.before.st_nlink);
        output.stream() << primary.dump(-1, ' ', false) << '\n';
        write_projection(primary);
        const std::string extension = lower(std::filesystem::path(line).extension().string());
        if (archive_extensions.count(extension) && std::chrono::steady_clock::now() < deadline) {
            for (const auto& result : analyze_archive(line, max_bytes, max_members, max_archive_bytes,
                                                      ratio, max_depth, max_decoded_bytes, deadline)) {
                const std::string result_status = result.value("status", "SUCCESS");
                if (result_status == "FAILED") ++failed_records;
                else if (result_status == "PARTIAL") ++partial_records;
                else if (result_status == "SKIPPED") ++skipped_records;
                output.stream() << result.dump(-1, ' ', false) << '\n';
                write_projection(result);
            }
        }
        ++count;
    }
    const bool timed_out = std::chrono::steady_clock::now() >= deadline;
    const bool partial = timed_out || failed_records > 0 || partial_records > 0;
    const Json summary{{"status", partial ? "PARTIAL" : "SUCCESS"},
                       {"scanned_files", count}, {"timeout", timed_out},
                       {"failed_records", failed_records}, {"partial_records", partial_records},
                       {"skipped_records", skipped_records},
                       {"detector_version", VERSION}};
    output.stream() << summary.dump() << '\n';
    std::cout << summary.dump() << '\n';
    if (!output.commit() || (projection && !projection->commit())) return 2;
    return 0;
}

}
