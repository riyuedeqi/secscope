#include "web_access_parser.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <initializer_list>
#include <limits>
#include <map>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <regex>
#include <sstream>
#include <string>

namespace secscope {
namespace {

using Json = nlohmann::json;
constexpr std::size_t MAX_LINE_BYTES = 256U * 1024U;
const std::array<const char*, 12> FIELDS = {
    "timestamp", "source_file", "remote_ip", "method", "uri", "status",
    "bytes", "host", "user_agent", "referer", "parse_status", "raw_line_hash"};

const std::regex REQUEST_RE(R"(^([A-Za-z]+)[[:space:]]+([^[:space:]]+)(?:[[:space:]]+[^[:space:]]+)?$)",
                            std::regex::ECMAScript | std::regex::optimize);
const std::regex NUMBER_RE(R"(^[0-9]+(?:\.[0-9]+)?$)", std::regex::ECMAScript | std::regex::optimize);

std::string upper(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return value;
}

std::string json_value(const Json& value) {
    if (value.is_null()) return {};
    if (value.is_string()) return value.get<std::string>();
    if (value.is_object() || value.is_array()) return value.dump(-1, ' ', true);
    if (value.is_boolean()) return value.get<bool>() ? "True" : "False";
    return value.dump();
}

std::string first_value(const Json& object, std::initializer_list<const char*> names) {
    for (const char* name : names) {
        const auto found = object.find(name);
        if (found == object.end() || found->is_null()) continue;
        const std::string value = json_value(*found);
        if (!value.empty()) return value;
    }
    return {};
}

std::string normalize_timestamp(std::string value) {
    value = clean_cell(value);
    if (value.empty() || !std::regex_match(value, NUMBER_RE)) return value;
    try {
        long double epoch = std::stold(value);
        if (epoch > 100000000000.0L) epoch /= 1000.0L;
        if (epoch < static_cast<long double>(std::numeric_limits<std::time_t>::min()) ||
            epoch > static_cast<long double>(std::numeric_limits<std::time_t>::max())) return value;
        const std::time_t raw = static_cast<std::time_t>(epoch);
        std::tm utc{};
        if (!::gmtime_r(&raw, &utc)) return value;
        std::ostringstream output;
        output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
        return output.str();
    } catch (...) {
        return value;
    }
}

std::string sha256(const std::string& value) {
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (!context) return {};
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned length = 0;
    const bool ok = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1 &&
                    EVP_DigestUpdate(context, value.data(), value.size()) == 1 &&
                    EVP_DigestFinal_ex(context, digest.data(), &length) == 1;
    EVP_MD_CTX_free(context);
    if (!ok) return {};
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (unsigned index = 0; index < length; ++index) output << std::setw(2) << static_cast<unsigned>(digest[index]);
    return output.str();
}

using Record = std::map<std::string, std::string>;

Record partial_record() {
    Record result;
    for (const char* field : FIELDS) result[field] = {};
    result["parse_status"] = "PARTIAL_PARSE";
    return result;
}

Record parse_json_line(const std::string& line) {
    Json object;
    try { object = Json::parse(line); } catch (...) { return {}; }
    if (!object.is_object()) return {};
    std::string method = first_value(object, {"method", "request_method", "http_method"});
    std::string uri = first_value(object, {"uri", "path", "request_uri", "url"});
    if (method.empty() || uri.empty()) {
        std::smatch match;
        const std::string request = first_value(object, {"request", "request_line"});
        if (std::regex_match(request, match, REQUEST_RE)) {
            if (method.empty()) method = match[1].str();
            if (uri.empty()) uri = match[2].str();
        }
    }
    std::string remote = first_value(object, {"remote_addr", "client_ip", "ip", "remote_ip"});
    const auto comma = remote.find(',');
    if (comma != std::string::npos) {
        remote.resize(comma);
        while (!remote.empty() && std::isspace(static_cast<unsigned char>(remote.back()))) remote.pop_back();
    }
    Record result = partial_record();
    result["timestamp"] = normalize_timestamp(first_value(object, {"time", "timestamp", "time_iso8601", "@timestamp", "datetime"}));
    result["remote_ip"] = remote;
    result["method"] = upper(clean_cell(method));
    result["uri"] = first_value(object, {"uri", "path", "request_uri", "url"});
    if (result["uri"].empty()) result["uri"] = uri;
    result["status"] = first_value(object, {"status", "status_code", "response_status"});
    result["bytes"] = first_value(object, {"bytes", "body_bytes_sent", "bytes_sent", "response_bytes"});
    result["host"] = first_value(object, {"host", "http_host", "server_name", "vhost"});
    result["user_agent"] = first_value(object, {"user_agent", "http_user_agent", "agent"});
    result["referer"] = first_value(object, {"referer", "referrer", "http_referer"});
    if (!result["remote_ip"].empty() && !result["method"].empty() && !result["uri"].empty() && !result["status"].empty()) {
        result["parse_status"] = "FULL_PARSE";
    }
    return result;
}

Record parse_common_line(const std::string& line) {
    const auto open_bracket = line.find('[');
    if (open_bracket == std::string::npos || open_bracket == 0) return {};
    const auto close_bracket = line.find(']', open_bracket + 1);
    if (close_bracket == std::string::npos || close_bracket == open_bracket + 1) return {};

    // Common/combined logs have exactly three whitespace-delimited fields
    // before the timestamp: client address, ident, and authenticated user.
    std::istringstream prefix(line.substr(0, open_bracket));
    std::string remote;
    std::string ignored_ident;
    std::string ignored_user;
    std::string unexpected;
    if (!(prefix >> remote >> ignored_ident >> ignored_user) || (prefix >> unexpected)) return {};

    auto skip_space = [&line](std::size_t* position) {
        while (*position < line.size() &&
               std::isspace(static_cast<unsigned char>(line[*position]))) {
            ++(*position);
        }
    };
    auto read_quoted = [&line, &skip_space](std::size_t* position, std::string* value) {
        skip_space(position);
        if (*position >= line.size() || line[*position] != '"') return false;
        ++(*position);
        value->clear();
        while (*position < line.size()) {
            const char current = line[*position];
            if (current == '"') {
                ++(*position);
                return true;
            }
            if (current == '\\' && *position + 1 < line.size() &&
                line[*position + 1] == '"') {
                value->push_back('"');
                *position += 2;
                continue;
            }
            value->push_back(current);
            ++(*position);
        }
        return false;
    };
    auto read_token = [&line, &skip_space](std::size_t* position, std::string* value) {
        skip_space(position);
        const std::size_t start = *position;
        while (*position < line.size() &&
               !std::isspace(static_cast<unsigned char>(line[*position]))) {
            ++(*position);
        }
        if (*position == start) return false;
        *value = line.substr(start, *position - start);
        return true;
    };
    auto valid_status = [](const std::string& value) {
        if (value == "-") return true;
        return value.size() == 3 && std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return std::isdigit(c) != 0;
        });
    };
    auto valid_bytes = [](const std::string& value) {
        return value == "-" || (!value.empty() && std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return std::isdigit(c) != 0;
        }));
    };

    std::size_t position = close_bracket + 1;
    std::string request;
    std::string status;
    std::string bytes;
    if (!read_quoted(&position, &request) || !read_token(&position, &status) ||
        !read_token(&position, &bytes) || !valid_status(status) || !valid_bytes(bytes)) {
        return {};
    }
    std::smatch request_match;
    if (!std::regex_match(request, request_match, REQUEST_RE)) return {};

    Record result = partial_record();
    result["remote_ip"] = remote;
    result["timestamp"] = line.substr(open_bracket + 1, close_bracket - open_bracket - 1);
    result["method"] = upper(request_match[1].str());
    result["uri"] = request_match[2].str();
    result["status"] = status;
    result["bytes"] = bytes;

    // Optional combined fields are accepted only as complete quoted pairs;
    // malformed trailing fields must not erase the valid request/status data.
    const std::size_t optional_start = position;
    std::string referer;
    std::string user_agent;
    if (read_quoted(&position, &referer) && read_quoted(&position, &user_agent)) {
        result["referer"] = referer;
        result["user_agent"] = user_agent;
        std::string host;
        if (read_quoted(&position, &host)) result["host"] = host;
    } else {
        position = optional_start;
    }
    result["parse_status"] = "FULL_PARSE";
    return result;
}

Record parse_line(const std::string& line, const std::string& format) {
    Record result;
    const auto first = line.find_first_not_of(" \t");
    if (format == "json" || (format == "auto" && first != std::string::npos && line[first] == '{')) result = parse_json_line(line);
    if (result.empty() && (format == "auto" || format == "nginx_combined" ||
                           format == "apache_combined" || format == "tomcat")) result = parse_common_line(line);
    return result.empty() ? partial_record() : result;
}

}

int run_web_access_parser(const Arguments& args) {
    std::string error;
    if (!required_arguments(args, {"--input", "--output"}, &error)) { std::cerr << error << '\n'; return 2; }
    const std::string format = argument(args, "--format", "auto");
    if (format != "auto" && format != "nginx_combined" && format != "apache_combined" && format != "json" && format != "tomcat") {
        std::cerr << "unsupported --format\n"; return 2;
    }
    std::ifstream input(argument(args, "--input"));
    AtomicOutput output(argument(args, "--output"));
    if (!input || !output.good()) { std::cerr << "cannot open web access input/output\n"; return 2; }
    for (std::size_t index = 0; index < FIELDS.size(); ++index) output.stream() << (index ? "\t" : "") << FIELDS[index];
    output.stream() << '\n';
    std::string row;
    while (std::getline(input, row)) {
        row = trim_line(std::move(row));
        const auto tab = row.find('\t');
        const std::string source = tab == std::string::npos ? "unknown" : row.substr(0, tab);
        const std::string raw = tab == std::string::npos ? row : row.substr(tab + 1);
        Record parsed = raw.size() > MAX_LINE_BYTES ? partial_record() : parse_line(raw, format);
        parsed["source_file"] = source;
        parsed["raw_line_hash"] = sha256(raw);
        for (std::size_t index = 0; index < FIELDS.size(); ++index) {
            output.stream() << (index ? "\t" : "") << clean_cell(parsed[FIELDS[index]]);
        }
        output.stream() << '\n';
    }
    if (input.bad() || !output.stream()) return 3;
    return output.commit() ? 0 : 2;
}

}
