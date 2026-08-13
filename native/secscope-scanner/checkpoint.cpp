#include "checkpoint.hpp"
#include <cerrno>
#include <cstdlib>
#include <fstream>
#include <regex>
#include <unistd.h>
namespace secscope {
namespace { std::string esc(const std::string& v) { std::string o; for (char c : v) { if (c == '\\' || c == '"') o += '\\'; if (c == '\n') { o += "\\n"; continue; } o += c; } return o; }
std::string field(const std::string& text, const char* name) { std::regex r(std::string("\\\"") + name + "\\\"\\s*:\\s*\\\"([^\\\"]*)\\\""); std::smatch m; return std::regex_search(text, m, r) ? m[1].str() : std::string{}; }
std::size_t number(const std::string& text, const char* name) { std::regex r(std::string("\\\"") + name + "\\\"\\s*:\\s*([0-9]+)"); std::smatch m; if (!std::regex_search(text, m, r)) return 0; const std::string digits = m[1].str(); errno = 0; char* end = nullptr; const auto value = std::strtoull(digits.c_str(), &end, 10); return errno == ERANGE || !end || *end != '\0' ? 0 : static_cast<std::size_t>(value); }
}
bool save_checkpoint(const std::string& path, const Checkpoint& c) { std::string tmp = path + ".tmp"; std::ofstream out(tmp, std::ios::trunc); if (!out) return false; out << "{\"schema_version\":1,\"profile\":\"" << esc(c.profile) << "\",\"input_fingerprint\":\"" << esc(c.input_fingerprint) << "\",\"completed\":" << c.completed << ",\"total\":" << c.total << ",\"status\":\"" << esc(c.status) << "\",\"reason\":\"" << esc(c.reason) << "\"}\n"; out.close(); return out && ::rename(tmp.c_str(), path.c_str()) == 0; }
bool load_checkpoint(const std::string& path, Checkpoint* c) { if (!c) return false; std::ifstream in(path, std::ios::binary); if (!in) return false; in.seekg(0, std::ios::end); auto size = in.tellg(); if (size < 0 || size > 1024 * 1024) return false; in.seekg(0, std::ios::beg); std::string text((std::istreambuf_iterator<char>(in)), {}); if (text.empty() || text.find("\"schema_version\":1") == std::string::npos) return false; c->profile = field(text, "profile"); c->input_fingerprint = field(text, "input_fingerprint"); c->completed = number(text, "completed"); c->total = number(text, "total"); c->status = field(text, "status"); c->reason = field(text, "reason"); return true; }
}
