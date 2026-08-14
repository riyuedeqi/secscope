#include "events_parser.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <initializer_list>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <unistd.h>

namespace secscope {
namespace {

using Json = nlohmann::json;
constexpr std::size_t MAX_LINE_BYTES = 128 * 1024;
constexpr std::size_t MAX_DETAIL_BYTES = 6000;

struct Event {
    std::string source;
    std::string action = "other";
    std::string domain = "PROCESS";
    std::string epoch;
    std::string event_id;
    std::string pid;
    std::string ppid;
    std::string uid;
    std::string exe;
    std::string path;
    std::string target;
    std::string details;
    std::string arch;
    std::string syscall;
    std::string parse_status = "COMPLETE";
};

std::string bounded(std::string value, std::size_t limit = MAX_DETAIL_BYTES) {
    if (value.size() > limit) value.resize(limit);
    return clean_cell(std::move(value));
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char item) {
        return static_cast<char>(std::tolower(item));
    });
    return value;
}

std::string event_domain(const std::string& text) {
    const std::string value = lower(text);
    if (value.find("memfd") != std::string::npos || value.find("ptrace") != std::string::npos ||
        value.find("process_vm_writev") != std::string::npos || value.find("/proc/") != std::string::npos ||
        value.find("rwx") != std::string::npos) return "MEMORY";
    if (value.find("connect") != std::string::npos || value.find("socket") != std::string::npos ||
        value.find("network") != std::string::npos) return "NETWORK";
    if (value.find("cron") != std::string::npos || value.find("systemd") != std::string::npos ||
        value.find("authorized_keys") != std::string::npos || value.find("sudoers") != std::string::npos ||
        value.find("pam.d") != std::string::npos || value.find("ld.so.preload") != std::string::npos) return "PERSISTENCE";
    if (value.find("nginx") != std::string::npos || value.find("apache") != std::string::npos ||
        value.find("httpd") != std::string::npos || value.find("php-fpm") != std::string::npos ||
        value.find("tomcat") != std::string::npos || value.find("http") != std::string::npos) return "WEB";
    if (value.find("open") != std::string::npos || value.find("write") != std::string::npos ||
        value.find("rename") != std::string::npos || value.find("unlink") != std::string::npos ||
        value.find("chmod") != std::string::npos || value.find("file") != std::string::npos) return "FILE";
    if (value.find("login") != std::string::npos || value.find("auth") != std::string::npos ||
        value.find("sshd") != std::string::npos || value.find("sudo") != std::string::npos) return "AUTH";
    if (value.find("module") != std::string::npos || value.find("ima") != std::string::npos) return "INTEGRITY";
    return "PROCESS";
}

std::string event_action(const std::string& text) {
    const std::string value = lower(text);
    if (value.find("memfd") != std::string::npos) return "memfd";
    if (value.find("ptrace") != std::string::npos) return "ptrace";
    if (value.find("process_vm_writev") != std::string::npos) return "process_vm_writev";
    if (value.find("setns") != std::string::npos) return "setns";
    if (value.find("unshare") != std::string::npos) return "unshare";
    if (value.find("module") != std::string::npos || value.find("init_module") != std::string::npos) return "module_load";
    if (value.find("connect") != std::string::npos) return "connect";
    if (value.find("rename") != std::string::npos) return "rename";
    if (value.find("unlink") != std::string::npos || value.find("delete") != std::string::npos) return "unlink";
    if (value.find("chmod") != std::string::npos) return "chmod";
    if (value.find("open") != std::string::npos || value.find("write") != std::string::npos) return "file_access";
    if (value.find("execve") != std::string::npos || value.find("spawn") != std::string::npos || value.find("process") != std::string::npos) return "execve";
    if (value.find("login") != std::string::npos || value.find("auth") != std::string::npos) return "auth";
    return "other";
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

std::string json_text(const Json& value) {
    if (value.is_null()) return {};
    if (value.is_string()) return value.get<std::string>();
    return value.dump();
}

std::string json_field(const Json& object, std::initializer_list<const char*> names) {
    if (!object.is_object()) return {};
    for (const char* name : names) {
        const auto found = object.find(name);
        if (found != object.end() && !found->is_null()) {
            const std::string value = json_text(*found);
            if (!value.empty()) return value;
        }
    }
    return {};
}

std::string nested_field(const Json& object, const char* key, std::initializer_list<const char*> names) {
    const auto found = object.find(key);
    return found != object.end() && found->is_object() ? json_field(*found, names) : std::string{};
}

std::string epoch_from_value(std::string value) {
    value = bounded(std::move(value), 64);
    if (value.empty()) return std::to_string(static_cast<long long>(std::time(nullptr)));
    bool numeric = true;
    for (char item : value) if (!std::isdigit(static_cast<unsigned char>(item)) && item != '.') numeric = false;
    if (numeric) {
        try {
            const long double parsed = std::stold(value);
            const long double seconds = parsed > 100000000000.0L ? parsed / 1000.0L : parsed;
            if (seconds >= 0.0L && seconds <= 4102444800.0L) return std::to_string(static_cast<long long>(seconds));
        } catch (...) {
        }
    }
    if (value.size() >= 19 && (value[10] == 'T' || value[10] == ' ') && value[4] == '-' &&
        value[7] == '-' && value[13] == ':' && value[16] == ':') {
        std::tm calendar{};
        std::istringstream input(value.substr(0, 19));
        input >> std::get_time(&calendar, value[10] == 'T' ? "%Y-%m-%dT%H:%M:%S" : "%Y-%m-%d %H:%M:%S");
        if (!input.fail()) {
            const std::time_t base = ::timegm(&calendar);
            if (base >= 0) {
                long long offset = 0;
                const std::size_t fraction = value.find('.', 19);
                std::size_t timezone = fraction == std::string::npos ? 19 : fraction + 1;
                while (timezone < value.size() && std::isdigit(static_cast<unsigned char>(value[timezone]))) ++timezone;
                if (timezone < value.size() && value[timezone] != 'Z' && value[timezone] != 'z') {
                    const char sign = value[timezone];
                    if ((sign == '+' || sign == '-') && timezone + 5 < value.size() && value[timezone + 3] == ':') {
                        const int hours = std::atoi(value.substr(timezone + 1, 2).c_str());
                        const int minutes = std::atoi(value.substr(timezone + 4, 2).c_str());
                        offset = static_cast<long long>(hours * 3600 + minutes * 60);
                        if (sign == '-') offset = -offset;
                    }
                }
                const long long seconds = static_cast<long long>(base) - offset;
                if (seconds >= 0 && seconds <= 4102444800LL) return std::to_string(seconds);
            }
        }
    }
    return std::to_string(static_cast<long long>(std::time(nullptr)));
}

std::string process_start_ticks(const std::string& pid) {
    if (pid.empty()) return {};
    std::ifstream input("/proc/" + pid + "/stat");
    std::string stat;
    std::getline(input, stat);
    const auto close = stat.rfind(')');
    if (close == std::string::npos || close + 2 >= stat.size()) return {};
    std::istringstream fields(stat.substr(close + 2));
    std::string token;
    for (int index = 0; index < 20; ++index) if (!(fields >> token)) return {};
    return token;
}

std::string process_exe(const std::string& pid) {
    if (pid.empty()) return {};
    char buffer[4096]{};
    const ssize_t length = ::readlink(("/proc/" + pid + "/exe").c_str(), buffer, sizeof(buffer) - 1);
    return length > 0 ? std::string(buffer, static_cast<std::size_t>(length)) : std::string{};
}

std::string boot_id() {
    std::ifstream input("/proc/sys/kernel/random/boot_id");
    std::string value;
    std::getline(input, value);
    return value.empty() ? "unknown" : bounded(std::move(value), 128);
}

std::string process_instance(const std::string& pid, const std::string& exe, const std::string& boot) {
    if (pid.empty()) return {};
    const std::string start = process_start_ticks(pid);
    return "process:" + boot + ":" + pid + ":" + (start.empty() ? "starttime-unavailable" : start) + ":" + (exe.empty() ? "unknown" : exe);
}

bool audit_timestamp(const std::string& line, std::string* epoch, std::string* serial) {
    const auto open = line.find("audit(");
    if (open == std::string::npos) return false;
    const auto start = open + 6;
    const auto dot = line.find('.', start);
    const auto colon = line.find(':', start);
    const auto close = line.find(')', start);
    if (colon == std::string::npos || close == std::string::npos || colon <= start || close <= colon) return false;
    const auto time_end = dot != std::string::npos && dot < colon ? dot : colon;
    *epoch = line.substr(start, time_end - start);
    *serial = line.substr(colon + 1, close - colon - 1);
    return !epoch->empty() && !serial->empty();
}

std::string audit_syscall_name(const std::string& arch, const std::string& syscall, bool* unmapped) {
    if (unmapped) *unmapped = false;
    if (syscall.empty()) return {};
    bool numeric = true;
    for (const char item : syscall) if (!std::isdigit(static_cast<unsigned char>(item))) numeric = false;
    if (!numeric) return syscall;
    errno = 0;
    char* end = nullptr;
    const unsigned long number = std::strtoul(syscall.c_str(), &end, 10);
    if (errno != 0 || !end || *end != '\0') {
        if (unmapped) *unmapped = true;
        return {};
    }
    const std::string normalized = lower(arch);
    const auto lookup = [number](std::initializer_list<std::pair<unsigned long, const char*>> values) {
        for (const auto& value : values) if (value.first == number) return std::string(value.second);
        return std::string{};
    };
    std::string name;
    if (normalized == "c000003e") name = lookup({{59, "execve"}, {42, "connect"}, {2, "open"}, {257, "openat"}, {1, "write"}, {82, "rename"}, {87, "unlink"}, {90, "chmod"}, {101, "ptrace"}, {272, "unshare"}, {308, "setns"}, {319, "memfd_create"}, {175, "init_module"}, {313, "finit_module"}, {311, "process_vm_writev"}});
    else if (normalized == "40000003") name = lookup({{11, "execve"}, {102, "socketcall"}, {5, "open"}, {295, "openat"}, {4, "write"}, {38, "rename"}, {10, "unlink"}, {15, "chmod"}, {26, "ptrace"}, {346, "setns"}, {310, "unshare"}, {128, "init_module"}, {350, "finit_module"}, {348, "process_vm_writev"}});
    else if (normalized == "c00000b7") name = lookup({{221, "execve"}, {203, "connect"}, {56, "openat"}, {64, "write"}, {38, "renameat"}, {35, "unlinkat"}, {53, "fchmodat"}, {117, "ptrace"}, {97, "unshare"}, {279, "memfd_create"}, {105, "init_module"}, {273, "finit_module"}, {271, "process_vm_writev"}});
    if (!name.empty()) return name;
    if (unmapped) *unmapped = true;
    return {};
}

std::string token_value(const std::string& line, const std::string& key) {
    const std::string marker = key + "=";
    const auto position = line.find(marker);
    if (position == std::string::npos || (position > 0 && line[position - 1] != ' ')) return {};
    std::size_t start = position + marker.size();
    if (start < line.size() && line[start] == '"') {
        ++start;
        const auto end = line.find('"', start);
        return end == std::string::npos ? line.substr(start) : line.substr(start, end - start);
    }
    const auto end = line.find(' ', start);
    return line.substr(start, end == std::string::npos ? end : end - start);
}

Event make_audit_event(const std::string& line, const std::string& boot, const std::string& serial) {
    Event event;
    event.source = "auditd";
    event.epoch = epoch_from_value("");
    event.event_id = "audit:" + serial;
    event.pid = token_value(line, "pid");
    event.ppid = token_value(line, "ppid");
    event.uid = token_value(line, "auid");
    if (event.uid.empty()) event.uid = token_value(line, "uid");
    event.exe = token_value(line, "exe");
    event.path = token_value(line, "name");
    event.target = token_value(line, "daddr");
    if (event.target.empty()) event.target = token_value(line, "addr");
    event.arch = token_value(line, "arch");
    event.syscall = token_value(line, "syscall");
    event.details = bounded(line);
    event.parse_status = "COMPLETE";
    event.action = event_action(event.details);
    event.domain = event_domain(event.details + " " + event.exe + " " + event.path);
    (void)boot;
    return event;
}

Event make_falco_event(const std::string& line, const std::string& boot) {
    Event event;
    event.source = "falco";
    Json object;
    try { object = Json::parse(line); } catch (...) {
        event.parse_status = "PARTIAL";
        event.epoch = epoch_from_value("");
        event.event_id = "falco:" + sha256(line).substr(0, 20);
        event.details = bounded(line);
        return event;
    }
    if (!object.is_object()) {
        event.parse_status = "PARTIAL";
        event.epoch = epoch_from_value("");
        event.event_id = "falco:" + sha256(line).substr(0, 20);
        event.details = bounded(line);
        return event;
    }
    const Json* fields = nullptr;
    const auto field_object = object.find("output_fields");
    if (field_object != object.end() && field_object->is_object()) fields = &(*field_object);
    const std::string object_time = json_field(object, {"time", "timestamp", "evt.time"});
    event.epoch = epoch_from_value(object_time.empty() && fields ? json_field(*fields, {"evt.time"}) : object_time);
    event.pid = fields ? json_field(*fields, {"proc.pid"}) : std::string{};
    event.ppid = fields ? json_field(*fields, {"proc.ppid"}) : std::string{};
    event.uid = fields ? json_field(*fields, {"user.uid"}) : std::string{};
    event.exe = fields ? json_field(*fields, {"proc.exepath", "proc.name"}) : std::string{};
    event.path = fields ? json_field(*fields, {"fd.name", "fs.path.name"}) : std::string{};
    event.target = fields ? json_field(*fields, {"fd.rip", "fd.sip", "fd.lip"}) : std::string{};
    event.details = "rule=" + json_field(object, {"rule"}) + " priority=" + json_field(object, {"priority"}) +
                    " output_fields=" + (fields ? fields->dump() : "{}") + " output=" + json_field(object, {"output"});
    event.details = bounded(event.details);
    event.action = event_action(event.details);
    event.domain = event_domain(event.details + " " + event.exe + " " + event.path);
    event.event_id = "falco:" + sha256(line).substr(0, 20);
    if (event.exe.empty()) event.exe = process_exe(event.pid);
    (void)boot;
    return event;
}

Event make_text_event(const std::string& source, const std::string& line) {
    Event event;
    event.source = source;
    event.epoch = epoch_from_value("");
    event.event_id = source + ":" + sha256(line).substr(0, 20);
    event.details = bounded(line);
    event.action = event_action(event.details);
    event.domain = event_domain(event.details);
    event.parse_status = "COMPLETE";
    return event;
}

void merge_audit(Event* current, const Event& next, const std::string& line) {
    if (!current) return;
    if (current->pid.empty()) current->pid = next.pid;
    if (current->ppid.empty()) current->ppid = next.ppid;
    if (current->uid.empty()) current->uid = next.uid;
    if (current->exe.empty()) current->exe = next.exe;
    if (!next.path.empty()) current->path = next.path;
    if (current->target.empty()) current->target = next.target;
    if (current->arch.empty()) current->arch = next.arch;
    if (current->syscall.empty()) current->syscall = next.syscall;
    if (current->details.size() < MAX_DETAIL_BYTES) {
        std::size_t room = MAX_DETAIL_BYTES - current->details.size();
        if (room >= 4) {
            current->details += " || ";
            room -= 4;
        }
        if (room > 0) {
            std::string addition = line;
            if (addition.size() > room) addition.resize(room);
            current->details += clean_cell(addition);
        }
    }
}

void finalize_audit(Event* event) {
    if (!event) return;
    bool unmapped = false;
    const std::string syscall = audit_syscall_name(event->arch, event->syscall, &unmapped);
    if (!syscall.empty() || unmapped) {
        const std::string prefix = unmapped ? "syscall_unmapped=" + lower(event->arch) + ":" + event->syscall + " || "
                                           : "syscall_name=" + syscall + " || ";
        event->details = prefix + event->details;
        if (event->details.size() > MAX_DETAIL_BYTES) event->details.resize(MAX_DETAIL_BYTES);
    }
    if (unmapped) event->parse_status = "PARTIAL";
    event->details = clean_cell(event->details);
    event->action = event_action(event->details);
    event->domain = event_domain(event->details + " " + event->exe + " " + event->path);
}

void write_event(std::ostream& output, const Event& event, const std::string& boot) {
    const std::string instance = process_instance(event.pid, event.exe, boot);
    const std::string parent = event.ppid.empty() ? std::string{} : process_instance(event.ppid, "parent", boot);
    const std::string file_entity = event.path.empty() ? std::string{} : "file:" + sha256(event.path).substr(0, 48);
    const std::string network = event.target.empty() ? std::string{} : "network:" + (instance.empty() ? "unknown" : instance) + ":" + sha256(event.target);
    std::string entity_type = "GENERIC";
    std::string entity_id;
    if (!instance.empty()) { entity_type = "PROCESS"; entity_id = instance; }
    else if (!file_entity.empty()) { entity_type = "FILE"; entity_id = file_entity; }
    else if (!network.empty()) { entity_type = "NETWORK"; entity_id = network; }
    const std::string epoch = event.epoch.empty() ? epoch_from_value("") : event.epoch;
    const long long numeric_epoch = std::strtoll(epoch.c_str(), nullptr, 10);
    const auto raw_epoch = static_cast<std::time_t>(numeric_epoch);
    std::tm utc{};
    std::string timestamp;
    if (::gmtime_r(&raw_epoch, &utc)) { std::ostringstream value; value << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ"); timestamp = value.str(); }
    output << Json{{"record_type", "event"}, {"event_id", event.event_id}, {"source", event.source},
                   {"timestamp_utc", timestamp}, {"time_epoch", numeric_epoch}, {"entity_type", entity_type},
                   {"entity_id", entity_id}, {"process_instance_id", instance}, {"parent_instance_id", parent},
                   {"file_entity_id", file_entity}, {"network_flow_id", network}, {"site_id", ""},
                   {"request_id", ""}, {"evidence_domain", event.domain}, {"confidence", "OBSERVED"},
                   {"raw_reference", event.source + ":raw"}, {"action", event.action}, {"domain", event.domain},
                   {"pid", event.pid}, {"ppid", event.ppid}, {"uid", event.uid}, {"exe", event.exe},
                   {"path", event.path}, {"target", event.target}, {"details", bounded(event.details, 1200)},
                   {"parse_status", event.parse_status}}.dump() << '\n';
}

} // namespace

int run_events_parser(const Arguments& args) {
    std::string error;
    if (!required_arguments(args, {"--input", "--output", "--audit-output"}, &error)) {
        std::cerr << error << '\n';
        return 2;
    }
    std::ifstream input(argument(args, "--input"));
    AtomicOutput output(argument(args, "--output"));
    AtomicOutput audit_output(argument(args, "--audit-output"));
    if (!input || !output.good() || !audit_output.good()) { std::cerr << "cannot open events input/output\n"; return 2; }
    const std::size_t max_lines = static_cast<std::size_t>(uint_argument(args, "--max-lines", 120000, 1, 1000000));
    const long long start_epoch = static_cast<long long>(uint_argument(args, "--start-epoch", 0, 0, 4102444800ULL));
    const std::string boot = boot_id();
    std::string line;
    std::unordered_map<std::string, std::size_t> audit_positions;
    std::vector<Event> audit_events;
    std::uint64_t lines = 0;
    std::uint64_t events = 0;
    std::uint64_t falco = 0;
    std::uint64_t audit = 0;
    std::uint64_t text = 0;
    bool partial = false;
    auto emit_audits = [&]() {
        for (Event& event : audit_events) {
            finalize_audit(&event);
            write_event(output.stream(), event, boot);
            audit_output.stream() << event.epoch << '\x1f' << event.event_id << '\x1f' << event.pid << '\x1f'
                                  << event.ppid << '\x1f' << event.uid << '\x1f' << clean_cell(event.exe) << '\x1f'
                                  << clean_cell(event.path) << '\x1f' << clean_cell(event.target) << '\x1f' << event.parse_status
                                  << '\x1f' << clean_cell(event.details) << '\n';
            ++events;
            ++audit;
        }
    };
    while (std::getline(input, line)) {
        if (++lines > max_lines) { partial = true; break; }
        line = trim_line(std::move(line));
        const auto tab = line.find('\t');
        const std::string source = tab == std::string::npos ? "system-log" : line.substr(0, tab);
        const std::string raw = tab == std::string::npos ? line : line.substr(tab + 1);
        if (raw.empty()) continue;
        if (raw.size() > MAX_LINE_BYTES) { partial = true; continue; }
        if (source == "auditd" || source == "journald-audit") {
            std::string epoch;
            std::string serial;
            if (source == "auditd" && audit_timestamp(raw, &epoch, &serial)) {
                if (start_epoch > 0 && std::strtoll(epoch.c_str(), nullptr, 10) < start_epoch) continue;
                const auto found = audit_positions.find(serial);
                if (found == audit_positions.end()) {
                    Event event = make_audit_event(raw, boot, serial);
                    event.epoch = epoch;
                    audit_positions.emplace(serial, audit_events.size());
                    audit_events.push_back(std::move(event));
                } else {
                    merge_audit(&audit_events[found->second], make_audit_event(raw, boot, serial), raw);
                }
                continue;
            }
            if (source == "journald-audit") {
                Event event = make_text_event(source, raw);
                if (start_epoch > 0 && std::strtoll(event.epoch.c_str(), nullptr, 10) < start_epoch) continue;
                write_event(output.stream(), event, boot);
                ++events; ++audit;
                continue;
            }
            partial = true;
            continue;
        }
        Event event;
        if (source == "falco") {
            event = make_falco_event(raw, boot);
            ++falco;
        } else {
            const std::string lowered = lower(raw);
            if (source == "system-log" && lowered.find("exec") == std::string::npos && lowered.find("connect") == std::string::npos &&
                lowered.find("login") == std::string::npos && lowered.find("auth") == std::string::npos && lowered.find("write") == std::string::npos &&
                lowered.find("rename") == std::string::npos && lowered.find("unlink") == std::string::npos && lowered.find("module") == std::string::npos) continue;
            event = make_text_event(source, raw);
            ++text;
        }
        if (start_epoch > 0 && std::strtoll(event.epoch.c_str(), nullptr, 10) < start_epoch) continue;
        write_event(output.stream(), event, boot);
        ++events;
    }
    emit_audits();
    if (input.bad() || !output.stream() || !audit_output.stream()) partial = true;
    output.stream() << Json{{"record_type", "summary"}, {"lines", lines}, {"events", events}, {"falco", falco},
                             {"audit", audit}, {"text", text}, {"partial", partial}, {"reason", partial ? "input_or_limit" : ""}}.dump() << '\n';
    if (!output.stream() || !audit_output.stream() || !output.commit() || !audit_output.commit()) return 3;
    std::cout << Json{{"status", partial ? "PARTIAL" : "SUCCESS"}, {"lines", lines}, {"events", events},
                      {"falco", falco}, {"audit", audit}, {"text", text}, {"partial", partial}}.dump() << '\n';
    return 0;
}

} // namespace secscope
