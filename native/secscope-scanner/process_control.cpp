#include "process_control.hpp"

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <thread>
#include <utility>
#include <unistd.h>

namespace secscope {
namespace {

// Process control is an opt-in Linux-only action path. Ordinary collection
// never calls it; every input is revalidated before a signal is sent.
using Json = nlohmann::json;
constexpr std::size_t MAX_REQUEST_BYTES = 64 * 1024;
constexpr std::size_t MAX_FINDINGS_BYTES = 16 * 1024 * 1024;
constexpr std::size_t MAX_TEXT_BYTES = 4096;

// A PID is reusable. Keep boot ID, start ticks, and executable together so a
// request cannot silently retarget a later process that received the same PID.
struct ProcessIdentity {
    pid_t pid = 0;
    pid_t ppid = 0;
    std::uint64_t start_ticks = 0;
    char state = '?';
    std::string boot_id;
    std::string exe;
};

std::string bounded_read(const std::string& path, std::size_t limit) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return {};
    std::string value(limit, '\0');
    input.read(value.data(), static_cast<std::streamsize>(value.size()));
    value.resize(static_cast<std::size_t>(input.gcount()));
    return value;
}

std::string json_text(const Json& object, const char* key) {
    const auto found = object.find(key);
    if (found == object.end() || !found->is_string()) return {};
    const std::string value = found->get<std::string>();
    return value.size() <= MAX_TEXT_BYTES ? value : std::string{};
}

bool parse_unsigned(const std::string& value, std::uint64_t* output) {
    if (!output || value.empty() || value[0] == '-') return false;
    errno = 0;
    char* end = nullptr;
    const unsigned long long parsed = std::strtoull(value.c_str(), &end, 10);
    if (errno != 0 || end == value.c_str() || *end != '\0') return false;
    *output = static_cast<std::uint64_t>(parsed);
    return true;
}

bool parse_stat(const std::string& value, ProcessIdentity* identity) {
    if (!identity) return false;
    // The comm field may contain ')'. Parsing from its last ')' makes the tail
    // stable; tail index 19 is /proc stat field 22, the process start time.
    const auto close = value.rfind(')');
    if (close == std::string::npos || close + 2 >= value.size()) return false;
    std::istringstream tail(value.substr(close + 2));
    std::string token;
    for (int index = 0; index < 20; ++index) {
        if (!(tail >> token)) return false;
        if (index == 0) identity->state = token.empty() ? '?' : token[0];
        if (index == 1) {
            std::uint64_t ppid = 0;
            if (!parse_unsigned(token, &ppid) || ppid > static_cast<std::uint64_t>(INT32_MAX)) return false;
            identity->ppid = static_cast<pid_t>(ppid);
        }
        if (index == 19 && !parse_unsigned(token, &identity->start_ticks)) return false;
    }
    return identity->start_ticks != 0;
}

bool read_identity(pid_t pid, ProcessIdentity* identity) {
    if (!identity || pid <= 0) return false;
    // Read every identity component from the live /proc entry and fail closed
    // if any component disappears or cannot be read.
    ProcessIdentity current;
    current.pid = pid;
    current.boot_id = trim_line(bounded_read("/proc/sys/kernel/random/boot_id", 128));
    if (current.boot_id.empty() || !parse_stat(bounded_read("/proc/" + std::to_string(pid) + "/stat", 4096), &current)) return false;
    char buffer[4096];
    const ssize_t length = ::readlink(("/proc/" + std::to_string(pid) + "/exe").c_str(), buffer, sizeof(buffer) - 1);
    if (length <= 0) return false;
    buffer[length] = '\0';
    current.exe.assign(buffer, static_cast<std::size_t>(length));
    *identity = std::move(current);
    return true;
}

bool parse_instance_id(const std::string& value, ProcessIdentity* expected) {
    if (!expected || value.rfind("process:", 0) != 0) return false;
    const std::size_t boot_end = value.find(':', 8);
    const std::size_t pid_end = boot_end == std::string::npos ? boot_end : value.find(':', boot_end + 1);
    const std::size_t ticks_end = pid_end == std::string::npos ? pid_end : value.find(':', pid_end + 1);
    if (boot_end == std::string::npos || pid_end == std::string::npos || ticks_end == std::string::npos) return false;
    std::uint64_t pid = 0;
    if (!parse_unsigned(value.substr(boot_end + 1, pid_end - boot_end - 1), &pid) || pid > static_cast<std::uint64_t>(INT32_MAX)) return false;
    ProcessIdentity result;
    result.boot_id = value.substr(8, boot_end - 8);
    result.pid = static_cast<pid_t>(pid);
    if (!parse_unsigned(value.substr(pid_end + 1, ticks_end - pid_end - 1), &result.start_ticks)) return false;
    result.exe = value.substr(ticks_end + 1);
    if (result.boot_id.empty() || result.pid <= 0 || result.start_ticks == 0 || result.exe.empty()) return false;
    *expected = std::move(result);
    return true;
}

bool same_instance(const ProcessIdentity& expected, const ProcessIdentity& actual) {
    return expected.pid == actual.pid && expected.start_ticks == actual.start_ticks &&
           expected.boot_id == actual.boot_id && expected.exe == actual.exe;
}

bool protected_process(pid_t target) {
    // Do not stop the controller's own chain or the init boundary. This also
    // prevents an operator request from killing the process running the helper.
    if (target <= 2 || target == ::getpid()) return true;
    std::set<pid_t> seen;
    pid_t current = ::getpid();
    for (int depth = 0; current > 1 && depth < 128 && seen.insert(current).second; ++depth) {
        ProcessIdentity identity;
        if (!read_identity(current, &identity)) break;
        current = identity.ppid;
        if (current == target) return true;
    }
    return false;
}

int open_audit_log(const std::string& path) {
    if (path.empty()) return -1;
    // O_NOFOLLOW protects the final path component; fstat validates the actual
    // descriptor after open instead of trusting the earlier pathname lookup.
    struct stat before{};
    const bool exists = ::lstat(path.c_str(), &before) == 0;
    if (exists && (!S_ISREG(before.st_mode) || S_ISLNK(before.st_mode) || (before.st_mode & 077) != 0 ||
                   (before.st_uid != ::getuid() && before.st_uid != ::geteuid()))) return -1;
    const int descriptor = ::open(path.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0) return -1;
    struct stat after{};
    if (::fstat(descriptor, &after) != 0 || !S_ISREG(after.st_mode) || (after.st_mode & 077) != 0 ||
        (after.st_uid != ::getuid() && after.st_uid != ::geteuid())) {
        ::close(descriptor);
        return -1;
    }
    return descriptor;
}

std::string timestamp_utc() {
    const std::time_t now = std::time(nullptr);
    std::tm value{};
    if (!::gmtime_r(&now, &value)) return "1970-01-01T00:00:00Z";
    char buffer[32];
    if (::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &value) == 0) return "1970-01-01T00:00:00Z";
    return buffer;
}

bool write_audit(int descriptor, const Json& request, const ProcessIdentity& identity,
                 const std::string& phase, const std::string& result, const std::string& detail) {
    // The caller relies on fsync here: an ATTEMPT record must be durable before
    // a signal is allowed, and a RESULT record must survive the action.
    Json event{{"schema_version", 1}, {"timestamp_utc", timestamp_utc()}, {"phase", phase},
               {"result", result}, {"detail", detail}, {"action", json_text(request, "action")},
               {"finding_id", json_text(request, "finding_id")}, {"finding_type", json_text(request, "finding_type")},
               {"severity", json_text(request, "severity")}, {"confidence", json_text(request, "confidence")},
               {"reason", json_text(request, "reason")}, {"process_instance_id", json_text(request, "process_instance_id")},
               {"pid", identity.pid}, {"start_ticks", identity.start_ticks}, {"exe", identity.exe},
               {"actor_uid", ::getuid()}, {"actor_euid", ::geteuid()}};
    const std::string line = event.dump() + "\n";
    const ssize_t written = ::write(descriptor, line.data(), line.size());
    return written == static_cast<ssize_t>(line.size()) && ::fsync(descriptor) == 0;
}

int pidfd_open_for(pid_t pid) {
    // A pidfd binds the signal target to the inspected process rather than to a
    // numeric PID. The caller handles ENOSYS/EINVAL as an older-kernel fallback.
#ifdef SYS_pidfd_open
    return static_cast<int>(::syscall(SYS_pidfd_open, pid, 0));
#else
    (void)pid;
    errno = ENOSYS;
    return -1;
#endif
}

int send_signal(int pidfd, pid_t pid, int signal) {
#if defined(SYS_pidfd_send_signal)
    if (pidfd >= 0) return static_cast<int>(::syscall(SYS_pidfd_send_signal, pidfd, signal, nullptr, 0));
#else
    (void)pidfd;
#endif
    return ::kill(pid, signal);
}

bool wait_for_state(pid_t pid, char expected, bool disappearance_ok, unsigned timeout_ms) {
    // A successful signal syscall is not proof that the requested state took
    // effect; verify the kernel-visible process state before reporting success.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    do {
        ProcessIdentity current;
        if (!read_identity(pid, &current)) return disappearance_ok;
        if (expected == '\0') {
            if (current.state != 'T' && current.state != 't') return true;
        } else if (current.state == expected || (expected == 'T' && current.state == 't')) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    } while (std::chrono::steady_clock::now() < deadline);
    return false;
}

bool read_secure_file(const std::string& path, std::size_t limit, std::string* content) {
    if (path.empty() || !content) return false;
    // Open once with O_NOFOLLOW and parse the bytes from that descriptor, so a
    // symlink or replacement pathname cannot change the authorization input.
    const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return false;
    struct stat status{};
    if (::fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) || (status.st_mode & 077) != 0 ||
        (status.st_uid != ::getuid() && status.st_uid != ::geteuid()) || status.st_size <= 0 ||
        static_cast<std::uint64_t>(status.st_size) > limit) {
        ::close(descriptor);
        return false;
    }
    content->clear();
    content->reserve(static_cast<std::size_t>(status.st_size));
    char buffer[8192];
    while (content->size() <= limit) {
        const ssize_t count = ::read(descriptor, buffer, sizeof(buffer));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) { ::close(descriptor); return false; }
        if (count == 0) break;
        content->append(buffer, static_cast<std::size_t>(count));
    }
    ::close(descriptor);
    return !content->empty() && content->size() <= limit;
}

bool finding_authorizes(const Json& document, const Json& request, const ProcessIdentity& expected) {
    // A finding is an authorization binding, not just a severity label. Risk,
    // confidence, lifecycle, ID, and process instance must all agree.
    if (!document.is_object()) return false;
    const auto schema = document.find("schema_version");
    if (schema == document.end() || !schema->is_number_integer() ||
        schema->get<int>() < 3 || json_text(document, "platform") != "linux") return false;
    const auto findings = document.find("findings");
    if (findings == document.end() || !findings->is_array()) return false;
    const std::string requested_id = json_text(request, "finding_id");
    for (const auto& finding : *findings) {
        if (!finding.is_object() || json_text(finding, "id") != requested_id) continue;
        const std::string severity = json_text(finding, "severity");
        const std::string lifecycle = json_text(finding, "lifecycle");
        const bool active = lifecycle == "NEW" || lifecycle == "ONGOING" || lifecycle == "CHANGED" ||
                            lifecycle == "ESCALATED" || lifecycle == "REOPENED" || lifecycle == "UNTRACKED";
        return json_text(finding, "finding_type") == "SECURITY_THREAT" &&
               (severity == "HIGH" || severity == "CRITICAL") && json_text(finding, "confidence") == "HIGH" &&
               severity == json_text(request, "severity") &&
               json_text(finding, "finding_type") == json_text(request, "finding_type") &&
               json_text(finding, "confidence") == json_text(request, "confidence") && active &&
               json_text(finding, "process_instance_id") == json_text(request, "process_instance_id") &&
               expected.pid > 0;
    }
    return false;
}

void print_result(const std::string& status, const std::string& result, const ProcessIdentity& identity) {
    std::cout << Json{{"schema_version", 1}, {"status", status}, {"result", result},
                      {"pid", identity.pid}, {"start_ticks", identity.start_ticks}, {"exe", identity.exe}}.dump() << '\n';
}

}

int run_process_control(const Arguments& args) {
    const std::string request_path = argument(args, "--request");
    const std::string findings_path = argument(args, "--findings");
    const std::string audit_path = argument(args, "--audit-log");
    // Parse all authorization inputs before touching the target process. Any
    // malformed, stale, or incomplete request must stop before the signal path.
    std::string content;
    if (!read_secure_file(request_path, MAX_REQUEST_BYTES, &content)) {
        std::cerr << "request must be a non-empty regular file owned by the invoking user with mode 0600 or stricter\n";
        return 2;
    }
    Json request;
    try {
        request = Json::parse(content);
    } catch (const std::exception& error) {
        std::cerr << "invalid process-control request: " << error.what() << '\n';
        return 2;
    }
    if (!request.is_object()) {
        std::cerr << "process-control request must be a JSON object\n";
        return 2;
    }
    const auto request_schema = request.find("schema_version");
    if (request_schema == request.end() || !request_schema->is_number_integer() || request_schema->get<int>() != 1) {
        std::cerr << "unsupported process-control request schema\n";
        return 2;
    }
    const std::string action = json_text(request, "action");
    const std::string finding_type = json_text(request, "finding_type");
    const std::string severity = json_text(request, "severity");
    const std::string confidence = json_text(request, "confidence");
    const std::string confirmation = json_text(request, "confirmation");
    const std::string reason = json_text(request, "reason");
    ProcessIdentity expected;
    if (!parse_instance_id(json_text(request, "process_instance_id"), &expected) || json_text(request, "finding_id").empty() || reason.empty()) {
        std::cerr << "process_instance_id, finding_id, and reason are required\n";
        return 2;
    }
    if (finding_type != "SECURITY_THREAT" || (severity != "HIGH" && severity != "CRITICAL") || confidence != "HIGH") {
        std::cerr << "process control requires a HIGH-confidence HIGH/CRITICAL SECURITY_THREAT\n";
        return 3;
    }
    std::string findings_content;
    if (!read_secure_file(findings_path, MAX_FINDINGS_BYTES, &findings_content)) {
        std::cerr << "findings must be a secure non-empty findings.json file\n";
        return 2;
    }
    Json findings;
    try {
        findings = Json::parse(findings_content);
    } catch (const std::exception& error) {
        std::cerr << "invalid findings document: " << error.what() << '\n';
        return 2;
    }
    if (!finding_authorizes(findings, request, expected)) {
        std::cerr << "finding does not authorize this process instance or action threshold\n";
        return 3;
    }
    // Literal action/confirmation pairs make accidental destructive calls
    // impossible through a typo or a partially populated request.
    int signal = 0;
    char expected_state = '?';
    bool disappearance_ok = false;
    unsigned timeout_ms = 1000;
    if (action == "contain" && confirmation == "CONTAIN") { signal = SIGSTOP; expected_state = 'T'; }
    else if (action == "release" && confirmation == "RELEASE") { signal = SIGCONT; expected_state = '\0'; }
    else if (action == "terminate" && confirmation == "TERMINATE") { signal = SIGTERM; disappearance_ok = true; timeout_ms = 2000; }
    else if (action == "kill" && confirmation == "KILL") {
        const auto destructive = request.find("allow_destructive");
        if (destructive != request.end() && destructive->is_boolean() && destructive->get<bool>()) {
            signal = SIGKILL; disappearance_ok = true; timeout_ms = 2000;
        }
    }
    else {
        std::cerr << "action confirmation is missing or invalid\n";
        return 3;
    }
    if (signal == 0) {
        std::cerr << "destructive process control requires allow_destructive=true\n";
        return 3;
    }
    // Check target safety before creating audit state or attempting delivery.
    if (protected_process(expected.pid)) {
        std::cerr << "refusing to control PID 1/2, self, or an ancestor process\n";
        return 3;
    }
    ProcessIdentity actual;
    if (!read_identity(expected.pid, &actual) || !same_instance(expected, actual)) {
        std::cerr << "process instance no longer matches the request\n";
        return 3;
    }
    const int audit = open_audit_log(audit_path);
    if (audit < 0) {
        std::cerr << "audit log must be a secure regular file with mode 0600 or stricter\n";
        return 2;
    }
    // Persist operator intent before opening the pidfd or sending a signal.
    // Missing ATTEMPT evidence is a hard stop.
    if (!write_audit(audit, request, actual, "ATTEMPT", "AUTHORIZED", "identity_verified")) {
        ::close(audit);
        std::cerr << "cannot persist process-control audit intent\n";
        return 2;
    }
    const int pidfd = pidfd_open_for(actual.pid);
    if (pidfd < 0 && errno != ENOSYS && errno != EINVAL) {
        write_audit(audit, request, actual, "RESULT", "FAILED", std::string("pidfd_open:") + std::strerror(errno));
        ::close(audit);
        return 4;
    }
    // Recheck after pidfd_open to close the last pre-signal identity window on
    // kernels that need the numeric-PID fallback.
    ProcessIdentity rechecked;
    if (!read_identity(expected.pid, &rechecked) || !same_instance(expected, rechecked)) {
        write_audit(audit, request, actual, "RESULT", "REJECTED", "identity_changed_before_signal");
        if (pidfd >= 0) ::close(pidfd);
        ::close(audit);
        return 3;
    }
    // Use pidfd_send_signal when available; send_signal falls back only on
    // kernels that do not expose the pidfd syscall.
    if (send_signal(pidfd, actual.pid, signal) != 0) {
        const std::string detail = std::string("signal_failed:") + std::strerror(errno);
        write_audit(audit, request, actual, "RESULT", "FAILED", detail);
        if (pidfd >= 0) ::close(pidfd);
        ::close(audit);
        std::cerr << detail << '\n';
        return 4;
    }
    if (pidfd >= 0) ::close(pidfd);
    const bool verified = wait_for_state(actual.pid, expected_state, disappearance_ok, timeout_ms);
    const std::string result = verified ? "SUCCESS" : "PARTIAL";
    const std::string detail = verified ? "signal_effect_verified" : "signal_sent_but_effect_not_verified";
    const bool audited = write_audit(audit, request, actual, "RESULT", result, detail);
    ::close(audit);
    if (!audited) {
        std::cerr << "signal sent but result audit failed\n";
        return 5;
    }
    print_result(verified ? "SUCCESS" : "PARTIAL", action, actual);
    return verified ? 0 : 5;
}

}
