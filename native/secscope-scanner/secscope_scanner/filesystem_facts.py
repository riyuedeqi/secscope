"""Whole-filesystem fact collection (suid/unowned/large/recent/persistence). Mirror of filesystem_facts.cpp."""
import errno
import grp
import os
import pwd
import stat as stat_module
import sys
import time

from .native_io import (AtomicOutput, absolute_lexical_path, argument, dumps_json,
                        required_arguments, uint_argument)

MAX_PATH_BYTES = 4096
MAX_FILES = 50000000
MAX_DIRS = 5000000

_PERSISTENCE_EXACT = {"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
                      "/etc/sudoers", "/etc/crontab", "/etc/ld.so.preload", "/etc/rc.local",
                      "/etc/profile"}
_PERSISTENCE_PREFIXES = ("/etc/sudoers.d/", "/etc/cron.d/", "/var/spool/cron/", "/etc/pam.d/",
                         "/etc/systemd/system/", "/etc/profile.d/")
_PERSISTENCE_SUFFIXES = ("/.ssh/authorized_keys", "/.bashrc", "/.bash_profile", "/.profile",
                         "/.zshrc")


class Outputs(object):
    def __init__(self, args):
        self.suid = AtomicOutput(argument(args, "--suid-output"))
        self.weird_suid = AtomicOutput(argument(args, "--weird-suid-output"))
        self.unowned = AtomicOutput(argument(args, "--unowned-output"))
        self.large = AtomicOutput(argument(args, "--large-output"))
        self.recent = AtomicOutput(argument(args, "--recent-output"))
        self.persistence = AtomicOutput(argument(args, "--persistence-output"))
        self.coverage = AtomicOutput(argument(args, "--coverage-jsonl"))

    def good(self):
        return all(output.good() for output in
                   (self.suid, self.weird_suid, self.unowned, self.large,
                    self.recent, self.persistence, self.coverage))

    def all_streams(self):
        return (self.suid, self.weird_suid, self.unowned, self.large,
                self.recent, self.persistence, self.coverage)

    def commit(self):
        return all(output.commit() for output in self.all_streams())

    def close(self):
        for output in self.all_streams():
            output.close()


class Facts(object):
    def __init__(self):
        self.visited = 0
        self.files = 0
        self.directories = 0
        self.stat_calls = 0
        self.symlink_skipped = 0
        self.permission_denied = 0
        self.disappeared = 0
        self.unrepresentable = 0
        self.suid = 0
        self.weird_suid = 0
        self.unowned = 0
        self.large = 0
        self.recent = 0
        self.persistence = 0
        self.partial = False
        self.reason = ""


def mark_partial(facts, reason):
    facts.partial = True
    if not facts.reason and reason:
        facts.reason = reason


def unsafe_path(path):
    return (not path or len(path) > MAX_PATH_BYTES or "\t" in path or
            "\r" in path or "\n" in path)


def under(path, prefix):
    return path == prefix or path.startswith(prefix + "/")


def excluded_root_tree(path, root):
    if root != "/":
        return False
    return under(path, "/proc") or under(path, "/sys") or under(path, "/snap")


def lookup_user(uid, cache):
    if uid in cache:
        return cache[uid]
    try:
        pwd.getpwuid(uid)
        present = True
    except KeyError:
        present = False
    cache[uid] = present
    return present


def lookup_group(gid, cache):
    if gid in cache:
        return cache[gid]
    try:
        grp.getgrgid(gid)
        present = True
    except KeyError:
        present = False
    cache[gid] = present
    return present


def persistence_path(path):
    if path in _PERSISTENCE_EXACT:
        return True
    for prefix in _PERSISTENCE_PREFIXES:
        if path.startswith(prefix):
            return True
    for suffix in _PERSISTENCE_SUFFIXES:
        if path.endswith(suffix):
            return True
    return False


def child_path(directory, name):
    return ("/" + name) if directory == "/" else (directory + "/" + name)


def visit_directory(root, directory, depth, max_depth, root_dev, deadline, max_files,
                    recent_cutoff, outputs, facts, users, groups):
    if time.monotonic() >= deadline:
        mark_partial(facts, "timeout")
        return False
    try:
        entries = list(os.scandir(directory))
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            facts.permission_denied += 1
            mark_partial(facts, "permission_denied")
        else:
            facts.disappeared += 1
            mark_partial(facts, "directory_open_failed")
        return False
    facts.directories += 1
    for entry in entries:
        if time.monotonic() >= deadline:
            mark_partial(facts, "timeout")
            break
        if facts.files >= max_files:
            mark_partial(facts, "max_files")
            break
        if entry.name in (".", ".."):
            continue
        facts.visited += 1
        path = child_path(directory, entry.name)
        if excluded_root_tree(path, root):
            continue
        facts.stat_calls += 1
        try:
            status = entry.stat(follow_symlinks=False)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EPERM):
                facts.permission_denied += 1
                mark_partial(facts, "permission_denied")
            elif exc.errno == errno.ENOENT:
                facts.disappeared += 1
                mark_partial(facts, "file_disappeared")
            else:
                mark_partial(facts, "file_disappeared")
            continue
        if stat_module.S_ISLNK(status.st_mode):
            facts.symlink_skipped += 1
            continue
        if stat_module.S_ISDIR(status.st_mode):
            if status.st_dev != root_dev:
                continue
            if depth >= max_depth:
                mark_partial(facts, "max_depth")
                continue
            if facts.directories >= MAX_DIRS:
                mark_partial(facts, "directory_budget")
                break
            visit_directory(root, path, depth + 1, max_depth, root_dev, deadline,
                            max_files, recent_cutoff, outputs, facts, users, groups)
            continue
        if not stat_module.S_ISREG(status.st_mode):
            continue
        facts.files += 1
        if unsafe_path(path):
            facts.unrepresentable += 1
            mark_partial(facts, "unrepresentable_path")
            continue
        suid = bool(status.st_mode & (stat_module.S_ISUID | stat_module.S_ISGID))
        weird = suid and (under(path, "/tmp") or under(path, "/dev/shm") or
                          under(path, "/var/tmp") or under(path, "/home"))
        unowned = not lookup_user(status.st_uid, users) or not lookup_group(status.st_gid, groups)
        large = max(status.st_size, 0) > 200 * 1024 * 1024
        recent = max(int(status.st_mtime), 0) >= recent_cutoff
        persistence = persistence_path(path)
        if suid:
            outputs.suid.write(path + "\n")
            facts.suid += 1
        if weird:
            outputs.weird_suid.write(path + "\n")
            facts.weird_suid += 1
        if unowned:
            outputs.unowned.write(path + "\n")
            facts.unowned += 1
        if large:
            outputs.large.write(path + "\n")
            facts.large += 1
        if recent:
            outputs.recent.write("%s\t%d\n" % (path, int(status.st_mtime)))
            facts.recent += 1
        if persistence:
            outputs.persistence.write(path + "\n")
            facts.persistence += 1
    return not facts.partial


def run_filesystem_facts(args):
    ok, error = required_arguments(args, ["--root", "--suid-output", "--weird-suid-output",
                                          "--unowned-output", "--large-output",
                                          "--recent-output", "--persistence-output",
                                          "--coverage-jsonl"])
    if not ok:
        sys.stderr.write(error + "\n")
        return 2
    root = absolute_lexical_path(argument(args, "--root"))
    try:
        root_status = os.lstat(root)
    except OSError:
        root_status = None
    if root_status is None or not stat_module.S_ISDIR(root_status.st_mode) or \
            stat_module.S_ISLNK(root_status.st_mode):
        sys.stderr.write("root must be a non-symlink directory\n")
        return 2
    timeout = uint_argument(args, "--timeout-seconds", 900, 1, 86400)
    max_depth = uint_argument(args, "--max-depth", 64, 0, 64)
    max_files = uint_argument(args, "--max-files", MAX_FILES, 1, MAX_FILES)
    recent_seconds = uint_argument(args, "--recent-seconds", 7 * 86400, 0, 10 * 365 * 86400)
    now = int(time.time())
    recent_cutoff = now - recent_seconds if now > recent_seconds else 0
    outputs = Outputs(args)
    if not outputs.good():
        outputs.close()
        sys.stderr.write("cannot create filesystem facts output\n")
        return 2
    facts = Facts()
    users = {}
    groups = {}
    visit_directory(root, root, 0, max_depth, root_status.st_dev,
                    time.monotonic() + timeout, max_files, recent_cutoff,
                    outputs, facts, users, groups)
    outputs.coverage.write(dumps_json({
        "record_type": "summary", "root": root, "files": facts.files,
        "directories": facts.directories, "visited": facts.visited,
        "stat_calls": facts.stat_calls, "suid": facts.suid, "weird_suid": facts.weird_suid,
        "unowned": facts.unowned, "large": facts.large, "recent": facts.recent,
        "persistence": facts.persistence, "symlink_skipped": facts.symlink_skipped,
        "permission_denied": facts.permission_denied, "disappeared": facts.disappeared,
        "unrepresentable": facts.unrepresentable, "partial": facts.partial,
        "reason": facts.reason}) + "\n")
    committed = outputs.commit()
    outputs.close()
    if not committed:
        return 3
    sys.stdout.write(dumps_json({"status": "PARTIAL" if facts.partial else "SUCCESS",
                                 "root": root, "files": facts.files,
                                 "directories": facts.directories, "suid": facts.suid,
                                 "unowned": facts.unowned, "large": facts.large,
                                 "recent": facts.recent, "persistence": facts.persistence,
                                 "partial": facts.partial, "reason": facts.reason}) + "\n")
    return 0
