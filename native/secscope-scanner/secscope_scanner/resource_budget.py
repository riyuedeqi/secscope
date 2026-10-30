"""Worker budget from host resources. Mirror of resource_budget.cpp."""
import math
import os

from .types import ResourceBudget


def _env_uint(name, fallback):
    value = os.environ.get(name)
    if not value:
        return fallback
    try:
        parsed = int(value, 10)
    except ValueError:
        return fallback
    if parsed <= 0 or parsed > 1000000:
        return fallback
    return parsed


def _env_double(name, fallback):
    value = os.environ.get(name)
    if not value:
        return fallback
    try:
        parsed = float(value)
    except ValueError:
        return fallback
    if not (parsed > 0.0 and parsed <= 1000.0):
        return fallback
    return parsed


def _available_memory_mb():
    try:
        with open("/proc/meminfo", "r") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 3 and parts[0] == "MemAvailable:":
                    return int(parts[1]) // 1024
    except (OSError, ValueError):
        pass
    try:
        pagesize = os.sysconf("SC_PAGE_SIZE")
        available = os.sysconf("SC_AVPHYS_PAGES")
        if pagesize > 0 and available > 0:
            return pagesize * available // (1024 * 1024)
    except (OSError, ValueError):
        pass
    return 0


def _load_average():
    try:
        with open("/proc/loadavg", "r") as handle:
            value = float(handle.read().split()[0])
        if math.isfinite(value) and value >= 0.0:
            return value
    except (OSError, ValueError, IndexError):
        pass
    return 0.0


def _psi_avg10(path):
    try:
        with open(path, "r") as handle:
            for line in handle:
                marker = line.find("avg10=")
                if marker < 0:
                    continue
                text = line[marker + 6:].strip()
                try:
                    value = float(text.split()[0] if text else text)
                except ValueError:
                    continue
                if math.isfinite(value) and value >= 0.0:
                    return value
    except (OSError, ValueError):
        pass
    return 0.0


def _rotational_storage_for(roots):
    path = roots[0] if roots else "/"
    try:
        status = os.stat(path)
    except OSError:
        return False
    major = os.major(status.st_dev)
    minor = os.minor(status.st_dev)
    device = "/sys/dev/block/%d:%d/queue/rotational" % (major, minor)
    try:
        with open(device, "r") as handle:
            return int(handle.read().strip()) != 0
    except (OSError, ValueError):
        return False


def resolve_budget(config):
    budget = ResourceBudget()
    try:
        online = os.sysconf("SC_NPROCESSORS_ONLN")
    except (OSError, ValueError):
        online = -1
    budget.vcpus = min(online, 1000000) if online > 0 else 1
    profile_cap = min(budget.vcpus, 8) if config.profile == "full" else min(budget.vcpus, 4)
    requested = _env_uint("SECSCOPE_NATIVE_WORKERS", profile_cap)
    budget.workers = max(1, min(requested, profile_cap))
    available = _available_memory_mb()
    default_memory = min(256, max(64, available // 8))
    budget.max_memory_mb = _env_uint("SECSCOPE_NATIVE_MAX_MEMORY_MB", default_memory)
    budget.max_load_factor = _env_double("SECSCOPE_NATIVE_MAX_LOAD_FACTOR", 1.5)
    budget.stage_timeout_seconds = _env_uint("SECSCOPE_NATIVE_STAGE_TIMEOUT", config.timeout_seconds)
    budget.io_psi_avg10 = _psi_avg10("/proc/pressure/io")
    budget.memory_psi_avg10 = _psi_avg10("/proc/pressure/memory")
    budget.rotational_storage = _rotational_storage_for(config.roots)
    # Busy hosts keep the same scan limits and lower only native worker
    # parallelism. A high load must not turn a complete inspection into a
    # skipped inspection.
    if _load_average() > float(budget.vcpus) * budget.max_load_factor:
        budget.workers = 1
        budget.constrained = True
    if 0 < available < 512:
        budget.workers = 1
    elif 0 < available < 1024:
        budget.workers = min(budget.workers, 2)
    if budget.io_psi_avg10 >= 10.0 or budget.memory_psi_avg10 >= 5.0:
        budget.workers = min(budget.workers, 2)
    if budget.rotational_storage and budget.workers > 2:
        budget.workers = 2
    if budget.workers > 1 and budget.max_memory_mb // budget.workers < 16:
        budget.workers = 1
    budget.constrained = budget.workers < profile_cap or (0 < available < 1024)
    return budget


def budget_available(budget):
    # Load is handled by resolve_budget() through worker reduction. Do not
    # reject the scan: traversal depth, file count and timeout are detection
    # limits and must remain unchanged by host contention.
    del budget
    return True
