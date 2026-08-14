#!/usr/bin/env python3
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("binary_analyzer", str(ROOT / "helpers" / "binary_analyzer.py"))
binary = importlib.util.module_from_spec(spec); spec.loader.exec_module(binary)


def main():
    strings = binary.extract_strings(b"OpenProcess VirtualAllocEx WriteProcessMemory CreateRemoteThread harmless fixture text")
    combos = binary.api_combinations([], strings)
    assert any(x["name"] == "process_injection" for x in combos)
    weak = binary.api_combinations(["socket"], binary.extract_strings(b"socket connect http powershell"))
    assert not any(x["name"] in ("process_injection", "encrypted_periodic_client", "script_download_execute") for x in weak)
    loader = binary.api_combinations(["VirtualAlloc", "VirtualProtect", "CreateThread"], binary.extract_strings(b"bounded text fixture"))
    assert any(x["name"] == "memory_loader" for x in loader)
    reverse = binary.api_combinations(["socket", "connect", "dup2", "execve"], binary.extract_strings(b"bounded fixture"))
    assert any(x["name"] == "reverse_connection_shell" for x in reverse)
    memfd = binary.api_combinations(["memfd_create", "mmap", "mprotect"], binary.extract_strings(b"bounded fixture"))
    assert any(x["name"] == "memfd_loader" for x in memfd)
    assert binary.entropy(b"A" * 4096) < 0.1
    print("binary analyzer tests: OK")


if __name__ == "__main__": main()
