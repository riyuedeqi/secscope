"""Cache daemon main loop. Mirror of cache-daemon.cpp.

The SO_PEERCRED owner check is Linux-only; on other platforms the socket
option is absent and every peer is denied, matching the former C++ daemon
(getsockopt failure path). Like the C++ version this daemon targets Linux.
"""
import os
import signal
import socket
import struct
import sys

from .protocol import json_response, read_frame, request_command, request_value, write_frame
from .storage import Storage

SO_PEERCRED = getattr(socket, "SO_PEERCRED", None)
_UCRED = struct.Struct("3i")
STOP = [False]


def _on_signal(_signum, _frame):
    STOP[0] = True


def _peer_uid(conn):
    if SO_PEERCRED is None:
        return None
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, _UCRED.size)
        return _UCRED.unpack(raw)[1]
    except (OSError, struct.error):
        return None


def main(argv):
    socket_path = "/run/secscope-cache/cache.sock"
    storage_path = "/var/lib/secscope/cache.snapshot"
    index = 0
    while index < len(argv):
        if argv[index] == "--socket" and index + 1 < len(argv):
            index += 1
            socket_path = argv[index]
        elif argv[index] == "--storage" and index + 1 < len(argv):
            index += 1
            storage_path = argv[index]
        index += 1
    directory = os.path.dirname(socket_path)
    if directory:
        try:
            os.makedirs(directory, exist_ok=True)
            os.chmod(directory, 0o700)
        except OSError:
            return 2
    try:
        os.unlink(socket_path)
    except OSError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(socket_path)
        os.chmod(socket_path, 0o600)
        server.listen(16)
    except OSError:
        server.close()
        return 2
    storage = Storage(storage_path)
    storage.load()
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    server.settimeout(1.0)
    try:
        while not STOP[0]:
            try:
                conn, _addr = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            # 读路径的 socket 超时/重置只影响当前连接（对齐 C++ SO_RCVTIMEO
            # 语义），绝不能穿出主循环杀死 daemon。
            try:
                with conn:
                    conn.settimeout(5.0)
                    peer = _peer_uid(conn)
                    if peer is None or peer != os.getuid():
                        write_frame(conn.send, json_response("DENIED"))
                        continue
                    payload = read_frame(conn.recv)
                    if payload is None:
                        continue
                    command = request_command(payload)
                    key = request_value(payload, "key")
                    value = request_value(payload, "value")
                    if command in ("ping", "health"):
                        response = json_response("OK", "pong" if command == "ping" else "healthy")
                    elif command == "reset":
                        storage.reset()
                        response = json_response("OK", "reset")
                    elif command == "get_cached_hash":
                        cached = storage.get(key)
                        response = json_response("HIT", cached) if cached is not None \
                            else json_response("MISS")
                    elif command == "update_hash":
                        response = json_response("OK") if storage.put(key, value) \
                            else json_response("FAILED", "storage")
                    elif command in ("commit_baseline", "checkpoint", "file_snapshot",
                                     "file_delta", "process_snapshot"):
                        response = json_response("OK", "accepted")
                    else:
                        response = json_response("INVALID", "unknown_command")
                    write_frame(conn.send, response)
            except OSError:
                continue
    finally:
        server.close()
        try:
            os.unlink(socket_path)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
