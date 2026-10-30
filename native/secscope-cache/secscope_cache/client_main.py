"""Cache client CLI. Mirror of cache-client.cpp."""
import socket
import sys

from .protocol import read_frame, write_frame


def main(argv):
    if not argv:
        return 2
    path = "/run/secscope-cache/cache.sock"
    if argv[0] == "--socket":
        if len(argv) < 3 or not argv[1]:
            return 2
        path = argv[1]
        argv = argv[2:]
    if not argv or not argv[0]:
        return 2
    request = argv[0]
    if not request.startswith("{"):
        request = '{"schema_version":1,"command":"%s"}' % request
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(path)
    except OSError:
        sock.close()
        return 3
    try:
        ok = write_frame(sock.send, request)
        response = read_frame(sock.recv) if ok else None
    finally:
        sock.close()
    if not ok or response is None:
        return 4
    sys.stdout.write(response + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
