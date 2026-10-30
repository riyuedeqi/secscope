"""Length-prefixed frame protocol and JSON helpers. Mirror of protocol.cpp."""
import json
import struct

from . import MAX_FRAME

_HEADER = struct.Struct("!I")


def read_exact(receiver, count):
    chunks = []
    got = 0
    while got < count:
        chunk = receiver(count - got)
        if not chunk:
            return None
        chunks.append(chunk)
        got += len(chunk)
    return b"".join(chunks)


def read_frame(receiver):
    header = read_exact(receiver, _HEADER.size)
    if header is None:
        return None
    length = _HEADER.unpack(header)[0]
    if length == 0 or length > MAX_FRAME:
        return None
    payload = read_exact(receiver, length)
    if payload is None:
        return None
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return None


def write_frame(sender, payload):
    if not payload or len(payload.encode("utf-8", "surrogateescape")) > MAX_FRAME:
        return False
    data = payload.encode("utf-8", "surrogateescape")
    try:
        sender(_HEADER.pack(len(data)))
        sender(data)
    except OSError:
        return False
    return True


def request_value(text, key):
    if len(text) > MAX_FRAME:
        return ""
    try:
        obj = json.loads(text)
    except ValueError:
        return ""
    if not isinstance(obj, dict):
        return ""
    value = obj.get(key)
    return value if isinstance(value, str) else ""


def request_command(payload):
    return request_value(payload, "command")


def json_response(status, detail=""):
    return ('{"schema_version":1,"protocol_version":1,"status":%s,"detail":%s}' % (
        json.dumps(status, ensure_ascii=False),
        json.dumps(detail[:65536], ensure_ascii=False)))
