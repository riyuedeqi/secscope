"""SecScope local cache daemon, Python implementation.

Ported 1:1 from the former C++ sources; the length-prefixed JSON protocol,
storage snapshot format and CLI are unchanged.
"""

PROTOCOL_VERSION = 1
MAX_FRAME = 1024 * 1024
