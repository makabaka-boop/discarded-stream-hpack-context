#!/usr/bin/env python3
"""h2audit - HTTP/2 one-direction capture auditor with stream filtering.

Reads the raw frame bytes of ONE captured direction (client->server or
server->client) plus a list of stream IDs to drop, reassembles
HEADERS/CONTINUATION blocks, and decodes HPACK manually: integer coding,
string literals, indexed/literal representations, dynamic-table capacity
updates and per-entry eviction are all implemented here.  Only the Huffman
string primitive is delegated to a mature component (hpack.huffman_table
when installed, otherwise an embedded RFC 7541 Appendix B table decoder).
The whole header block is NEVER handed to a ready-made HPACK decoder.

Rules implemented (per audit contract):

* negotiated dynamic-table limit is fixed at 256 bytes; capture <= 16 KiB;
* TLS, server push and flow control are out of scope (PUSH_PROMISE aborts);
* a frame interleaved before the current header block ends (missing
  CONTINUATION) is a connection error;
* dropped streams' blocks are still fully decoded and advance the shared
  dynamic table, their fields are just not delivered;
* kept streams are emitted as ordered header lists with per-field
  reference sources; duplicate fields are never collapsed;
* a list with more than 64 fields is rejected (not delivered) but its
  compression instructions are still consumed and the connection goes on;
* illegal index, illegal table-size update or bad Huffman stops the whole
  connection -- no state guessing afterwards.

Exit codes: 0 = capture consumed, 1 = usage/IO error, 2 = connection error
(audit stopped; partial results and the error are still reported as JSON).
"""

from __future__ import annotations

import argparse
import json
import sys

# --------------------------------------------------------------------------
# Audit contract constants
# --------------------------------------------------------------------------

MAX_CAPTURE_BYTES = 16 * 1024   # total capture never exceeds 16 KiB
HEADER_TABLE_LIMIT = 256        # negotiated dynamic table size (fixed)
MAX_FIELDS_PER_LIST = 64        # lists with more fields are rejected only

CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

# Frame types (RFC 7540)
FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_PRIORITY = 0x2
FRAME_RST_STREAM = 0x3
FRAME_SETTINGS = 0x4
FRAME_PUSH_PROMISE = 0x5
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_WINDOW_UPDATE = 0x8
FRAME_CONTINUATION = 0x9

FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLAG_PRIORITY = 0x20

STATIC_TABLE_SIZE = 61


# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------

class UsageError(Exception):
    """Bad invocation or unreadable/oversized input (exit 1)."""


class H2ConnectionError(Exception):
    """Connection-level error: the audit stops, no state guessing (exit 2)."""

    def __init__(self, message: str, offset: int | None = None):
        super().__init__(message)
        self.offset = offset
        self.partial_report: dict | None = None


class HPACKError(H2ConnectionError):
    """HPACK decoding error: illegal index / size update / bad Huffman."""


# --------------------------------------------------------------------------
# Huffman string primitive (the only part delegated to a mature component)
# --------------------------------------------------------------------------

def _huffman_decode_with_hpack(data: bytes) -> bytes:
    # Mature component: hpack's table-driven Huffman decoder.  It rejects
    # EOS symbols, non-EOS padding and padding longer than 7 bits.
    from hpack.exceptions import HPACKDecodingError
    from hpack.huffman_table import decode_huffman

    try:
        return decode_huffman(data)
    except HPACKDecodingError as exc:
        raise HPACKError(f"bad Huffman string: {exc}") from exc


# RFC 7541 Appendix B: (code, bit-length) for symbols 0..255 plus EOS (256).
# Embedded so the auditor still works where the hpack package is absent.
_HUFFMAN_TABLE = [
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28), (0xfffffe4, 28), (0xfffffe5, 28),
    (0xfffffe6, 28), (0xfffffe7, 28), (0xfffffe8, 28), (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9,
    28), (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28), (0xfffffed, 28),
    (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28), (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe,
    30), (0xffffff3, 28), (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28),
    (0xffffff8, 28), (0xffffff9, 28), (0xffffffa, 28), (0xffffffb, 28), (0x14, 6), (0x3f8, 10),
    (0x3f9, 10), (0xffa, 12), (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11), (0x3fa, 10), (0x3fb,
    10), (0xf9, 8), (0x7fb, 11), (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6), (0x0, 5), (0x1, 5),
    (0x2, 5), (0x19, 6), (0x1a, 6), (0x1b, 6), (0x1c, 6), (0x1d, 6), (0x1e, 6), (0x1f, 6), (0x5c, 7),
    (0xfb, 8), (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10), (0x1ffa, 13), (0x21, 6), (0x5d, 7),
    (0x5e, 7), (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7), (0x63, 7), (0x64, 7), (0x65, 7), (0x66,
    7), (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7), (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7),
    (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7), (0xfc, 8), (0x73, 7), (0xfd, 8), (0x1ffb, 13),
    (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6), (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4,
    5), (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6), (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7), (0x28,
    6), (0x29, 6), (0x2a, 6), (0x7, 5), (0x2b, 6), (0x76, 7), (0x2c, 6), (0x8, 5), (0x9, 5), (0x2d,
    6), (0x77, 7), (0x78, 7), (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15), (0x7fc, 11), (0x3ffd,
    14), (0x1ffd, 13), (0xffffffc, 28), (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20),
    (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22), (0x7fffd9, 23), (0x3fffd6, 22), (0x7fffda, 23),
    (0x7fffdb, 23), (0x7fffdc, 23), (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
    (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23), (0xffffee, 24), (0x7fffe1, 23),
    (0x7fffe2, 23), (0x7fffe3, 23), (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23),
    (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24), (0x3fffda, 22), (0x1fffdd, 21),
    (0xfffe9, 20), (0x3fffdb, 22), (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21),
    (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22), (0xfffff0, 24), (0x1fffdf, 21), (0x3fffdf, 22),
    (0x7fffeb, 23), (0x7fffec, 23), (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
    (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23), (0xfffea, 20), (0x3fffe2, 22),
    (0x3fffe3, 22), (0x3fffe4, 22), (0x7ffff0, 23), (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23),
    (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19), (0x3fffe7, 22), (0x7ffff2, 23),
    (0x3fffe8, 22), (0x1ffffec, 25), (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde,
    27), (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25), (0x7fff2, 19), (0x1fffe3,
    21), (0x3ffffe6, 26), (0x7ffffe0, 27), (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27),
    (0xfffff2, 24), (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26), (0xffffffd,
    28), (0x7ffffe3, 27), (0x7ffffe4, 27), (0x7ffffe5, 27), (0xfffec, 20), (0xfffff3, 24), (0xfffed,
    20), (0x1fffe6, 21), (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23), (0x3fffea,
    22), (0x3fffeb, 22), (0x1ffffee, 25), (0x1ffffef, 25), (0xfffff4, 24), (0xfffff5, 24),
    (0x3ffffea, 26), (0x7ffff4, 23), (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed,
    26), (0x7ffffe7, 27), (0x7ffffe8, 27), (0x7ffffe9, 27), (0x7ffffea, 27), (0x7ffffeb, 27),
    (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27), (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0,
    27), (0x3ffffee, 26), (0x3fffffff, 30),
]


def _build_huffman_tree() -> dict:
    root: dict = {}
    for symbol, (code, nbits) in enumerate(_HUFFMAN_TABLE):
        node = root
        for shift in range(nbits - 1, -1, -1):
            node = node.setdefault((code >> shift) & 1, {})
        node["sym"] = symbol
    return root


_HUFFMAN_TREE = _build_huffman_tree()
_EOS_SYMBOL = 256


def _huffman_decode_embedded(data: bytes) -> bytes:
    out = bytearray()
    node = _HUFFMAN_TREE
    pending = 0      # bits accumulated since last emitted symbol
    pending_len = 0
    for byte in data:
        for shift in range(7, -1, -1):
            bit = (byte >> shift) & 1
            pending = (pending << 1) | bit
            pending_len += 1
            node = node.get(bit)
            if node is None:
                raise HPACKError("bad Huffman string: no matching code")
            symbol = node.get("sym")
            if symbol is not None:
                if symbol == _EOS_SYMBOL:
                    raise HPACKError("bad Huffman string: EOS symbol in input")
                out.append(symbol)
                node = _HUFFMAN_TREE
                pending = 0
                pending_len = 0
    # Leftover bits must be a strict prefix of EOS (all ones), at most 7 bits.
    if pending_len > 7 or pending != (1 << pending_len) - 1:
        raise HPACKError("bad Huffman string: invalid padding")
    return bytes(out)


def _select_huffman_decoder():
    try:
        import hpack.huffman_table  # noqa: F401  (mature component present)
    except ImportError:
        return _huffman_decode_embedded
    return _huffman_decode_with_hpack


huffman_decode = _select_huffman_decoder()


# --------------------------------------------------------------------------
# HPACK static table (RFC 7541 Appendix A), 1-based
# --------------------------------------------------------------------------

STATIC_TABLE: list[tuple[bytes, bytes]] = [
    (b":authority", b""),
    (b":method", b"GET"), (b":method", b"POST"),
    (b":path", b"/"), (b":path", b"/index.html"),
    (b":scheme", b"http"), (b":scheme", b"https"),
    (b":status", b"200"), (b":status", b"204"), (b":status", b"206"),
    (b":status", b"304"), (b":status", b"400"), (b":status", b"404"),
    (b":status", b"500"),
    (b"accept-charset", b""), (b"accept-encoding", b"gzip, deflate"),
    (b"accept-language", b""), (b"accept-ranges", b""), (b"accept", b""),
    (b"access-control-allow-origin", b""), (b"age", b""), (b"allow", b""),
    (b"authorization", b""), (b"cache-control", b""),
    (b"content-disposition", b""), (b"content-encoding", b""),
    (b"content-language", b""), (b"content-length", b""),
    (b"content-location", b""), (b"content-range", b""),
    (b"content-type", b""), (b"cookie", b""), (b"date", b""), (b"etag", b""),
    (b"expect", b""), (b"expires", b""), (b"from", b""), (b"host", b""),
    (b"if-match", b""), (b"if-modified-since", b""), (b"if-none-match", b""),
    (b"if-range", b""), (b"if-unmodified-since", b""), (b"last-modified", b""),
    (b"link", b""), (b"location", b""), (b"max-forwards", b""),
    (b"proxy-authenticate", b""), (b"proxy-authorization", b""),
    (b"range", b""), (b"referer", b""), (b"refresh", b""),
    (b"retry-after", b""), (b"server", b""), (b"set-cookie", b""),
    (b"strict-transport-security", b""), (b"transfer-encoding", b""),
    (b"user-agent", b""), (b"vary", b""), (b"via", b""),
    (b"www-authenticate", b""),
]
assert len(STATIC_TABLE) == STATIC_TABLE_SIZE


# --------------------------------------------------------------------------
# HPACK dynamic table with per-entry eviction
# --------------------------------------------------------------------------

def _entry_size(name: bytes, value: bytes) -> int:
    return len(name) + len(value) + 32  # RFC 7541 section 4.1


class DynamicTable:
    """Newest entry first; dynamic index 1 == most recently added."""

    def __init__(self, max_size: int = HEADER_TABLE_LIMIT):
        self.max_size = max_size
        self.entries: list[tuple[bytes, bytes]] = []
        self.size = 0

    def __len__(self) -> int:
        return len(self.entries)

    def get(self, dyn_index: int) -> tuple[bytes, bytes]:
        # dyn_index is 1-based within the dynamic table
        return self.entries[dyn_index - 1]

    def add(self, name: bytes, value: bytes) -> None:
        self.entries.insert(0, (name, value))
        self.size += _entry_size(name, value)
        self._evict()

    def set_max_size(self, new_max: int) -> None:
        self.max_size = new_max
        self._evict()

    def _evict(self) -> None:
        while self.size > self.max_size and self.entries:
            name, value = self.entries.pop()  # evict oldest
            self.size -= _entry_size(name, value)


# --------------------------------------------------------------------------
# HPACK decoder (manual: integers, strings, representations, table updates)
# --------------------------------------------------------------------------

def _decode_int(data: bytes, pos: int, prefix_bits: int) -> tuple[int, int]:
    """RFC 7541 section 5.1 integer with an N-bit prefix."""
    if pos >= len(data):
        raise HPACKError("truncated integer")
    mask = (1 << prefix_bits) - 1
    value = data[pos] & mask
    pos += 1
    if value < mask:
        return value, pos
    shift = 0
    while True:
        if pos >= len(data):
            raise HPACKError("truncated integer continuation")
        byte = data[pos]
        pos += 1
        value += (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            break
        if shift > 56:
            raise HPACKError("integer literal too large")
    return value, pos


def _decode_string(data: bytes, pos: int) -> tuple[bytes, bool, int]:
    """RFC 7541 section 5.2 string literal; returns (value, was_huffman, pos)."""
    if pos >= len(data):
        raise HPACKError("truncated string literal")
    huffman = bool(data[pos] & 0x80)
    length, pos = _decode_int(data, pos, 7)
    if pos + length > len(data):
        raise HPACKError("truncated string literal data")
    raw = data[pos:pos + length]
    pos += length
    if huffman:
        return huffman_decode(raw), True, pos
    return raw, False, pos


class HPACKDecoder:
    """Decodes one header block at a time against the shared table state."""

    def __init__(self, table_limit: int = HEADER_TABLE_LIMIT):
        self.table_limit = table_limit
        self.table = DynamicTable(table_limit)

    # -- index space ------------------------------------------------------

    def lookup(self, index: int) -> tuple[tuple[bytes, bytes], dict]:
        if index <= 0:
            raise HPACKError("illegal index 0")
        if index <= STATIC_TABLE_SIZE:
            return STATIC_TABLE[index - 1], {"table": "static", "index": index}
        dyn_index = index - STATIC_TABLE_SIZE
        if dyn_index > len(self.table):
            raise HPACKError(
                f"illegal index {index}: dynamic table holds "
                f"{len(self.table)} entries"
            )
        return self.table.get(dyn_index), {"table": "dynamic", "index": index}

    # -- header block -----------------------------------------------------

    def decode_block(self, block: bytes) -> list[dict]:
        """Decode a complete header block; returns ordered field dicts.

        Raises HPACKError (a connection error) on illegal index, illegal
        table-size update or bad Huffman.  All compression instructions are
        consumed even if the resulting list will be rejected by the caller.
        """
        fields: list[dict] = []
        pos = 0
        seen_field = False
        while pos < len(block):
            byte = block[pos]
            if byte & 0x80:  # 1xxxxxxx: indexed header field
                index, pos = _decode_int(block, pos, 7)
                (name, value), source = self.lookup(index)
                fields.append({
                    "name": name, "value": value,
                    "source": {"type": "indexed", **source},
                })
                seen_field = True
            elif byte & 0x40:  # 01xxxxxx: literal, incremental indexing
                name, name_src, name_huff, pos = self._decode_name(block, pos, 6)
                value, value_huff, pos = _decode_string(block, pos)
                self.table.add(name, value)
                fields.append({
                    "name": name, "value": value,
                    "source": {
                        "type": "literal", "indexing": "incremental",
                        "name_from": name_src, "name_huffman": name_huff,
                        "value_huffman": value_huff,
                        "added_to_dynamic_table": True,
                    },
                })
                seen_field = True
            elif byte & 0x20:  # 001xxxxx: dynamic table size update
                new_size, pos = _decode_int(block, pos, 5)
                if seen_field:
                    raise HPACKError(
                        "illegal table size update: not at start of header block"
                    )
                if new_size > self.table_limit:
                    raise HPACKError(
                        f"illegal table size update {new_size}: exceeds "
                        f"negotiated limit {self.table_limit}"
                    )
                self.table.set_max_size(new_size)
            else:  # 0000xxxx / 0001xxxx: literal, without / never indexed
                never = bool(byte & 0x10)
                name, name_src, name_huff, pos = self._decode_name(block, pos, 4)
                value, value_huff, pos = _decode_string(block, pos)
                fields.append({
                    "name": name, "value": value,
                    "source": {
                        "type": "literal",
                        "indexing": "never" if never else "without",
                        "name_from": name_src, "name_huffman": name_huff,
                        "value_huffman": value_huff,
                        "added_to_dynamic_table": False,
                    },
                })
                seen_field = True
        return fields

    def _decode_name(self, block: bytes, pos: int, prefix_bits: int):
        index, pos = _decode_int(block, pos, prefix_bits)
        if index == 0:
            name, huff, pos = _decode_string(block, pos)
            return name, "literal", huff, pos
        (name, _value), source = self.lookup(index)
        return name, source, False, pos


# --------------------------------------------------------------------------
# HTTP/2 frame layer
# --------------------------------------------------------------------------

def _display(raw: bytes) -> str:
    return raw.decode("utf-8", errors="backslashreplace")


def _headers_fragment(payload: bytes, flags: int, offset: int) -> bytes:
    """Strip PADDED / PRIORITY scaffolding, return the block fragment."""
    pos = 0
    pad_len = 0
    if flags & FLAG_PADDED:
        if pos >= len(payload):
            raise H2ConnectionError("HEADERS: missing pad length", offset)
        pad_len = payload[pos]
        pos += 1
    if flags & FLAG_PRIORITY:
        if pos + 5 > len(payload):
            raise H2ConnectionError("HEADERS: truncated priority fields", offset)
        pos += 5
    if pad_len > len(payload) - pos:
        raise H2ConnectionError("HEADERS: padding exceeds payload", offset)
    return payload[pos:len(payload) - pad_len]


def audit_capture(data: bytes, drop_streams: set[int], verbose: bool = False) -> dict:
    """Consume one direction of frames; return the audit report.

    On a connection error the partial report is attached to the raised
    H2ConnectionError as ``partial_report``.
    """
    result: dict = {
        "capture_bytes": len(data),
        "header_table_limit": HEADER_TABLE_LIMIT,
        "max_fields_per_list": MAX_FIELDS_PER_LIST,
        "drop_streams": sorted(drop_streams),
        "frames_consumed": 0,
        "blocks": [],
        "error": None,
    }
    decoder = HPACKDecoder(HEADER_TABLE_LIMIT)

    pos = 0
    if data.startswith(CLIENT_PREFACE):
        pos = len(CLIENT_PREFACE)

    # Pending header block: stream id + accumulated fragments.
    pending_sid: int | None = None
    pending_frags: list[bytes] = []

    def finish_block(sid: int, block: bytes, offset: int) -> None:
        try:
            fields = decoder.decode_block(block)
        except HPACKError as exc:
            exc.offset = offset
            raise
        entry: dict = {"stream_id": sid}
        if sid in drop_streams:
            # Fully decoded and applied to the shared table, not delivered.
            entry["status"] = "dropped"
            entry["field_count"] = len(fields)
        elif len(fields) > MAX_FIELDS_PER_LIST:
            # Reject only this list; compression state already consumed.
            entry["status"] = "rejected"
            entry["reason"] = "too_many_fields"
            entry["field_count"] = len(fields)
        else:
            entry["status"] = "delivered"
            entry["headers"] = [
                {
                    "name": _display(f["name"]),
                    "value": _display(f["value"]),
                    "source": f["source"],
                }
                for f in fields
            ]
        result["blocks"].append(entry)

    try:
        while pos < len(data):
            frame_offset = pos
            if len(data) - pos < 9:
                raise H2ConnectionError("truncated frame header", frame_offset)
            length = int.from_bytes(data[pos:pos + 3], "big")
            ftype = data[pos + 3]
            flags = data[pos + 4]
            sid = int.from_bytes(data[pos + 5:pos + 9], "big") & 0x7FFFFFFF
            pos += 9
            if len(data) - pos < length:
                raise H2ConnectionError(
                    f"truncated frame payload: need {length}, "
                    f"have {len(data) - pos}",
                    frame_offset,
                )
            payload = data[pos:pos + length]
            pos += length

            if pending_sid is not None and not (
                ftype == FRAME_CONTINUATION and sid == pending_sid
            ):
                raise H2ConnectionError(
                    f"header block on stream {pending_sid} not finished: "
                    f"interleaved frame type {ftype} on stream {sid}",
                    frame_offset,
                )

            if ftype == FRAME_HEADERS:
                if sid == 0:
                    raise H2ConnectionError("HEADERS on stream 0", frame_offset)
                fragment = _headers_fragment(payload, flags, frame_offset)
                if flags & FLAG_END_HEADERS:
                    finish_block(sid, fragment, frame_offset)
                else:
                    pending_sid = sid
                    pending_frags = [fragment]
            elif ftype == FRAME_CONTINUATION:
                if pending_sid is None:
                    raise H2ConnectionError(
                        "CONTINUATION without an open header block", frame_offset
                    )
                pending_frags.append(payload)
                if flags & FLAG_END_HEADERS:
                    finish_block(pending_sid, b"".join(pending_frags), frame_offset)
                    pending_sid = None
                    pending_frags = []
            elif ftype == FRAME_PUSH_PROMISE:
                raise H2ConnectionError(
                    "PUSH_PROMISE not handled by this auditor", frame_offset
                )
            # DATA, SETTINGS, PING, GOAWAY, WINDOW_UPDATE, RST_STREAM,
            # PRIORITY and unknown/extension frames carry no header state.
            result["frames_consumed"] += 1

        if pending_sid is not None:
            raise H2ConnectionError(
                f"capture ends inside header block on stream {pending_sid}", pos
            )
    except H2ConnectionError as exc:
        exc.partial_report = result
        raise

    if verbose:
        result["dynamic_table"] = {
            "size": decoder.table.size,
            "max_size": decoder.table.max_size,
            "entries": [
                {
                    "index": STATIC_TABLE_SIZE + i + 1,
                    "name": _display(name),
                    "value": _display(value),
                    "size": _entry_size(name, value),
                }
                for i, (name, value) in enumerate(decoder.table.entries)
            ],
        }
    return result


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _parse_drop_streams(values: list[str]) -> set[int]:
    streams: set[int] = set()
    for value in values or []:
        for part in value.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                sid = int(part, 10)
            except ValueError:
                raise UsageError(f"invalid stream id: {part!r}")
            if not 1 <= sid <= 0x7FFFFFFF:
                raise UsageError(f"stream id out of range: {sid}")
            streams.add(sid)
    return streams


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="h2audit",
        description="Audit one direction of an HTTP/2 capture: decode HPACK "
                    "header blocks, drop selected streams, report kept "
                    "streams' ordered headers with reference sources.",
    )
    parser.add_argument(
        "capture", help="file with raw frame bytes of one direction"
    )
    parser.add_argument(
        "--drop-streams", action="append", default=[], metavar="IDS",
        help="comma-separated stream ids to drop (repeatable), "
             "e.g. --drop-streams 3,7",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="include final dynamic table state in the report",
    )
    args = parser.parse_args(argv)

    try:
        drop_streams = _parse_drop_streams(args.drop_streams)
        with open(args.capture, "rb") as fh:
            data = fh.read()
        if len(data) > MAX_CAPTURE_BYTES:
            raise UsageError(
                f"capture is {len(data)} bytes, limit is {MAX_CAPTURE_BYTES}"
            )
    except UsageError as exc:
        print(f"h2audit: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"h2audit: cannot read {args.capture}: {exc}", file=sys.stderr)
        return 1

    exit_code = 0
    try:
        report = audit_capture(data, drop_streams, verbose=args.verbose)
    except H2ConnectionError as exc:
        # Connection stopped: report partial audit plus the error.
        report = exc.partial_report or {
            "capture_bytes": len(data),
            "header_table_limit": HEADER_TABLE_LIMIT,
            "max_fields_per_list": MAX_FIELDS_PER_LIST,
            "drop_streams": sorted(drop_streams),
            "frames_consumed": 0,
            "blocks": [],
        }
        report["error"] = {"message": str(exc), "offset": exc.offset}
        exit_code = 2

    report["capture"] = args.capture
    json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
