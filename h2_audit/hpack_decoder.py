"""Stateful, instruction-at-a-time HPACK decoder used by the capture auditor.

Only the HPACK Huffman decoding primitive is delegated to the mature ``hpack``
package; frame reassembly, representation parsing, table updates, insertion and
eviction all happen here so a filtered/discarded header block can correctly
advance connection-level state without its fields being delivered.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from hpack.exceptions import HPACKDecodingError
from hpack.huffman_table import decode_huffman

from .static_table import STATIC_TABLE

def entry_size(name: bytes, value: bytes) -> int:
    """Dynamic table entry size: name + value + 32-byte entry overhead."""
    return len(name) + len(value) + 32


class HPACKConnectionError(Exception):
    """Fatal HPACK or framing error; RFC 7541/RFC 7540 says stop the connection."""


SourceKind = Literal["static", "dynamic", "literal"]
IndexMode = Literal["incremental", "without-index", "never-indexed", "indexed"]


@dataclass(frozen=True)
class HeaderField:
    name: bytes
    value: bytes
    source: SourceKind
    index: int | None = None
    name_source: SourceKind | None = None
    name_index: int | None = None
    representation: IndexMode | None = None
    huffman_name: bool = False
    huffman_value: bool = False


@dataclass(frozen=True)
class TableEvent:
    kind: Literal["capacity-update", "insert", "evict"]
    index: int | None = None
    name: bytes | None = None
    value: bytes | None = None
    capacity: int | None = None
    table_size: int | None = None


class DynamicEntry:
    __slots__ = ("name", "value")

    def __init__(self, name: bytes, value: bytes) -> None:
        self.name = name
        self.value = value

    def size(self) -> int:
        return entry_size(self.name, self.value)


def _decode_integer(data: bytes, pos: int, prefix_bits: int) -> tuple[int, int]:
    if pos >= len(data):
        raise HPACKConnectionError("truncated HPACK integer")
    mask = (1 << prefix_bits) - 1
    number = data[pos] & mask
    consumed = 1
    if number < mask:
        return number, pos + consumed

    shift = 0
    pos += 1
    # The negotiated limit and 16 KiB capture make larger values impossible to
    # consume legitimately. The continuation check also rejects run-away data.
    while True:
        if pos >= len(data):
            raise HPACKConnectionError("truncated HPACK integer continuation")
        if consumed > 6:
            raise HPACKConnectionError("HPACK integer is too large")
        byte = data[pos]
        pos += 1
        consumed += 1
        number += (byte & 0x7F) << shift
        if not byte & 0x80:
            break
        shift += 7
        if shift > 35:
            raise HPACKConnectionError("HPACK integer is too large")
    return number, pos


def _decode_string(data: bytes, pos: int) -> tuple[bytes, bool, int]:
    if pos >= len(data):
        raise HPACKConnectionError("truncated HPACK string length")
    huffman = bool(data[pos] & 0x80)
    length, pos = _decode_integer(data, pos, 7)
    end = pos + length
    if end > len(data):
        raise HPACKConnectionError("truncated HPACK string")
    raw = data[pos:end]
    if huffman:
        try:
            value = bytes(decode_huffman(raw))
        except HPACKDecodingError as exc:
            raise HPACKConnectionError(f"bad Huffman coding: {exc}") from exc
    else:
        value = raw
    return value, huffman, end


class HPACKDecoder:
    def __init__(self, negotiated_limit: int = 256) -> None:
        self.negotiated_limit = negotiated_limit
        # entries[0] is the newest dynamic entry. HPACK's first dynamic index is
        # len(STATIC_TABLE)+1.
        self.entries: list[DynamicEntry] = []
        self.current_size = 0
        self.max_size = negotiated_limit

    def dynamic_lookup(self, dynamic_index_one_based: int) -> DynamicEntry:
        if dynamic_index_one_based < 1 or dynamic_index_one_based > len(self.entries):
            raise HPACKConnectionError(
                f"dynamic table index {len(STATIC_TABLE) + dynamic_index_one_based} "
                "is not present"
            )
        return self.entries[dynamic_index_one_based - 1]

    def lookup(self, index: int) -> tuple[SourceKind, bytes, bytes]:
        if index == 0:
            raise HPACKConnectionError("HPACK index zero is invalid")
        if index <= len(STATIC_TABLE):
            name, value = STATIC_TABLE[index - 1]
            return "static", name, value
        dynamic_index = index - len(STATIC_TABLE)
        entry = self.dynamic_lookup(dynamic_index)
        return "dynamic", entry.name, entry.value

    def lookup_name(self, index: int) -> tuple[SourceKind, bytes]:
        if index == 0:
            # Index zero means a literal name follows; callers handle that case.
            raise HPACKConnectionError("internal error: lookup_name called with zero")
        if index <= len(STATIC_TABLE):
            return "static", STATIC_TABLE[index - 1][0]
        entry = self.dynamic_lookup(index - len(STATIC_TABLE))
        return "dynamic", entry.name

    def resize(self, new_max: int) -> TableEvent:
        if new_max > self.negotiated_limit:
            raise HPACKConnectionError(
                f"dynamic table capacity {new_max} exceeds negotiated {self.negotiated_limit}"
            )
        if new_max < 0:
            raise HPACKConnectionError("negative dynamic table capacity")
        self.max_size = new_max
        self._evict_to_fit(0)
        return TableEvent(
            "capacity-update",
            capacity=new_max,
            table_size=self.current_size,
        )

    def _evict_to_fit(self, incoming_size: int) -> list[TableEvent]:
        events: list[TableEvent] = []
        while self.current_size + incoming_size > self.max_size and self.entries:
            # Evict from the tail (oldest entry).
            removed = self.entries.pop()
            self.current_size -= removed.size()
            # Historical indices cannot be reported after an insertion because
            # they are based on the post-operation table; this remains useful in
            # a trace immediately before the insertion is attempted.
            events.append(
                TableEvent(
                    "evict",
                    index=len(STATIC_TABLE) + len(self.entries) + 1,
                    name=removed.name,
                    value=removed.value,
                    table_size=self.current_size,
                )
            )
        return events

    def insert(self, name: bytes, value: bytes) -> list[TableEvent]:
        entry = DynamicEntry(name, value)
        size = entry.size()
        if size > self.max_size:
            # RFC 7541 §4.4: entries that do not fit are not inserted; the
            # table is emptied as far as necessary.
            events = self._evict_to_fit(size)
            return events
        events = self._evict_to_fit(size)
        self.entries.insert(0, entry)
        self.current_size += size
        # Index of the just-inserted entry is always the first dynamic index.
        events.append(
            TableEvent(
                "insert",
                index=len(STATIC_TABLE) + 1,
                name=name,
                value=value,
                table_size=self.current_size,
            )
        )
        return events

    def decode_block(
        self,
        block: bytes,
        include_fields: bool = True,
        max_fields: int = 64,
    ) -> tuple[list[HeaderField], list[TableEvent], bool, int]:
        """Decode every representation in one complete header block.

        Returns fields (only when ``include_fields``), all table events, and
        whether the delivered list was rejected for exceeding ``max_fields``.
        Compression instructions continue to be consumed after that rejection.
        """

        fields: list[HeaderField] = []
        events: list[TableEvent] = []
        rejected = False
        observed = 0
        pos = 0
        saw_representation = False

        while pos < len(block):
            first = block[pos]

            if first & 0xE0 == 0x20:
                if saw_representation:
                    raise HPACKConnectionError(
                        "dynamic table capacity update is not at the start of a header block"
                    )
                new_size, pos = _decode_integer(block, pos, 5)
                events.append(self.resize(new_size))
                continue

            # Once a header representation is seen, later capacity updates are
            # illegal in this block.
            saw_representation = True

            if first & 0x80:
                index, pos = _decode_integer(block, pos, 7)
                source, name, value = self.lookup(index)
                field = HeaderField(
                    name=name,
                    value=value,
                    source=source,
                    index=index,
                    representation="indexed",
                )
                events_from_rep = []
            elif first & 0xC0 == 0x40:
                name_index, new_pos = _decode_integer(block, pos, 6)
                pos = new_pos
                if name_index:
                    name_source, name = self.lookup_name(name_index)
                else:
                    name, huff_name, pos = _decode_string(block, pos)
                    name_source = "literal"
                value, huff_value, pos = _decode_string(block, pos)
                field = HeaderField(
                    name=name,
                    value=value,
                    source="literal",
                    name_source=name_source if name_index else "literal",
                    name_index=name_index if name_index else None,
                    representation="incremental",
                    huffman_name=False if name_index else huff_name,
                    huffman_value=huff_value,
                )
                events_from_rep = self.insert(name, value)
                events.extend(events_from_rep)
            elif first & 0xF0 == 0x00:
                mode: IndexMode = "without-index" if first < 0x10 else "never-indexed"
                name_index, pos = _decode_integer(block, pos, 4)
                if name_index:
                    name_source, name = self.lookup_name(name_index)
                    huff_name = False
                else:
                    name, huff_name, pos = _decode_string(block, pos)
                    name_source = "literal"
                value, huff_value, pos = _decode_string(block, pos)
                field = HeaderField(
                    name=name,
                    value=value,
                    source="literal",
                    name_source=name_source,
                    name_index=name_index if name_index else None,
                    representation=mode,
                    huffman_name=huff_name,
                    huffman_value=huff_value,
                )
                events_from_rep = []
            else:
                raise HPACKConnectionError(
                    f"unrecognized HPACK representation byte 0x{first:02x}"
                )

            observed += 1
            if include_fields:
                if len(fields) >= max_fields:
                    rejected = True
                else:
                    fields.append(field)
            # If excluded, events still include insertions/evictions above.

        return fields, events, rejected, observed
