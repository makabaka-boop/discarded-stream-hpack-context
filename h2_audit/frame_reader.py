"""HTTP/2 frame reader and HEADERS/CONTINUATION reassembly."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TextIO

from .hpack_decoder import HPACKConnectionError, HPACKDecoder, HeaderField
from .static_table import STATIC_TABLE

FRAME_HEADER_LENGTH = 9
MAX_CAPTURE = 16 * 1024
NEGOTIATED_TABLE_LIMIT = 256
MAX_HEADER_FIELDS = 64

HEADERS = 0x01
CONTINUATION = 0x09

END_HEADERS = 0x04
PADDED = 0x08
PRIORITY = 0x20


@dataclass
class DeliveredList:
    stream_id: int
    discarded: bool
    fields: list[HeaderField] = field(default_factory=list)
    observed_field_count: int = 0
    rejected_too_many_fields: bool = False


@dataclass
class FrameInfo:
    type: int
    flags: int
    stream_id: int
    length: int
    offset: int


@dataclass
class Assembly:
    stream_id: int
    fragments: bytearray
    first_frame: FrameInfo


def _text(raw: bytes) -> str:
    # JSON consumers get exact bytes in *_b64; this is only a convenience view.
    return raw.decode("utf-8", errors="replace")


def _field_to_json(item: HeaderField) -> dict[str, object]:
    result: dict[str, object] = {
        "name": _text(item.name),
        "value": _text(item.value),
        "name_b64": base64.b64encode(item.name).decode("ascii"),
        "value_b64": base64.b64encode(item.value).decode("ascii"),
        "representation": item.representation,
        "value_reference": {"kind": item.source, "index": item.index}
        if item.representation == "indexed"
        else {"kind": "literal", "huffman": item.huffman_value},
    }
    if item.representation != "indexed":
        result["name_reference"] = (
            {
                "kind": item.name_source,
                "index": item.name_index,
                "huffman": item.huffman_name,
            }
            if item.name_source == "literal"
            else {"kind": item.name_source, "index": item.name_index}
        )
    return result


def _list_to_json(item: DeliveredList) -> dict[str, object]:
    status = "discarded" if item.discarded else (
        "rejected_too_many_fields" if item.rejected_too_many_fields else "delivered"
    )
    return {
        "stream_id": item.stream_id,
        "status": status,
        "observed_field_count": item.observed_field_count,
        "fields": [_field_to_json(field) for field in item.fields]
        if not item.discarded and not item.rejected_too_many_fields
        else [],
    }


def read_frame_header(data: bytes, offset: int) -> tuple[FrameInfo, int]:
    if len(data) - offset < FRAME_HEADER_LENGTH:
        raise HPACKConnectionError("truncated HTTP/2 frame header")
    length = int.from_bytes(data[offset:offset + 3], "big")
    frame_type = data[offset + 3]
    flags = data[offset + 4]
    stream_word = int.from_bytes(data[offset + 5:offset + 9], "big")
    stream_id = stream_word & 0x7FFFFFFF
    payload_start = offset + FRAME_HEADER_LENGTH
    end = payload_start + length
    if end > len(data):
        raise HPACKConnectionError(
            f"truncated payload for frame type 0x{frame_type:02x} at byte {offset}"
        )
    return FrameInfo(frame_type, flags, stream_id, length, offset), end


def headers_fragment(payload: bytes, flags: int) -> bytes:
    pos = 0
    if flags & PADDED:
        if not payload:
            raise HPACKConnectionError("PADDING_PRESENT on empty HEADERS payload")
        pad_length = payload[0]
        pos = 1
    else:
        pad_length = 0

    if flags & PRIORITY:
        pos += 5

    # The one-byte pad length, priority information and padding cannot consume
    # bytes that are needed for a (possibly zero-length) header block.
    if pos + pad_length > len(payload):
        raise HPACKConnectionError("HEADERS padding length exceeds payload")
    return payload[pos:len(payload) - pad_length]


def audit_capture(
    data: bytes,
    discarded_streams: set[int],
    *,
    max_capture: int = MAX_CAPTURE,
) -> dict[str, object]:
    if len(data) > max_capture:
        raise HPACKConnectionError(
            f"capture is {len(data)} bytes; maximum supported is {max_capture}"
        )

    decoder = HPACKDecoder(NEGOTIATED_TABLE_LIMIT)
    header_lists: list[DeliveredList] = []
    traces: list[dict[str, object]] = []
    seen_streams: set[int] = set()
    assembly: Assembly | None = None
    offset = 0
    frame_count = 0

    while offset < len(data):
        frame, payload_end = read_frame_header(data, offset)
        payload_start = offset + FRAME_HEADER_LENGTH
        payload = data[payload_start:payload_end]
        frame_count += 1

        if assembly is not None:
            if frame.type != CONTINUATION:
                raise HPACKConnectionError(
                    f"frame type 0x{frame.type:02x} inserted before END_HEADERS on stream "
                    f"{assembly.stream_id}"
                )
            if frame.stream_id != assembly.stream_id:
                raise HPACKConnectionError(
                    "CONTINUATION stream identifier does not match HEADERS"
                )
            assembly.fragments.extend(payload)
            if frame.flags & END_HEADERS:
                block = bytes(assembly.fragments)
                stream_id = assembly.stream_id
                first_offset = assembly.first_frame.offset
                assembly = None
                delivered = _decode_complete_block(
                    decoder, block, stream_id, stream_id in discarded_streams
                )
                header_lists.append(delivered)
                seen_streams.add(stream_id)
                traces.append(
                    {
                        "stream_id": stream_id,
                        "frame_offset": first_offset,
                        "block_bytes": len(block),
                        "discarded": delivered.discarded,
                        "observed_field_count": delivered.observed_field_count,
                    }
                )
        elif frame.type == CONTINUATION:
            raise HPACKConnectionError(
                f"unmatched CONTINUATION frame on stream {frame.stream_id}"
            )
        elif frame.type == HEADERS:
            if frame.stream_id == 0:
                raise HPACKConnectionError("HEADERS frame on stream zero")
            fragment = headers_fragment(payload, frame.flags)
            if frame.flags & END_HEADERS:
                delivered = _decode_complete_block(
                    decoder, bytes(fragment), frame.stream_id,
                    frame.stream_id in discarded_streams,
                )
                header_lists.append(delivered)
                seen_streams.add(frame.stream_id)
                traces.append(
                    {
                        "stream_id": frame.stream_id,
                        "frame_offset": frame.offset,
                        "block_bytes": len(fragment),
                        "discarded": delivered.discarded,
                        "observed_field_count": delivered.observed_field_count,
                    }
                )
            else:
                assembly = Assembly(
                    frame.stream_id,
                    bytearray(fragment),
                    frame,
                )
        # Other frame types are permitted between complete header blocks. The
        # task explicitly does not model flow control, TLS or server push.

        offset = payload_end

    if assembly is not None:
        raise HPACKConnectionError(
            f"header block on stream {assembly.stream_id} ends without END_HEADERS"
        )

    return {
        "status": "ok",
        "capture_bytes": len(data),
        "frame_count": frame_count,
        "negotiated_dynamic_table_limit": NEGOTIATED_TABLE_LIMIT,
        "max_header_fields_per_list": MAX_HEADER_FIELDS,
        "discarded_streams": sorted(discarded_streams),
        "discarded_streams_without_header_block": sorted(
            discarded_streams - seen_streams
        ),
        "header_blocks": [_list_to_json(item) for item in header_lists],
        "block_order": traces,
        "final_dynamic_table": {
            "capacity": decoder.max_size,
            "size": decoder.current_size,
            "entries": [
                {
                    "index": len(STATIC_TABLE) + index + 1,
                    "name": _text(entry.name),
                    "value": _text(entry.value),
                }
                for index, entry in enumerate(decoder.entries)
            ],
        },
    }


def _decode_complete_block(
    decoder: HPACKDecoder,
    block: bytes,
    stream_id: int,
    discarded: bool,
) -> DeliveredList:
    fields, _events, rejected, observed = decoder.decode_block(
        block,
        include_fields=not discarded,
        max_fields=MAX_HEADER_FIELDS,
    )
    return DeliveredList(
        stream_id=stream_id,
        discarded=discarded,
        fields=fields,
        observed_field_count=observed,
        rejected_too_many_fields=rejected,
    )


def audit_file(path: str | Path, discarded_streams: set[int]) -> dict[str, object]:
    with Path(path).open("rb") as capture:
        return audit_capture(capture.read(), discarded_streams)


def write_report(report: dict[str, object], output: TextIO) -> None:
    json.dump(report, output, ensure_ascii=False, indent=2, sort_keys=False)
    output.write("\n")
