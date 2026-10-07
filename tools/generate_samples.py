#!/usr/bin/env python3
"""Generate small, real HTTP/2 frame captures used for manual verification."""

from __future__ import annotations

from pathlib import Path

from hpack import Encoder

HEADERS = 0x01
END_HEADERS = 0x04


def frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + stream_id.to_bytes(4, "big")
        + payload
    )


def main() -> None:
    out_dir = Path(__file__).resolve().parents[1] / "samples"
    out_dir.mkdir(exist_ok=True)

    encoder = Encoder()
    # The auditor models SETTINGS_HEADER_TABLE_SIZE as fixed at 256 bytes.
    encoder.header_table_size = 256

    discarded = encoder.encode(
        [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":path", b"/filtered"),
            (b"x-discarded-secret", b"shared-table-state"),
        ],
        huffman=True,
    )
    # Indexed reference to dynamic entry 62 (static table length 61 + first
    # dynamic entry), which was inserted by the discarded header block.
    normal = bytes([0xBE])

    capture = (
        frame(HEADERS, END_HEADERS, 3, discarded)
        + frame(HEADERS, END_HEADERS, 5, normal)
    )
    path = out_dir / "filtered-shared-hpack.bin"
    path.write_bytes(capture)
    print(f"wrote {path} ({len(capture)} bytes); discard stream 3")


if __name__ == "__main__":
    main()
